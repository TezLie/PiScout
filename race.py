"""
race.py

Parallel discovery — runs all discovery methods simultaneously and reports
each result the moment it arrives, so the first one can be shown right away.

Two discovery threads run in parallel:
  1. SNMP discovery   (discover_snmp)    — queries the switch directly
  2. Passive LLDP/CDP (discover_passive) — listens for switch advertisements

A third thread runs a persistent CDP burst throughout the discovery window.

Reporting results:
  Every result from SNMP, LLDP or CDP is passed to the caller's on_result
  callback as soon as it arrives. Discovery keeps going after the first one
  so the other protocols can fill in or override fields. It ends when every
  source has reported (SNMP answered or gave up, and both an LLDP and a CDP
  frame arrived). Once SNMP is done, it stops waiting for the remaining
  LLDP/CDP frames _LATE_SOURCE_WAIT seconds after the first result; main.py
  keeps a passive listener running afterwards that still catches them.

Combining results:
  merge_results() builds one record field by field. Each field is taken from
  the highest-priority source that has a value for it: SNMP, then LLDP, then
  CDP. The record remembers which source supplied each field so the display
  can show it at the end of the line.

Race condition fix:
  The passive capture socket is opened BEFORE triggers are sent. A
  threading.Event (socket_ready) is set by discover_passive the instant the
  socket is open and listening. race.py waits on this event before sending
  any trigger frames. This guarantees no frames from the switch are missed
  because our socket wasn't open yet when the switch responded.

Persistent CDP burst:
  Rather than a one-shot burst at the start, CDP frames are sent continuously
  at 100ms intervals throughout the entire discovery window. This maximises
  the chance of catching the switch's CDP polling cycle on platforms like
  the Catalyst 6500 that do not support immediate CDP response.

What this file does:
  - Open passive listener socket first
  - Wait for socket confirmation before sending triggers
  - Start persistent CDP burst thread
  - Spawn SNMP and passive discovery threads
  - Pass each result to the caller as it arrives
  - Provide merge_results() to combine them by priority (SNMP > LLDP > CDP)

What this file does NOT do:
  - Implement any discovery logic
  - Parse frames
  - Query SNMP
  - Talk to the display
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from typing import Callable, Optional

import discover_passive
import discover_snmp
import parse_utils
import trigger


log = logging.getLogger(__name__)

# Highest priority first. When sources disagree, the earlier one wins.
PROTOCOL_PRIORITY = ("SNMP", "LLDP", "CDP")

# Neighbor fields combined by merge_results().
MERGED_FIELDS = ("switch_name", "switch_ip", "port", "port_desc", "vlan", "voice_vlan")

# Values that count as "no data" when merging.
_EMPTY_VALUES = {"", "Unknown", "None", "N/A"}

# Once SNMP is done, how long after the first result to keep the CDP burst
# and listener running for the protocols that have not answered yet.
_LATE_SOURCE_WAIT = 10.0

# Sentinels placed in the result queue when a thread finishes.
_SNMP_DONE    = object()
_PASSIVE_DONE = object()


# ============================================================
# Combining results
# ============================================================

def _has_value(value) -> bool:
    return str(value or "").strip() not in _EMPTY_VALUES


def keep_better(existing: Optional[dict], new: dict) -> dict:
    """
    Decide which of two results from the same protocol to keep.

    The newest result wins, except that a partial result never replaces
    a complete one (a switch may send an occasional frame with fewer TLVs).
    """
    if existing and not existing.get("is_partial") and new.get("is_partial"):
        return existing
    return new


def merge_results(results: dict[str, dict]) -> Optional[dict]:
    """
    Combine results from several protocols into one neighbor record.

    Parameters:
        results : protocol label ("SNMP", "LLDP", "CDP") -> neighbor dict

    Returns a neighbor dict with the usual fields plus:
        sources    : field name -> protocol that supplied the value
                     (only fields that have a value are listed)
        protocol   : contributing protocols in priority order, e.g. "SNMP+LLDP"
        is_partial : True when switch_name or port is still missing

    Returns None if results is empty.
    """
    if not results:
        return None

    merged:  dict = {}
    sources: dict = {}

    for field in MERGED_FIELDS:
        merged[field] = ""
        for protocol in PROTOCOL_PRIORITY:
            value = (results.get(protocol) or {}).get(field, "")
            if _has_value(value):
                merged[field]   = str(value).strip()
                sources[field]  = protocol
                break

    # The description may have come from a different source than the port
    # name, so check again that it is not just the port name repeated.
    if not parse_utils.clean_port_description(merged["port_desc"], merged["port"]):
        merged["port_desc"] = ""
        sources.pop("port_desc", None)

    used = [p for p in PROTOCOL_PRIORITY if p in sources.values()]

    merged["sources"]    = sources
    merged["protocol"]   = "+".join(used)
    merged["is_partial"] = not (_has_value(merged["switch_name"]) and _has_value(merged["port"]))
    return merged


# ============================================================
# Running discovery
# ============================================================

def run(
    interface:    str,
    local_mac:    Optional[bytes],
    cancel_event: threading.Event,
    on_result:    Callable[[dict], None],
    timeout:      float = 120.0,
) -> bool:
    """
    Run all discovery methods in parallel and report each result as it arrives.

    Blocks until every source has reported, all methods give up, or the
    cancel_event is set (e.g. link went down while discovering).

    Parameters:
        interface    : Ethernet interface name, e.g. "eth0"
        local_mac    : 6-byte MAC of the interface for self-frame filtering
                       and BRIDGE-MIB MAC lookup. May be None.
        cancel_event : set by main.py if link drops during discovery.
        on_result    : called with each neighbor dict (SNMP, LLDP or CDP)
                       from this thread, in the order they arrive.
        timeout      : maximum seconds for any single discovery method

    Returns:
        True if at least one result was reported.
    """
    # Internal stop event signals all threads to exit once discovery ends.
    # Separate from cancel_event so we don't affect main.py's shutdown logic.
    internal_stop = threading.Event()

    # socket_ready is set by discover_passive the moment its AF_PACKET socket
    # is open and listening. We wait on this before sending any triggers so
    # that switch responses are never missed due to a timing gap.
    socket_ready = threading.Event()

    result_queue: queue.Queue = queue.Queue()

    def _run_passive() -> None:
        def _on_result(result: dict) -> bool:
            result_queue.put(result)
            return False   # keep listening for the other protocol

        try:
            discover_passive.listen(
                interface=interface,
                local_mac=local_mac,
                cancel_event=internal_stop,
                on_result=_on_result,
                timeout=timeout,
                socket_ready=socket_ready,
            )
        except Exception as exc:
            log.exception("Passive discovery thread raised an exception: %s", exc)
            # Ensure socket_ready is set even on failure.
            socket_ready.set()
        result_queue.put(_PASSIVE_DONE)

    def _run_snmp() -> None:
        try:
            result = discover_snmp.discover(
                interface=interface,
                local_mac=local_mac,
                cancel_event=internal_stop,
                timeout=timeout,
            )
        except Exception as exc:
            log.exception("SNMP discovery thread raised an exception: %s", exc)
            result = None

        if result:
            result_queue.put(result)
        result_queue.put(_SNMP_DONE)

    # ---- Step 1: Start passive thread FIRST so socket opens immediately ----
    passive_thread = threading.Thread(
        target=_run_passive,
        name="rf-passive",
        daemon=True,
    )
    passive_thread.start()

    # ---- Step 2: Wait for passive socket to confirm open (near-instant) ----
    # Timeout of 2.0s is a safety net — in practice this fires in <50ms.
    if not socket_ready.wait(timeout=2.0):
        log.warning("Race: passive socket did not open within 2s on %s", interface)

    # ---- Step 3: Send the LLDP trigger NOW that the socket is listening ----
    # CDP is handled entirely by the persistent burst started in Step 4 — its
    # first frame goes out immediately, so no separate one-shot CDP send is
    # needed here.
    log.debug("Race: socket ready — sending LLDP trigger on %s", interface)
    trigger.send_lldp_trigger(interface, local_mac)

    # ---- Step 4: Start persistent CDP burst thread ----
    # Sends CDP frames every 100ms throughout the entire discovery window.
    burst_thread = trigger.start_persistent_cdp_burst(interface, internal_stop, src_mac=local_mac)

    # ---- Step 5: Start SNMP thread ----
    snmp_thread = threading.Thread(
        target=_run_snmp,
        name="rf-snmp",
        daemon=True,
    )
    snmp_thread.start()

    log.debug("Race: all discovery threads running on %s", interface)

    # ---- Step 6: Pass results on as they arrive ----
    seen:            set[str]        = set()
    snmp_done        = False
    passive_done     = False
    first_result_at: Optional[float] = None

    while True:
        if cancel_event.is_set():
            log.debug("Race: cancelled by caller on %s", interface)
            break

        if snmp_done and passive_done:
            break   # every method has finished

        if snmp_done and {"LLDP", "CDP"} <= seen:
            break   # every source has reported

        if (
            snmp_done
            and first_result_at is not None
            and time.monotonic() - first_result_at >= _LATE_SOURCE_WAIT
        ):
            log.debug(
                "Race: stopped waiting for remaining sources on %s (have %s)",
                interface, sorted(seen),
            )
            break

        try:
            item = result_queue.get(timeout=0.5)
        except queue.Empty:
            continue

        if item is _SNMP_DONE:
            snmp_done = True
            continue
        if item is _PASSIVE_DONE:
            passive_done = True
            continue

        protocol = item.get("protocol", "?")
        seen.add(protocol)
        if first_result_at is None:
            first_result_at = time.monotonic()
        log.debug("Race: got %s result on %s", protocol, interface)

        try:
            on_result(item)
        except Exception:
            log.exception("Race: on_result callback failed for %s", protocol)

    # ---- Step 7: Clean up all threads ----
    internal_stop.set()
    burst_thread.join(timeout=2.0)
    snmp_thread.join(timeout=5.0)
    passive_thread.join(timeout=5.0)

    if seen:
        log.info("Race complete on %s | sources=%s", interface, "+".join(
            p for p in PROTOCOL_PRIORITY if p in seen
        ))
    else:
        log.info(
            "Race: no result on %s (all methods exhausted or cancelled)",
            interface,
        )

    return bool(seen)
