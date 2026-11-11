"""
main.py

PiScout — entry point and main loop.

Monitors Ethernet carrier state, runs the discovery race on link-up,
and updates the e-paper display with switch port information.

Discovery is handled by race.py, which runs SNMP and passive LLDP/CDP
capture in parallel and reports each result as it arrives. The first
result is drawn straight away; later ones are merged in field by field
(SNMP first, then LLDP, then CDP) and the screen is updated.

What this file does:
- Initialize the display
- Monitor link state on the configured interface
- Show appropriate screens (waiting, scanning, result, stale)
- Call race.run() on link-up, merge results and feed them to the display
- Handle SIGTERM gracefully for clean shutdown

What this file does NOT do:
- Implement any discovery logic (that belongs in discover_*.py and race.py)
- Parse LLDP or CDP frames directly
- Query SNMP directly
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Optional

import config
import race
import trigger
import discover_passive
import history

# Configure logging before importing display or discovery modules
# so their loggers inherit the correct level.
_log_level_str = (config.LOG_LEVEL or "WARNING").upper()
_log_level     = getattr(logging, _log_level_str, logging.WARNING)

logging.basicConfig(
    level=_log_level,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

log = logging.getLogger(__name__)
log.info("Logging initialized at level %s", _log_level_str)


# ============================================================
# -------------------- DISPLAY FACTORY -----------------------
# ============================================================

def _get_display_type() -> str:
    return str(config.DISPLAY_TYPE).lower().strip()


def _create_display():
    """
    Instantiate the correct display driver based on config.DISPLAY_TYPE.
    """
    display_type = _get_display_type()
    font_path    = config.DISPLAY_FONT_PATH

    if display_type == "epaper":
        from display_epaper import EPaperDisplay
        return EPaperDisplay(
            font_path=font_path,
            min_refresh_interval=int(config.EPAPER_MIN_REFRESH_INTERVAL),
            auto_sleep=bool(config.EPAPER_AUTO_SLEEP),
            startup_mode=True,
            partial_refresh_limit=int(config.EPAPER_PARTIAL_REFRESH_LIMIT),
        )

    if display_type == "lcd":
        from display_lcd import LCDDisplay
        return LCDDisplay(
            font_path=font_path,
            rotate_180=bool(config.LCD_ROTATE_180),
            clear_on_start=bool(config.LCD_CLEAR_ON_START),
            background_color=config.LCD_BACKGROUND_COLOR,
            text_color=config.LCD_TEXT_COLOR,
            backlight_brightness=int(config.LCD_BACKLIGHT_BRIGHTNESS),
        )

    log.warning(
        "Unknown DISPLAY_TYPE '%s' — defaulting to epaper.",
        display_type,
    )
    from display_epaper import EPaperDisplay
    return EPaperDisplay(font_path=font_path)


# ============================================================
# -------------------- DISPLAY HELPERS -----------------------
# ============================================================

def _truncate(text: str, max_len: int) -> str:
    text = str(text).strip()
    return text if len(text) <= max_len else text[: max_len - 1] + "…"


# Neighbor field shown on each body line, in display order.
_LINE_FIELDS = ("switch_name", "switch_ip", "port", "port_desc", "vlan")


def build_display_lines(neighbor: dict) -> list[str]:
    """Build the body lines for a valid neighbor result."""
    return [
        f"SW: {_truncate(neighbor.get('switch_name', 'Unknown'), 18)}",
        f"IP: {_truncate(neighbor.get('switch_ip',   'Unknown'), 18)}",
        f"PORT: {_truncate(neighbor.get('port',       'Unknown'), 16)}",
        f"DESC: {_truncate(neighbor.get('port_desc',  'Unknown'), 16)}",
        f"VLAN: {neighbor.get('vlan', 'Unknown')}",
    ]


def build_display_sources(neighbor: dict) -> list[str]:
    """Protocol that supplied each body line, shown at the end of the line."""
    sources = neighbor.get("sources", {})
    return [sources.get(field, "") for field in _LINE_FIELDS]


def build_scanning_lines() -> list[str]:
    """Shown immediately after link-up while discovery is running."""
    return ["", "", "Scanning...", "", ""]


def build_waiting_for_link_lines() -> list[str]:
    """Shown when no Ethernet carrier is detected."""
    return ["", "", "Waiting for", "link...", ""]


def build_stale_lines() -> list[str]:
    """Shown when a previously seen neighbor has not re-advertised."""
    return ["", "No active", "neighbor data.", "", ""]


def _show(display, lines: list[str], force: bool = False, sources: Optional[list[str]] = None) -> bool:
    """
    Show lines on whichever display is connected.

    sources is an optional list, parallel to lines, naming the protocol
    that supplied each line. It is drawn at the end of the line.
    """
    try:
        return display.show_lines(lines, force=force, sources=sources)
    except Exception as exc:
        log.error("Display update failed: %s", exc)
        return False


def _screen_content(neighbor: Optional[dict]) -> Optional[tuple]:
    """What a neighbor result looks like on screen, for change detection."""
    if neighbor is None:
        return None
    return (build_display_lines(neighbor), build_display_sources(neighbor))


def _show_result(display, neighbor: dict, reason: str) -> None:
    """Draw a merged neighbor result and log it."""
    display.set_startup_mode(False)
    _show(display, build_display_lines(neighbor), force=True, sources=build_display_sources(neighbor))
    log.info(
        "%s | protocol=%s switch=%s ip=%s port=%s desc=%s vlan=%s voice=%s",
        reason,
        neighbor.get("protocol"),
        neighbor.get("switch_name"),
        neighbor.get("switch_ip"),
        neighbor.get("port"),
        neighbor.get("port_desc"),
        neighbor.get("vlan"),
        neighbor.get("voice_vlan"),
    )


# ============================================================
# -------------------- CARRIER DETECTION ---------------------
# ============================================================

def _read_carrier(interface: str) -> bool:
    """
    Read the Ethernet carrier state from the kernel sysfs.

    Returns True if link is up, False if down or the file cannot be read.
    """
    carrier_path = Path(f"/sys/class/net/{interface}/carrier")
    try:
        return carrier_path.read_text(encoding="ascii").strip() == "1"
    except Exception:
        return False


def _interface_exists(interface: str) -> bool:
    return Path(f"/sys/class/net/{interface}").exists()


def _read_link_speed(interface: str) -> int:
    """
    Read the negotiated link speed from sysfs.

    Returns the speed in Mbps (100 or 1000 on typical ports).
    Returns -1 if the link has not yet negotiated or the file cannot be read.
    Auto-negotiation on 1GbE takes 1-3 seconds after physical link-up.
    """
    speed_path = Path(f"/sys/class/net/{interface}/speed")
    try:
        val = int(speed_path.read_text(encoding="ascii").strip())
        return val if val > 0 else -1
    except Exception:
        return -1


def _wait_for_negotiation(
    interface:      str,
    shutdown_event: threading.Event,
    timeout:        float = 5.0,
) -> bool:
    """
    Wait for Ethernet auto-negotiation to complete.

    During the 1-3 seconds after physical link-up, the NIC and switch
    are negotiating speed and duplex. No frames can be sent or received
    during this window. This function blocks until negotiation completes
    or the timeout expires.

    Returns True if negotiation completed, False if it timed out.
    """
    deadline = time.monotonic() + timeout
    while not shutdown_event.is_set() and time.monotonic() < deadline:
        if _read_link_speed(interface) > 0:
            return True
        time.sleep(0.05)
    return _read_link_speed(interface) > 0


# ============================================================
# -------------------- MAIN LOOP -----------------------------
# ============================================================

def run() -> None:
    """
    Main loop. Never returns unless a fatal error occurs or SIGTERM fires.
    """
    # --- Shutdown event (set by SIGTERM/SIGINT handler) ---
    shutdown_event = threading.Event()

    def _sigterm_handler(signum, frame):
        log.info("Signal %d received — initiating graceful shutdown", signum)
        shutdown_event.set()

    signal.signal(signal.SIGTERM, _sigterm_handler)
    signal.signal(signal.SIGINT,  _sigterm_handler)

    # --- Configuration ---
    interface            = str(config.NETWORK_INTERFACE)
    disc_timeout         = float(config.DISCOVERY_TIMEOUT)
    reveal_delay         = float(config.RESULT_REVEAL_DELAY)
    partial_display_delay = float(config.PARTIAL_DISPLAY_DELAY)

    log.info("Starting PiScout")
    log.info("DISPLAY_TYPE=%s",           _get_display_type())
    log.info("NETWORK_INTERFACE=%s",      interface)
    log.info("DISCOVERY_TIMEOUT=%s",      disc_timeout)
    log.info("RESULT_REVEAL_DELAY=%s",    reveal_delay)
    log.info("PARTIAL_DISPLAY_DELAY=%s",  partial_display_delay)

    # --- Verify interface exists ---
    if not _interface_exists(interface):
        log.error(
            "Network interface '%s' not found. Check NETWORK_INTERFACE in config.py.",
            interface,
        )
        sys.exit(1)

    log.info("Network interface '%s' found.", interface)

    # --- Get local MAC for self-frame filtering ---
    local_mac = trigger.get_interface_mac(interface)
    if local_mac is None:
        log.warning("Could not read MAC address for %s — self-frame filtering disabled", interface)

    # --- Create display ---
    log.info("Creating %s display object", _get_display_type())
    display = _create_display()
    display.initialize()

    # --- Initial screen ---
    _show(display, build_waiting_for_link_lines(), force=True)

    # --- Main event loop ---
    while not shutdown_event.is_set():

        carrier = _read_carrier(interface)

        if not carrier:
            _show(display, build_waiting_for_link_lines())
            _wait_or_shutdown(shutdown_event, 0.5)
            continue

        # ---- Link is up — start a discovery session ----
        log.info("Link up on %s — starting discovery", interface)

        # Wait for auto-negotiation to complete before transmitting.
        # During the 1-3 second negotiation window no frames can be sent
        # or received. Polling here prevents wasted trigger frames being
        # dropped by the NIC before the link is ready.
        negotiated = _wait_for_negotiation(interface, shutdown_event, timeout=5.0)
        if not negotiated:
            log.debug("Link speed did not negotiate on %s — proceeding anyway", interface)

        if shutdown_event.is_set():
            break

        if not _read_carrier(interface):
            # Link dropped during negotiation.
            _show(display, build_waiting_for_link_lines(), force=True)
            continue

        # Send the LLDP trigger immediately after negotiation, before the
        # display starts drawing "Scanning...". The e-paper takes ~400ms
        # for a partial refresh — every millisecond of head start matters
        # on LLDP switches that respond almost immediately.
        trigger.send_lldp_trigger(interface, local_mac)
        log.debug("Early LLDP trigger sent on %s before display draw", interface)

        # Show "Scanning..." and note when it finishes drawing.
        # The reveal delay timer starts AFTER the display finishes drawing
        # so the user always sees the screen for at least reveal_delay seconds.
        _show(display, build_scanning_lines(), force=True)
        scan_drawn_at = time.monotonic()

        log.debug(
            "Scanning screen shown. Reveal delay: %.2fs after screen draw.",
            reveal_delay,
        )

        # cancel_event is set when link goes down or shutdown fires.
        cancel_event = threading.Event()

        # ---- Session state shared with the discovery thread ----
        # Results arrive one protocol at a time. Each one is merged into the
        # latest result per protocol (SNMP > LLDP > CDP per field) and the
        # screen is updated whenever what it shows changes.
        lock            = threading.Lock()
        by_protocol:    dict[str, dict]           = {}
        current_result: list[Optional[dict]]      = [None]
        first_result_at: list[Optional[float]]    = [None]
        last_success_ts = [time.monotonic()]
        stale_shown     = [False]
        displayed       = threading.Event()   # first result has been drawn
        race_done       = threading.Event()   # initial discovery finished

        def _on_result(fresh: dict) -> None:
            """Merge one protocol's result and update the screen if it changed."""
            with lock:
                last_success_ts[0] = time.monotonic()
                protocol = fresh.get("protocol", "?")
                by_protocol[protocol] = race.keep_better(by_protocol.get(protocol), fresh)
                merged = race.merge_results(by_protocol)

                prev = current_result[0]
                current_result[0] = merged
                if first_result_at[0] is None:
                    first_result_at[0] = time.monotonic()

                # Until the first draw, the main loop below decides when to show.
                if not displayed.is_set():
                    return

                screen_changed = _screen_content(merged) != _screen_content(prev)
                if not (screen_changed or stale_shown[0]):
                    return

                is_upgrade = prev["is_partial"] and not merged["is_partial"]
                _show_result(display, merged, f"Display updated with {protocol}")
                stale_shown[0] = False
                if is_upgrade:
                    history.record(merged)

        def _discovery_thread():
            # Initial discovery: SNMP, LLDP and CDP in parallel, each result
            # passed to _on_result as soon as it arrives.
            race.run(
                interface=interface,
                local_mac=local_mac,
                cancel_event=cancel_event,
                on_result=_on_result,
                timeout=disc_timeout,
            )
            race_done.set()

            with lock:
                if current_result[0] is not None:
                    history.record(current_result[0])

            # Keep listening for LLDP/CDP for the rest of the session. This
            # resets the stale timer, fills in fields that were missing, and
            # picks up changes such as a VLAN reassignment.
            while not cancel_event.is_set() and not shutdown_event.is_set():
                fresh = discover_passive.discover(
                    interface=interface,
                    local_mac=local_mac,
                    cancel_event=cancel_event,
                    timeout=disc_timeout,
                )
                if fresh and not cancel_event.is_set():
                    _on_result(fresh)

        discovery_thread = threading.Thread(
            target=_discovery_thread,
            name="rf-discovery",
            daemon=True,
        )
        discovery_thread.start()

        # ---- Monitor link and decide when to draw ----
        while not shutdown_event.is_set():
            if not _read_carrier(interface):
                log.info("Link lost on %s — stopping discovery", interface)
                cancel_event.set()
                discovery_thread.join(timeout=5.0)
                display.set_startup_mode(True)
                _show(display, build_waiting_for_link_lines(), force=True)
                break

            now = time.monotonic()
            with lock:
                best = current_result[0]

                # First draw. A complete result is shown as soon as the
                # "Scanning..." screen has been up for reveal_delay seconds.
                # A partial result (switch name or port missing) is held for
                # PARTIAL_DISPLAY_DELAY seconds in case another protocol
                # fills the gap — something is better than nothing after that.
                if best is not None and not displayed.is_set():
                    if not best["is_partial"]:
                        if now - scan_drawn_at >= reveal_delay:
                            _show_result(display, best, "Display updated")
                            displayed.set()
                    elif now - first_result_at[0] >= partial_display_delay:
                        _show_result(
                            display,
                            best,
                            f"Partial result displayed after {now - first_result_at[0]:.0f}s delay",
                        )
                        displayed.set()

                # Nothing found at all: show the stale screen. Discovery keeps
                # listening, so a late LLDP/CDP frame still gets drawn.
                if best is None and race_done.is_set() and not stale_shown[0]:
                    log.info("Discovery timed out on %s", interface)
                    _show(display, build_stale_lines(), force=True)
                    stale_shown[0] = True

                # Shown data has not been re-advertised within the timeout.
                stale_elapsed = now - last_success_ts[0]
                if displayed.is_set() and not stale_shown[0] and stale_elapsed > disc_timeout:
                    log.info(
                        "Neighbor data stale on %s (%.0fs since last success)",
                        interface,
                        stale_elapsed,
                    )
                    _show(display, build_stale_lines(), force=True)
                    stale_shown[0] = True

            _wait_or_shutdown(shutdown_event, 0.25)

        cancel_event.set()

    # ---- Graceful shutdown ----
    log.info("Shutting down PiScout")
    try:
        display.shutdown()
    except Exception as exc:
        log.debug("Display shutdown error: %s", exc)


def _wait_or_shutdown(shutdown_event: threading.Event, seconds: float) -> None:
    """Sleep for up to `seconds` but wake immediately if shutdown fires."""
    shutdown_event.wait(timeout=seconds)


# ============================================================
# -------------------- ENTRY POINT ---------------------------
# ============================================================

if __name__ == "__main__":
    try:
        run()
    except Exception:
        log.exception("Fatal error in main loop")
        sys.exit(1)
