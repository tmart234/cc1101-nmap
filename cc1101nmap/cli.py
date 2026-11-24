"""Command line entry point: python -m cc1101nmap  (or ./evilcrow_scanner.py)."""
from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading

from .backends import NmapFirmware, Recorder, Replay, Sink, StockEvilCrow, requests
from .catalog import Catalog
from .engine import Engine
from .sim import SimBackend
from .web import serve

log = logging.getLogger("cc1101nmap")

LEGACY = ("--interval", "--freqs", "--rssi-threshold", "--hunter-radio", "--analyst-radio")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cc1101-nmap",
        description="Passive sub-GHz scanner for the Evil Crow RF V2 / CC1101: identifies what is "
                    "transmitting near you and shows it on a live web dashboard. Receive-only.")
    p.add_argument("--backend", choices=["auto", "stock", "nmap", "sim", "replay"], default="auto",
                   help="auto (default): detect firmware on --host; stock: unmodified Evil Crow firmware; "
                        "nmap: cc1101-nmap companion firmware; sim: demo neighbourhood; replay: a --record file")
    p.add_argument("--host", "--ip", dest="host", default="evilcrow-rf.local",
                   help="Evil Crow address (default evilcrow-rf.local, the stock firmware's mDNS name)")
    p.add_argument("--region", choices=["US", "EU"], default="US", help="band plan to use (default US)")
    p.add_argument("--extended-range", action="store_true",
                   help="also tune 281-361/378-481/749-962 MHz (outside the CC1101 datasheet; reduced sensitivity). "
                        "Needed for EU TETRA uplink, US paging, 467 MHz FRS")
    p.add_argument("--local-freqs", metavar="CSV",
                   help="your area's frequencies (freq_mhz,label,category or a RadioReference-style export)")
    p.add_argument("--allow-sensitive", action="store_true",
                   help="show replayable codes, persistent TPMS IDs, and health/distress/medical bands & devices "
                        "(MedRadio, EMS MED, 406 MHz beacons, telecare, EU alarms, MiniMed/Omnipod)")
    p.add_argument("--web-host", default="0.0.0.0", help="dashboard bind address (default all interfaces)")
    p.add_argument("--web-port", type=int, default=8080, help="dashboard port (default 8080)")
    p.add_argument("--no-web", action="store_true", help="don't start the dashboard")
    p.add_argument("--json", action="store_true", help="print every event as a JSON line on stdout")
    p.add_argument("--events-log", metavar="FILE", help="append events as JSON lines to FILE")
    p.add_argument("--record", metavar="FILE", help="record raw observations (for --backend replay)")
    p.add_argument("--replay", metavar="FILE", help="file for --backend replay")
    p.add_argument("--speed", type=float, default=1.0, help="replay/simulation speed factor")
    p.add_argument("--dwell-scale", type=float, default=1.0, help="scale how long the receiver stays on each RX profile")
    p.add_argument("--path-loss", type=float, default=2.7,
                   help="path-loss exponent for distance estimates (2 open field, 2.7 suburban, 3.5 dense urban)")
    p.add_argument("--margin-db", type=float, default=12.0, help="dB above the noise floor that counts as a transmission")
    p.add_argument("--max-sweep-points", type=int, default=600, help="cap on RSSI sweep size (more = slower sweeps)")
    p.add_argument("--list", action="store_true", help="print what can be detected with these settings and exit")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true", help="only warnings and alerts")
    for legacy in LEGACY:
        p.add_argument(legacy, help=argparse.SUPPRESS)
    return p


def detect_firmware(host: str) -> str:
    base = host if host.startswith("http") else f"http://{host}"
    try:
        r = requests.get(base + "/nmap/info", timeout=4)
        if r.ok and r.json().get("fw") == "cc1101-nmap":
            return "nmap"
    except (requests.RequestException, ValueError):
        pass
    return "stock"


def print_catalog(cat: Catalog, max_points: int):
    print(f"Region {cat.region}, tuning {'extended' if cat.extended else 'datasheet'} ranges"
          f"{', sensitive enabled' if cat.allow_sensitive else ''}\n")
    order = {"decode": 0, "pulses": 1, "energy": 2}
    for e in sorted(cat.entries, key=lambda e: (order[e.detect], e.category)):
        rng = ", ".join(f"{a:g}-{b:g}" for a, b in e.ranges_mhz)
        tag = " [sensitive]" if e.sensitive else ""
        print(f"  [{e.detect:6}] {e.name}{tag}  ({rng} MHz)")
    plan = cat.sweep_plan(max_points)
    print(f"\nRSSI sweep (companion firmware): {sum(s.points for s in plan)} points in {len(plan)} segments")
    print("RX profiles:", ", ".join(f"{p['id']} {p['freq_mhz']} MHz" for p in cat.rx_profiles))


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    level = logging.DEBUG if args.verbose else logging.WARNING if args.quiet else logging.INFO
    logging.basicConfig(level=level, format="[%(asctime)s] %(levelname)-7s %(message)s", datefmt="%H:%M:%S",
                        stream=sys.stderr)
    for legacy in LEGACY:
        if getattr(args, legacy.lstrip("-").replace("-", "_")) is not None:
            log.warning("%s is no longer used: scanning is continuous and frequencies come from the catalog "
                        "(see --region, --local-freqs, --list)", legacy)

    cat = Catalog.load(region=args.region, allow_sensitive=args.allow_sensitive,
                       extended=args.extended_range, local_freqs=args.local_freqs)
    if args.list:
        print_catalog(cat, args.max_sweep_points)
        return 0

    engine = Engine(cat, allow_sensitive=args.allow_sensitive, path_loss_n=args.path_loss, margin_db=args.margin_db)
    if args.json:
        engine.listeners.append(lambda ev: print(json.dumps(ev), flush=True))
    if args.events_log:
        fh = open(args.events_log, "a", buffering=1)
        engine.listeners.append(lambda ev: fh.write(json.dumps(ev) + "\n"))
    sink = Sink(engine, Recorder(args.record) if args.record else None)

    kind = args.backend
    if kind == "replay" and not args.replay:
        log.error("--backend replay needs --replay FILE")
        return 2
    if kind in ("auto", "stock", "nmap") and requests is None:
        log.error("The 'requests' package is required for hardware backends: pip install -r requirements.txt")
        return 2
    if kind == "auto":
        kind = detect_firmware(args.host)
        log.info("Detected %s firmware on %s", "cc1101-nmap" if kind == "nmap" else "stock Evil Crow", args.host)
    web = None if args.no_web else serve(engine, cat, args.web_host, args.web_port, args.max_sweep_points)

    if kind == "stock":
        backend = StockEvilCrow(sink, cat, args.host, dwell_scale=args.dwell_scale)
    elif kind == "nmap":
        backend = NmapFirmware(sink, cat, args.host, dwell_scale=args.dwell_scale, max_points=args.max_sweep_points,
                               dashboard_port=web.port if web else None)
    elif kind == "sim":
        backend = SimBackend(sink, cat, speed=args.speed)
    else:
        backend = Replay(sink, cat, args.replay, speed=args.speed)
    backend.start()

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    try:
        while not stop.wait(5):
            engine.tick()
    except KeyboardInterrupt:
        pass
    log.info("Shutting down")
    backend.stop()
    if web:
        web.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
