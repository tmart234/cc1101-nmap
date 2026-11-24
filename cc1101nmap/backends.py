"""Radio backends: where observations come from.

* StockEvilCrow  - unmodified Evil Crow RF V2 firmware (joelsernamoreno/EvilCrowRF-V2).
                   Uses its real HTTP routes: POST /setrx, POST /stoprx, GET /logs,
                   POST /delete. Captures OOK pulse timings only (no RSSI).
* NmapFirmware   - the receive-only companion firmware in firmware/ (RSSI sweeps,
                   pulse capture with RSSI, hardware FSK packet mode).
* Replay         - re-run a recorded JSONL session (field debugging, sharing captures).

All backends run in their own thread and push observations into the Engine.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from typing import Callable, Dict, List, Optional

from .catalog import Catalog
from .obs import Packet, PulseCapture, SpectrumFrame
from .pulses import parse_stock_log

log = logging.getLogger(__name__)

try:
    import requests
except ImportError:  # only the hardware backends need it
    requests = None


class Recorder:
    """Writes every raw observation as JSON lines so a session can be replayed."""

    def __init__(self, path: str):
        self.fh = open(path, "a", buffering=1)
        self.lock = threading.Lock()

    def write(self, kind: str, obj) -> None:
        d = {"type": kind, **{k: (v.hex() if isinstance(v, bytes) else v) for k, v in vars(obj).items()}}
        with self.lock:
            self.fh.write(json.dumps(d) + "\n")


class Sink:
    """Fan-out from a backend to the engine (and optional recorder)."""

    def __init__(self, engine, recorder: Optional[Recorder] = None):
        self.engine = engine
        self.recorder = recorder

    def capture(self, c: PulseCapture):
        if self.recorder:
            self.recorder.write("capture", c)
        self.engine.ingest_capture(c)

    def packet(self, p: Packet):
        if self.recorder:
            self.recorder.write("packet", p)
        self.engine.ingest_packet(p)

    def spectrum(self, s: SpectrumFrame):
        if self.recorder:
            self.recorder.write("spectrum", s)
        self.engine.ingest_spectrum(s)

    def status(self, **kw):
        self.engine.set_status(**kw)


class ProfileRotator:
    """Cycles a receiver through RX profiles, honouring each profile's dwell time."""

    def __init__(self, profiles: List[dict], dwell_scale: float = 1.0):
        self.profiles = profiles
        self.scale = dwell_scale
        self.idx = -1
        self.until = 0.0

    def duty(self) -> Dict[float, float]:
        """Fraction of time spent listening on each frequency."""
        total = sum(p.get("dwell_s", 60) for p in self.profiles) or 1
        out: Dict[float, float] = {}
        for p in self.profiles:
            out[p["freq_mhz"]] = out.get(p["freq_mhz"], 0) + p.get("dwell_s", 60) / total
        return out

    def due(self, now: float) -> bool:
        return bool(self.profiles) and now >= self.until

    def advance(self, now: float) -> dict:
        self.idx = (self.idx + 1) % len(self.profiles)
        p = self.profiles[self.idx]
        self.until = now + p.get("dwell_s", 60) * self.scale
        return p

    @property
    def current(self) -> Optional[dict]:
        return self.profiles[self.idx] if self.profiles and self.idx >= 0 else None


class Backend(threading.Thread):
    kind = "base"

    def __init__(self, sink: Sink, catalog: Catalog):
        super().__init__(daemon=True, name=f"backend-{self.kind}")
        self.sink = sink
        self.catalog = catalog
        self.stop_event = threading.Event()

    def stop(self):
        self.stop_event.set()

    def sleep(self, s: float) -> bool:
        return not self.stop_event.wait(s)


class HttpBackend(Backend):
    def __init__(self, sink, catalog, host: str, timeout: float = 6.0):
        super().__init__(sink, catalog)
        if requests is None:
            raise RuntimeError("The 'requests' package is required: pip install requests")
        self.base = host if host.startswith("http") else f"http://{host}"
        self.http = requests.Session()
        self.timeout = timeout
        self.failures = 0

    def get(self, path: str, **params):
        r = self.http.get(self.base + path, params=params or None, timeout=self.timeout)
        r.raise_for_status()
        return r

    def post(self, path: str, **data):
        r = self.http.post(self.base + path, data=data, timeout=self.timeout)
        r.raise_for_status()
        return r

    def run(self):
        while not self.stop_event.is_set():
            try:
                self.session()
            except Exception as e:  # network drops, device reboots
                self.failures += 1
                wait = min(30, 2 ** min(self.failures, 5))
                log.warning("%s backend error: %s (retrying in %ds)", self.kind, e, wait)
                self.sink.status(connected=False, error=str(e)[:200])
                if not self.sleep(wait):
                    return

    def session(self):
        raise NotImplementedError


class StockEvilCrow(HttpBackend):
    """Drives the stock Evil Crow RF V2 web firmware.

    The stock ISR records edges from both CC1101s into one buffer, so only one
    module listens at a time; we rotate it through the OOK profiles. Captures
    are written to the SD card's /logs.txt, which we poll and periodically
    clear. An SD card must be inserted (the stock firmware needs it anyway).
    """
    kind = "stock"
    LOG_LIMIT = 48_000

    def __init__(self, sink, catalog, host="evilcrow-rf.local", module: int = 1, poll_s: float = 2.0,
                 dwell_scale: float = 1.0):
        super().__init__(sink, catalog, host)
        self.module = module
        self.poll_s = poll_s
        profiles = [p for p in catalog.profiles("stock") if p["mode"] == "ook"]
        profiles.sort(key=lambda p: not p.get("pin"))
        self.rotator = ProfileRotator(profiles, dwell_scale)
        sink.engine.listen_duty = self.rotator.duty()
        self.offset = 0

    def configure(self, p: dict):
        self.post("/stoprx")
        self.post("/setrx", module=str(self.module), frequency=f"{p['freq_mhz']:.3f}",
                  setrxbw=str(p.get("rxbw_khz", 270)), mod="2", deviation="0",
                  datarate=str(p.get("drate_kbaud", 5)), configmodule="1")
        log.info("Stock firmware: module %d listening on %.3f MHz OOK (%s)", self.module, p["freq_mhz"],
                 p.get("why", p["id"]))
        self.sink.status(listening=[{"module": self.module, "freq_mhz": p["freq_mhz"], "mode": "OOK",
                                     "profile": p["id"], "why": p.get("why", "")}])

    def read_logs(self, freq: float):
        text = self.get("/logs").text
        if len(text) < self.offset:          # cleared by someone else
            self.offset = 0
        new = text[self.offset:]
        # only consume through the last complete capture block
        cut = new.rfind("-----\n")
        if cut < 0:
            return
        new = new[:cut + 6]
        self.offset += len(new)
        for pulses in parse_stock_log(new):
            self.sink.capture(PulseCapture(pulses, freq, "OOK", time.time(), None, "stock"))
        if self.offset > self.LOG_LIMIT:
            self.post("/delete")
            self.offset = 0

    def session(self):
        self.get("/connectioncheck")
        try:
            stats = self.get("/stats").json()
        except ValueError:
            stats = {}
        if stats and not stats.get("sdcard_present", True):
            log.error("Evil Crow reports no SD card: the stock firmware can't log captures without one.")
        self.post("/delete")
        self.offset = 0
        self.failures = 0
        self.sink.status(connected=True, backend="stock", host=self.base, device=stats, error=None,
                         capabilities=["OOK pulse capture"],
                         limitations=["No RSSI sweeps with stock firmware: public-safety/cellular/LoRa energy "
                                      "detection needs the cc1101-nmap companion firmware.",
                                      "No RSSI per capture, so no distance estimates for decoded devices."])
        if not self.rotator.profiles:
            raise RuntimeError("No OOK RX profiles for this region")
        while not self.stop_event.is_set():
            now = time.time()
            if self.rotator.due(now):
                if self.rotator.current:
                    self.read_logs(self.rotator.current["freq_mhz"])
                self.configure(self.rotator.advance(now))
            self.read_logs(self.rotator.current["freq_mhz"])
            if not self.sleep(self.poll_s):
                return


class NmapFirmware(HttpBackend):
    """Talks to the receive-only cc1101-nmap companion firmware (firmware/)."""
    kind = "nmap"

    def __init__(self, sink, catalog, host="cc1101-nmap.local", poll_s: float = 1.0, dwell_scale: float = 1.0,
                 max_points: int = 600, dashboard_port: Optional[int] = None):
        super().__init__(sink, catalog, host)
        self.poll_s = poll_s
        self.max_points = max_points
        self.rotator = ProfileRotator(catalog.profiles("nmap"), dwell_scale)
        sink.engine.listen_duty = self.rotator.duty()
        self.seq = 0
        self.dashboard_port = dashboard_port

    def configure(self, p: dict):
        mode = p["mode"]
        args = dict(module="2", freq_khz=f"{p['freq_mhz'] * 1000:.1f}", mode=mode,
                    rxbw_khz=str(p.get("rxbw_khz", 203)), drate=str(p.get("drate_kbaud", 5)),
                    dev_khz=str(p.get("dev_khz", 0)))
        if mode in ("fsk_pkt", "ook_pkt"):
            args.update(sync=p["sync"], pktlen=str(p.get("pktlen", 20)))
            if p.get("manchester"):
                args["manchester"] = "1"
        if p.get("min_us"):
            args["min_us"] = str(p["min_us"])
        self.post("/nmap/rx", **args)
        self.sink.status(listening=[{"module": 2, "freq_mhz": p["freq_mhz"], "mode": mode.upper(),
                                     "profile": p["id"], "why": p.get("why", "")}])

    def session(self):
        params = {"dash": self.dashboard_port} if self.dashboard_port else {}
        info = self.get("/nmap/info", **params).json()
        if info.get("fw") != "cc1101-nmap":
            raise RuntimeError(f"{self.base} is not running cc1101-nmap firmware")
        plan = self.catalog.sweep_plan(min(self.max_points, int(info.get("max_points", 1024))))
        seg = ",".join(f"{s.start_mhz * 1000:.1f}:{s.stop_mhz * 1000:.1f}:{s.step_khz:g}:{s.rxbw_khz:g}" for s in plan)
        res = self.post("/nmap/plan", segments=seg).json()
        log.info("Sweep plan: %d segments, %d points", len(plan), res.get("points", 0))
        self.failures = 0
        self.sink.status(connected=True, backend="nmap", host=self.base, device=info, error=None,
                         sweep_points=res.get("points"), sweep_segments=len(plan),
                         capabilities=["RSSI sweep", "OOK pulse capture", "FSK packet mode"], limitations=[])
        self.seq = int(info.get("seq", 0))
        while not self.stop_event.is_set():
            now = time.time()
            if self.rotator.due(now):
                self.configure(self.rotator.advance(now))
            self.poll_spectrum()
            self.poll_events()
            if not self.sleep(self.poll_s):
                return

    def poll_spectrum(self):
        d = self.get("/nmap/spectrum").json()
        if not d.get("sweeps"):
            return
        freqs = [f / 1e6 for f in d["freq_hz"]]
        self.sink.spectrum(SpectrumFrame(freqs, [float(v) for v in d["peak"]], [float(v) for v in d["avg"]],
                                         [float(v) for v in d["rxbw_khz"]], int(d["sweeps"]), time.time(), "nmap"))
        self.sink.status(sweep_ms=d.get("sweep_ms"))

    def poll_events(self):
        d = self.get("/nmap/events", since=self.seq).json()
        now_host, now_dev = time.time(), d.get("now_ms", 0)

        def t(ms):
            return now_host - max(0, now_dev - ms) / 1000.0
        for c in d.get("captures", []):
            self.sink.capture(PulseCapture(c["pulses"], c["freq_khz"] / 1000, "FSK" if c["mode"] != "ook" else "OOK",
                                           t(c["ms"]), c.get("rssi"), "nmap"))
        for p in d.get("packets", []):
            self.sink.packet(Packet(bytes.fromhex(p["hex"]), p["freq_khz"] / 1000, p["sync"], t(p["ms"]),
                                    p.get("rssi"), p.get("lqi"), "nmap"))
        if d.get("dropped"):
            log.warning("Firmware dropped %d events (poll faster?)", d["dropped"])
        self.seq = int(d.get("seq", self.seq))


class Replay(Backend):
    kind = "replay"

    def __init__(self, sink, catalog, path: str, speed: float = 1.0):
        super().__init__(sink, catalog)
        self.path = path
        self.speed = speed

    def run(self):
        self.sink.status(connected=True, backend="replay", host=self.path, capabilities=["replay"], limitations=[])
        first_t, start = None, time.time()
        with open(self.path) as fh:
            for line in fh:
                if self.stop_event.is_set():
                    return
                d = json.loads(line)
                kind = d.pop("type")
                first_t = d["t"] if first_t is None else first_t
                delay = (d["t"] - first_t) / self.speed - (time.time() - start)
                if delay > 0 and not self.sleep(delay):
                    return
                d["t"] = time.time()
                if kind == "capture":
                    self.sink.capture(PulseCapture(**d))
                elif kind == "packet":
                    d["data"] = bytes.fromhex(d["data"])
                    self.sink.packet(Packet(**d))
                elif kind == "spectrum":
                    self.sink.spectrum(SpectrumFrame(**d))
        self.sink.status(replay_done=True)
        log.info("Replay finished")


BACKENDS: Dict[str, Callable] = {"stock": StockEvilCrow, "nmap": NmapFirmware, "replay": Replay}
