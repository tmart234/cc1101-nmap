"""A simulated neighbourhood for demos and tests (--backend sim).

It behaves like the companion firmware: an RSSI sweep plus an analyst
receiver rotating through RX profiles. Devices are generated with the real
protocol encoders, so everything goes through the same decode and
classification path as live hardware. The dashboard flags simulated data.
"""
from __future__ import annotations

import math
import random
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from . import encoders as E
from .backends import Backend, ProfileRotator
from .obs import Packet, PulseCapture, SpectrumFrame


@dataclass
class SimDevice:
    name: str
    freq_mhz: float
    period_s: float
    rssi: float
    make: Callable[["SimDevice", random.Random], object]   # returns pulses (list) or (sync, bytes)
    mode: str = "ook"                  # ook | fsk_pkt
    next_t: float = 0.0
    state: dict = field(default_factory=dict)


@dataclass
class Emitter:
    """An RF energy source seen by the sweep."""
    freq_mhz: float
    rssi: float
    on: Callable[[float], bool]        # is it transmitting at time t (seconds since start)?
    width_khz: float = 12.5


def _bursty(rng: random.Random, every_s: float, dur_s: float, start: float = 0, stop: float = math.inf,
            phase: Optional[float] = None) -> Callable[[float], bool]:
    phase = rng.uniform(0, every_s) if phase is None else phase

    def on(t: float) -> bool:
        if not start <= t <= stop:
            return False
        return ((t - start + phase) % every_s) < dur_s
    return on


def _cycle(period: float, windows: List[tuple], inner: Callable[[float], bool]) -> Callable[[float], bool]:
    """Repeat a scenario every `period` seconds; active only inside the windows."""
    def on(t: float) -> bool:
        tm = t % period
        return any(a <= tm <= b for a, b in windows) and inner(tm)
    return on


class SimWorld:
    def __init__(self, region: str = "US", seed: int = 1):
        self.rng = random.Random(seed)
        self.region = region
        self.devices: List[SimDevice] = []
        self.emitters: List[Emitter] = []
        self._build()

    def _build(self):
        r = self.rng
        dev = self.devices.append
        if self.region == "US":
            dev(SimDevice("Acurite tower (your yard)", 433.92, 18, -61,
                          lambda d, g: E.acurite_tower(2345, "A", d.state.setdefault("t", 21.0) + g.uniform(-.2, .2),
                                                       48, rng=g)))
            dev(SimDevice("Neighbour LaCrosse", 433.92, 50, -79,
                          lambda d, g: E.lacrosse_tx141th(0x5C, 0, 19.4 + g.uniform(-.3, .3), 61, rng=g)))
            dev(SimDevice("Ambient WS-2902 array", 915.0, 16, -67,
                          lambda d, g: ("2dd4", E.fineoffset_wh65(0xA7, 20.6, 52, g.randint(150, 230),
                                                                 g.uniform(0.5, 3), g.uniform(2, 5), 41)),
                          mode="fsk_pkt"))
            dev(SimDevice("WH31E in garage", 915.0, 61, -74,
                          lambda d, g: ("2dd4", E.ambient_wh31e(0x44, 2, 14.2, 63)), mode="fsk_pkt"))

            def door(d, g):
                d.state["open"] = not d.state.get("open", False) if g.random() < 0.5 else d.state.get("open", False)
                return E.honeywell(0x5A3C1, 8, contact_open=d.state["open"], heartbeat=g.random() < 0.3, rng=g)
            dev(SimDevice("Honeywell 5816 back door", 345.0, 140, -70, door))
            dev(SimDevice("2GIG motion (neighbour)", 345.0, 400, -86,
                          lambda d, g: E.honeywell(0x2B7E0, 2, heartbeat=True, rng=g)))
            dev(SimDevice("Doorbell button (EV1527)", 433.92, 230, -66,
                          lambda d, g: E.ev1527(0x6D2A18, 340, rng=g)))
            dev(SimDevice("Schrader TPMS (parked car)", 315.0, 120, -78,
                          lambda d, g: E.schrader_tpms(0x6703A38, 225.0, 23, rng=g)))
            dev(SimDevice("Apartment gate (MegaCode)", 318.0, 240, -74,
                          lambda d, g: E.megacode(3, 17316, 1, rng=g)))
            dev(SimDevice("Medtronic MiniMed pump", 916.5, 180, -76,
                          lambda d, g: ("ff00", E.minimed(0xA7, "597055", b"\x04\x00", pad_len=60)),
                          mode="ook_pkt"))
            dev(SimDevice("Omnipod Eros pod", 433.91, 210, -79,
                          lambda d, g: ("54c3", E.omnipod("1f014829", "POD", 14)),
                          mode="fsk_pkt"))
            # an unknown, clearly structured signal on 319.5 MHz (Interlogix band)
            dev(SimDevice("Interlogix sensor", 319.5, 300, -77,
                          lambda d, g: E.pwm("1011001110001011101011100101", (500, 250), (250, 500), g) * 3))

            # --- energy emitters (sweep) ---
            em = self.emitters.append
            em(Emitter(851.2125, -74, lambda t: True))                       # county P25 control channel
            em(Emitter(855.4875, -88, lambda t: True))                       # second site, farther
            em(Emitter(851.6125, -76, _bursty(r, 47, 9)))                    # voice channel (anyone, anywhere)
            # incident next door: patrol units arrive, talk, leave (every 15 min cycle)
            incident = [(40, 420)]
            em(Emitter(809.6125, -41, _cycle(900, incident, _bursty(r, 26, 5))))
            em(Emitter(808.3125, -63, _cycle(900, incident, _bursty(r, 37, 4))))
            em(Emitter(793.0, -57, _cycle(900, incident, _bursty(r, 20, 2)), width_khz=5000))   # FirstNet router
            em(Emitter(806.5625, -96, _bursty(r, 180, 6)))                   # distant interop traffic
            em(Emitter(836.52, -58, _bursty(r, 33, 3), width_khz=5000))      # a phone nearby
            em(Emitter(904.3, -82, _bursty(r, 61, 0.4), width_khz=125))      # LoRaWAN sensor
            for i in range(6):                                               # meters hopping
                em(Emitter(910.5 + i * 1.7, -80 - 2 * i, _bursty(r, 9 + i, 0.6), width_khz=200))
            em(Emitter(452.9375, -52, _cycle(1300, [(300, 420)], _bursty(r, 12, 1.5))))   # passing train
            em(Emitter(462.5625, -69, _cycle(700, [(200, 320)], _bursty(r, 19, 4))))      # FRS radios
            em(Emitter(415.1, -90, _bursty(r, 300, 3)))                       # federal, far
        else:
            dev(SimDevice("TFA 30.3155 (TX35)", 868.3, 4.1, -68,
                          lambda d, g: ("2dd4", E.lacrosse_itplus(17, 12.3 + g.uniform(-.1, .1), 71)), mode="fsk_pkt"))
            dev(SimDevice("Kamstrup water meter", 868.95, 16, -77,
                          lambda d, g: ("543d", E.wmbus_t1("KAM", "70223318", 0x1B, 0x16)), mode="fsk_pkt"))
            dev(SimDevice("Techem heat allocator", 868.95, 120, -84,
                          lambda d, g: ("543d", E.wmbus_c1a("TCH", "40751122", 0x6A, 0x08)), mode="fsk_pkt"))
            dev(SimDevice("Doorbell (EV1527)", 433.92, 260, -70, lambda d, g: E.ev1527(0x3C5A90, 300, rng=g)))
            dev(SimDevice("Medtronic MiniMed pump (EU)", 868.35, 180, -77,
                          lambda d, g: ("ff00", E.minimed(0xA7, "597055", b"\x04\x00", pad_len=60)),
                          mode="ook_pkt"))
            em = self.emitters.append
            em(Emitter(392.7125, -78, lambda t: True, width_khz=25))
            em(Emitter(382.3375, -45, _cycle(900, [(60, 480)], _bursty(r, 22, 6)), width_khz=25))
            em(Emitter(847.5, -60, _bursty(r, 29, 3), width_khz=5000))
            em(Emitter(868.1, -83, _bursty(r, 70, 0.3), width_khz=125))
            em(Emitter(869.2125, -72, _bursty(r, 240, 2), width_khz=25))     # EU social alarm (only swept with --allow-sensitive)
            em(Emitter(446.05625, -71, _cycle(800, [(100, 260)], _bursty(r, 15, 4))))
        for d in self.devices:
            d.next_t = self.rng.uniform(1, min(d.period_s, 30))

    def spectrum(self, t: float, freqs: List[float], rxbw: List[float], stamp: float) -> SpectrumFrame:
        g = self.rng
        peak, avg = [], []
        for f, bw in zip(freqs, rxbw):
            floor = -101 + 10 * math.log10(max(bw, 58) / 58) + g.gauss(0, 1.2)
            p = a = floor
            for e in self.emitters:
                half = (bw + e.width_khz) / 2000
                if abs(e.freq_mhz - f) <= half and e.on(t):
                    level = e.rssi - (3 if abs(e.freq_mhz - f) > bw / 2000 else 0) + g.gauss(0, 1.5)
                    p = max(p, level)
                    a = max(a, level - 4)
            peak.append(round(p, 1))
            avg.append(round(a, 1))
        return SpectrumFrame(freqs, peak, avg, rxbw, 1, stamp, "sim")


class SimBackend(Backend):
    kind = "sim"

    def __init__(self, sink, catalog, speed: float = 1.0, seed: int = 1, tick_s: float = 1.0):
        super().__init__(sink, catalog)
        self.world = SimWorld(catalog.region if catalog.region in ("US", "EU") else "US", seed)
        self.speed = speed
        self.tick_s = tick_s
        self.t0 = time.time()
        self.stamp = lambda t: self.t0 + t      # tests: simulated time; live: wall clock (see run)
        self.rotator = ProfileRotator(catalog.profiles("nmap"), dwell_scale=0.35)
        sink.engine.listen_duty = self.rotator.duty()
        plan = catalog.sweep_plan()
        self.freqs, self.rxbw = [], []
        for s in plan:
            n = s.points
            for i in range(n):
                self.freqs.append(round(s.start_mhz + i * s.step_khz / 1000, 5))
                self.rxbw.append(s.rxbw_khz)

    def step(self, t: float):
        """Advance the world to simulated time t (seconds since start)."""
        if self.rotator.due(t):
            p = self.rotator.advance(t)
            self.sink.status(listening=[{"module": 2, "freq_mhz": p["freq_mhz"], "mode": p["mode"].upper(),
                                         "profile": p["id"], "why": p.get("why", "")}])
        cur = self.rotator.current
        if self.freqs:
            self.sink.spectrum(self.world.spectrum(t, self.freqs, self.rxbw, self.stamp(t)))
        g = self.world.rng
        for d in self.world.devices:
            if t < d.next_t:
                continue
            d.next_t = t + d.period_s * g.uniform(0.9, 1.1)
            listening = cur and abs(cur["freq_mhz"] - d.freq_mhz) < 0.15 and cur["mode"] == d.mode
            if not listening:
                continue
            out = d.make(d, g)
            rssi = d.rssi + g.gauss(0, 2)
            if d.mode in ("fsk_pkt", "ook_pkt"):
                sync, data = out
                self.sink.packet(Packet(data, d.freq_mhz, sync, self.stamp(t), round(rssi, 1), 40, "sim"))
            else:
                self.sink.capture(PulseCapture(out, d.freq_mhz, "OOK", self.stamp(t), round(rssi, 1), "sim"))

    def run(self):
        self.sink.status(connected=True, backend="sim", host="simulated neighbourhood", simulated=True,
                         sweep_points=len(self.freqs), capabilities=["RSSI sweep", "OOK pulse capture",
                                                                     "FSK packet mode"], limitations=[])
        start = time.time()
        self.stamp = lambda t: time.time()
        while not self.stop_event.is_set():
            self.step((time.time() - start) * self.speed)
            if not self.sleep(self.tick_s):
                return
