"""Detection engine: turns raw observations into "what is near me".

Three tracks feed one picture:

* Decoded devices  - a decoder verified the packet; we know the exact device.
* Unidentified     - a clearly structured signal (not noise) that no decoder
                     matched; reported with what normally uses that band.
* RF activity      - energy on a swept band (radios we can't demodulate, like
                     P25/TETRA/LTE). Bursty energy on a mobile-transmit band
                     means a radio is keying up nearby; continuous carriers are
                     infrastructure (towers) and are listed separately.

Signal strength is converted into a rough distance using each emitter's
typical power and a log-distance path-loss model. It's an order-of-magnitude
guide ("next door" vs "down the street" vs "across town"), not a fix.
"""
from __future__ import annotations

import logging
import math
import statistics
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Deque, Dict, List, Optional, Tuple

from .catalog import CATEGORY_LABELS, Catalog, Entry
from .decoders import Decoded, decode_capture, decode_packet
from .obs import Packet, PulseCapture, SpectrumFrame
from .pulses import summarize

log = logging.getLogger(__name__)

PROXIMITY = (
    (50, "very_close", "very close (same or next building)"),
    (250, "nearby", "nearby (on your street)"),
    (1500, "area", "in the area"),
    (math.inf, "distant", "distant"),
)

STATEFUL_FIELDS = ("state", "alarm", "tamper", "battery_ok", "button_bits")


def estimate_distance_m(rssi_dbm: float, eirp_dbm: float, freq_mhz: float, n: float = 2.7) -> float:
    """Log-distance path loss, referenced to free-space loss at 1 m."""
    fspl_1m = 20 * math.log10(freq_mhz) - 27.55
    loss = eirp_dbm - rssi_dbm - fspl_1m
    return max(1.0, 10 ** (loss / (10 * n)))


def proximity(rssi: Optional[float], eirp: float, freq: float, n: float) -> Optional[dict]:
    if rssi is None:
        return None
    d = estimate_distance_m(rssi, eirp, freq, n)
    for limit, bucket, label in PROXIMITY:
        if d < limit:
            return {"bucket": bucket, "label": label, "meters": int(round(d, -1 if d > 100 else 0))}
    return None


@dataclass
class Track:
    key: str
    kind: str                       # device | unknown | rf
    entry: Optional[Entry]
    name: str
    freq_mhz: float
    first_seen: float
    last_seen: float
    count: int = 0
    rssi: Optional[float] = None
    fields: Dict[str, object] = field(default_factory=dict)
    integrity: str = ""
    sensitive_fields: tuple = ()
    history: Deque[Tuple[float, float]] = field(default_factory=lambda: deque(maxlen=120))
    tx_times: Deque[float] = field(default_factory=lambda: deque(maxlen=30))
    channels: Dict[float, dict] = field(default_factory=dict)
    continuous: bool = False
    episode_start: float = 0.0
    last_alert: float = -1e9
    fields_t: float = -1e9          # last time an rf_activity event was emitted
    gone: bool = False

    def interval(self) -> Optional[float]:
        if len(self.tx_times) < 3:
            return None
        deltas = [b - a for a, b in zip(self.tx_times, list(self.tx_times)[1:]) if b - a > 2]
        return statistics.median(deltas) if deltas else None


class Engine:
    def __init__(self, catalog: Catalog, allow_sensitive: bool = False, path_loss_n: float = 2.7,
                 margin_db: float = 12.0, clock: Callable[[], float] = time.time):
        self.catalog = catalog
        self.allow_sensitive = allow_sensitive
        self.n = path_loss_n
        self.margin_db = margin_db
        self.clock = clock
        self.lock = threading.RLock()
        self.changed = threading.Condition(self.lock)
        self.version = 0
        self.tracks: Dict[str, Track] = {}
        self.events: Deque[dict] = deque(maxlen=400)
        self.event_seq = 0
        self.listeners: List[Callable[[dict], None]] = []
        self.started = clock()
        self.stats = {"captures": 0, "noise_captures": 0, "packets": 0, "decoded": 0, "frames": 0, "sweeps": 0}
        self.status: Dict[str, object] = {}
        # fraction of time a receiver listens on each frequency (backends that
        # time-share a receiver set this, so silence isn't mistaken for "gone")
        self.listen_duty: Dict[float, float] = {}
        # spectrum state
        self.spectrum: Optional[SpectrumFrame] = None
        self.floor: Dict[int, float] = {}
        self.occupancy: Dict[int, float] = {}
        self.frames_seen: Dict[int, int] = {}
        self._energy_cache: Dict[int, Optional[Entry]] = {}

    def energy_entry(self, f: float) -> Optional[Entry]:
        k = int(round(f * 1000))
        if k not in self._energy_cache:
            self._energy_cache[k] = self.catalog.best(f, ("energy",))
        return self._energy_cache[k]

    # -- plumbing --------------------------------------------------------
    def _bump(self):
        self.version += 1
        self.changed.notify_all()

    def emit(self, kind: str, message: str, track: Optional[Track] = None, level: str = "info", **extra):
        self.event_seq += 1
        ev = {"seq": self.event_seq, "t": self.clock(), "kind": kind, "level": level, "message": message}
        if track:
            ev.update({"key": track.key, "category": track.entry.category if track.entry else "unknown"})
        ev.update(extra)
        self.events.append(ev)
        (log.warning if level == "alert" else log.info)("%s: %s", kind.upper(), message)
        for fn in self.listeners:
            try:
                fn(ev)
            except Exception:  # a broken sink must not stop the scanner
                log.exception("event listener failed")

    def set_status(self, **kw):
        with self.lock:
            self.status.update(kw)
            self._bump()

    # -- decoded and unidentified signals ---------------------------------
    def ingest_capture(self, cap: PulseCapture):
        with self.lock:
            self.stats["captures"] += 1
            results = decode_capture(cap)
            if results:
                for d in results:
                    self._device(d, cap.freq_mhz, cap.rssi, cap.t)
            else:
                s = summarize(cap.pulses)
                if s.structured:
                    self._unknown(cap, s)
                else:
                    self.stats["noise_captures"] += 1
            self._bump()

    def ingest_packet(self, pkt: Packet):
        with self.lock:
            self.stats["packets"] += 1
            for d in decode_packet(pkt):
                self._device(d, pkt.freq_mhz, pkt.rssi, pkt.t)
            self._bump()

    def _device(self, d: Decoded, freq: float, rssi: Optional[float], t: float):
        self.stats["decoded"] += 1
        entry = self.catalog.get(d.catalog_id)
        tr = self.tracks.get(d.device_key)
        if tr is None:
            tr = Track(d.device_key, "device", entry, entry.name if entry else d.model, freq, t, t,
                       integrity=d.integrity, sensitive_fields=d.sensitive_fields)
            self.tracks[d.device_key] = tr
            tr.fields = dict(d.fields)
            tr.fields["model"] = d.model
            self.emit("new_device", f"{d.model} ({self._ident(tr)}) at {freq:.2f} MHz{self._prox_txt(tr, rssi)}", tr)
        else:
            changes = [f for f in STATEFUL_FIELDS
                       if f in d.fields and tr.fields.get(f) is not None and tr.fields.get(f) != d.fields[f]]
            if tr.gone:
                self.emit("device_back", f"{d.model} ({self._ident(tr)}) is transmitting again", tr)
            for f in changes:
                lvl = "alert" if f in ("alarm", "tamper") and d.fields[f] else "info"
                self.emit("device_update", f"{d.model} ({self._ident(tr)}): {f} -> {d.fields[f]}", tr, lvl)
            tr.fields.update(d.fields)
            tr.fields["model"] = d.model
        if not tr.tx_times or t - tr.tx_times[-1] > 2:
            tr.tx_times.append(t)
            tr.count += 1
        tr.gone = False
        tr.last_seen, tr.freq_mhz = t, freq
        if rssi is not None:
            tr.rssi = rssi
            tr.history.append((t, rssi))

    def _unknown(self, cap: PulseCapture, s):
        entry = self.catalog.best(cap.freq_mhz, ("pulses",)) or self.catalog.best(cap.freq_mhz)
        key = f"unknown:{cap.freq_mhz:.2f}:{s.fingerprint}"
        tr = self.tracks.get(key)
        t = cap.t
        if tr is None:
            name = entry.name if entry and entry.detect == "pulses" else \
                f"Unidentified device ({entry.name} band)" if entry else "Unidentified device"
            tr = Track(key, "unknown", entry, name, cap.freq_mhz, t, t, integrity="structure")
            tr.fields = {"modulation": s.modulation_guess, "pulses_us": [w for w, _ in s.mark_clusters[:3]],
                         "gaps_us": [w for w, _ in s.gap_clusters[:3]], "bits_approx": s.marks}
            others = [e.name for e in self.catalog.match(cap.freq_mhz) if e is not entry][:3]
            if others:
                tr.fields["could_be"] = others
            self.tracks[key] = tr
            self.emit("new_signal", f"Unidentified {s.modulation_guess} signal at {cap.freq_mhz:.2f} MHz", tr)
        if not tr.tx_times or t - tr.tx_times[-1] > 2:
            tr.tx_times.append(t)
            tr.count += 1
        tr.last_seen = t
        if cap.rssi is not None:
            tr.rssi = cap.rssi
            tr.history.append((t, cap.rssi))

    # -- RF energy --------------------------------------------------------
    def ingest_spectrum(self, frame: SpectrumFrame):
        with self.lock:
            self.stats["frames"] += 1
            self.stats["sweeps"] += frame.sweeps
            self.spectrum = frame
            t = frame.t
            # Robust per-band noise reference: low percentile of this frame's averages.
            noise_ref = self._noise_refs(frame)
            active: List[int] = []
            for i, f in enumerate(frame.freqs_mhz):
                k = int(round(f * 1000))
                avg, peak = frame.avg_dbm[i], frame.peak_dbm[i]
                fl = self.floor.get(k, avg)
                fl = fl + 0.3 * (avg - fl) if avg < fl else fl + 0.01 * (avg - fl)
                self.floor[k] = fl
                ref = noise_ref[i]
                is_active = peak > ref + self.margin_db
                self.frames_seen[k] = self.frames_seen.get(k, 0) + 1
                self.occupancy[k] = self.occupancy.get(k, 0.0) * 0.95 + (0.05 if is_active else 0.0)
                if is_active:
                    active.append(i)
            for sig in self._group(frame, active):
                self._rf_signal(frame, sig, t)
            self._bump()

    def _noise_refs(self, frame: SpectrumFrame) -> List[float]:
        refs = [0.0] * len(frame.freqs_mhz)
        # group bins by catalog entry (each swept band is one entry)
        groups: Dict[str, List[int]] = {}
        for i, f in enumerate(frame.freqs_mhz):
            e = self.energy_entry(f)
            groups.setdefault(e.id if e else "_", []).append(i)
        for idxs in groups.values():
            vals = sorted(frame.avg_dbm[i] for i in idxs)
            if len(vals) >= 5:
                ref = vals[len(vals) // 5]
            else:  # single local channels: use their own long-term floor
                ref = min(self.floor.get(int(round(frame.freqs_mhz[i] * 1000)), vals[0]) for i in idxs)
            for i in idxs:
                refs[i] = ref
        return refs

    @staticmethod
    def _group(frame: SpectrumFrame, active: List[int]) -> List[List[int]]:
        """Group active bins by frequency overlap (segments can overlap in RF)."""
        order = sorted(active, key=lambda i: frame.freqs_mhz[i])
        groups: List[List[int]] = []
        reach = 0.0
        for i in order:
            f, half = frame.freqs_mhz[i], frame.rxbw_khz[i] / 2000
            if groups and f - half <= reach + 0.001:
                groups[-1].append(i)
            else:
                groups.append([i])
            reach = max(reach, f + half) if len(groups[-1]) > 1 else f + half
        return groups

    def _rf_signal(self, frame: SpectrumFrame, idxs: List[int], t: float):
        best_peak = max(frame.peak_dbm[i] for i in idxs)
        # among bins within 3 dB of the strongest, the narrowest one locates the signal best
        top = min((i for i in idxs if frame.peak_dbm[i] >= best_peak - 6),
                  key=lambda i: (frame.rxbw_khz[i], -frame.peak_dbm[i]))
        f, peak = frame.freqs_mhz[top], best_peak
        entry = self.energy_entry(f)
        if entry is None:
            return
        k = int(round(f * 1000))
        continuous = self.frames_seen.get(k, 0) >= 30 and self.occupancy.get(k, 0) > 0.6
        infra = entry.role == "base" or continuous
        key = f"rf:{entry.id}" + (":infra" if infra and entry.role != "base" else "")
        tr = self.tracks.get(key)
        if tr is None:
            tr = Track(key, "rf", entry, entry.name if not (infra and entry.role != "base")
                       else f"Continuous carrier in {entry.name} band", f, t, t, integrity="energy")
            tr.continuous = infra
            self.tracks[key] = tr
        new_episode = t - tr.last_seen > (8 if entry.role == "mobile" else 30) or tr.count == 0
        ch = tr.channels.setdefault(round(f, 4), {"freq_mhz": round(f, 4), "count": 0, "peak": peak, "last_seen": t})
        ch["count"] += 1
        ch["last_seen"] = t
        ch["peak"] = max(peak, ch["peak"]) if t - ch.get("peak_t", 0) < 300 else peak
        ch["peak_t"] = t
        if new_episode:
            tr.count += 1
            tr.episode_start = t
            tr.tx_times.append(t)
        tr.last_seen, tr.freq_mhz, tr.rssi = t, f, peak
        tr.history.append((t, peak))
        tr.fields = {"channels_active": len([c for c in tr.channels.values() if t - c["last_seen"] < 60]),
                     "bandwidth_khz": int(round(abs(frame.freqs_mhz[idxs[-1]] - frame.freqs_mhz[idxs[0]]) * 1000
                                                + frame.rxbw_khz[top]))}
        if infra:
            if new_episode and tr.count == 1:
                self.emit("infrastructure", f"{tr.name} at {f:.4f} MHz ({peak:.0f} dBm)", tr)
            return
        prox = proximity(peak, entry.eirp_dbm, f, self.n)
        if new_episode and (entry.alert or t - tr.fields_t > 300):
            tr.fields_t = t
            self.emit("rf_activity", f"{entry.name} - {f:.4f} MHz, {peak:.0f} dBm{self._prox_txt(tr, peak)}", tr,
                      freq_mhz=round(f, 4), rssi=peak)
        if entry.alert and prox and prox["bucket"] in ("very_close", "nearby") and t - tr.last_alert > 300:
            tr.last_alert = t
            svc = f" [{entry.service}]" if entry.service else ""
            self.emit("alert", f"{entry.name}{svc}: {prox['label']} (~{prox['meters']} m, {peak:.0f} dBm at "
                               f"{f:.4f} MHz)", tr, level="alert", freq_mhz=round(f, 4), rssi=peak)

    # -- housekeeping ------------------------------------------------------
    def tick(self):
        """Mark periodic devices gone, expire stale tracks."""
        with self.lock:
            now = self.clock()
            for key, tr in list(self.tracks.items()):
                age = now - tr.last_seen
                # only devices that report on a schedule can be "gone"; doorbells and
                # door sensors legitimately stay silent for hours
                nominal = tr.entry.interval_s if tr.entry and tr.entry.interval_s else None
                if tr.kind == "device" and nominal and nominal < 1800 and not tr.gone:
                    duty = next((d for f, d in self.listen_duty.items() if abs(f - tr.freq_mhz) < 0.2), 1.0)
                    expected = max(nominal, tr.interval() or 0) / max(duty, 0.05)
                    if age > max(4 * expected, 300):
                        tr.gone = True
                        self.emit("device_gone", f"{tr.fields.get('model', tr.name)} ({self._ident(tr)}) "
                                                 f"not heard for {int(age)} s", tr)
                ttl = 24 * 3600 if tr.kind == "device" else 6 * 3600
                if age > ttl:
                    del self.tracks[key]
            self._bump()

    # -- presentation -------------------------------------------------------
    def _ident(self, tr: Track) -> str:
        f = tr.fields
        for k in ("serial", "id", "channel"):
            if k in f and k not in tr.sensitive_fields:
                return f"{k} {f[k]}"
        return tr.key.split(":")[-1]

    def _prox_txt(self, tr: Track, rssi: Optional[float]) -> str:
        if rssi is None or tr.entry is None:
            return ""
        p = proximity(rssi, tr.entry.eirp_dbm, tr.freq_mhz, self.n)
        return f" - {p['label']} (~{p['meters']} m)" if p else ""

    def _item(self, tr: Track, now: float) -> dict:
        e = tr.entry
        fields = dict(tr.fields)
        if not self.allow_sensitive:
            for k in tr.sensitive_fields:
                if k in fields:
                    fields[k] = "(redacted)"
        recent = [r for t, r in tr.history if now - t < 120]
        rssi = max(recent) if (tr.kind == "rf" and recent) else tr.rssi
        confidence = {"device": "decoded", "unknown": "structure", "rf": "energy"}[tr.kind]
        active_window = 15 if tr.kind == "rf" else max(60.0, 1.5 * (tr.interval() or 0))
        return {
            "key": tr.key, "kind": tr.kind, "name": tr.name,
            "category": e.category if e else "unknown",
            "category_label": CATEGORY_LABELS.get(e.category if e else "unknown", "Unidentified"),
            "entry_id": e.id if e else None, "role": e.role if e else "device",
            "meaning": e.meaning if e else "", "caveats": e.caveats if e else "",
            "service": e.service if e else "", "alert_class": bool(e and e.alert),
            "confidence": confidence, "integrity": tr.integrity,
            "freq_mhz": round(tr.freq_mhz, 4), "first_seen": tr.first_seen, "last_seen": tr.last_seen,
            "count": tr.count, "interval_s": round(tr.interval(), 1) if tr.interval() else None,
            "rssi": round(rssi, 1) if rssi is not None else None,
            "proximity": proximity(rssi, e.eirp_dbm, tr.freq_mhz, self.n) if (rssi is not None and e and not tr.continuous) else None,
            "active": now - tr.last_seen < active_window, "gone": tr.gone, "continuous": tr.continuous,
            "fields": fields,
            "channels": sorted(({k: v for k, v in c.items() if k != "peak_t"} for c in tr.channels.values()),
                               key=lambda c: -c["last_seen"])[:8],
            "history": [[round(t - now, 1), round(r, 1)] for t, r in list(tr.history)[-60:]],
        }

    def snapshot(self, include_spectrum: bool = True) -> dict:
        with self.lock:
            now = self.clock()
            items = [self._item(tr, now) for tr in self.tracks.values()]
            near = [i for i in items if not i["continuous"] and i["role"] != "base"]
            infra = [i for i in items if i["continuous"] or i["role"] == "base"]
            near.sort(key=lambda i: (not i["active"], -i["last_seen"]))
            infra.sort(key=lambda i: -i["last_seen"])
            snap = {
                "now": now, "uptime_s": int(now - self.started), "version": self.version,
                "status": dict(self.status), "stats": dict(self.stats),
                "near": near, "infrastructure": infra,
                "events": list(self.events)[-150:],
                "counts": {"devices": sum(1 for i in near if i["kind"] == "device"),
                           "active": sum(1 for i in near if i["active"]),
                           "alerts_1h": sum(1 for e in self.events if e["level"] == "alert" and now - e["t"] < 3600)},
            }
            if include_spectrum and self.spectrum:
                sp = self.spectrum
                snap["spectrum"] = {
                    "t": sp.t, "freqs": [round(f, 4) for f in sp.freqs_mhz],
                    "peak": [round(v, 1) for v in sp.peak_dbm], "avg": [round(v, 1) for v in sp.avg_dbm],
                    "floor": [round(self.floor.get(int(round(f * 1000)), v), 1) for f, v in zip(sp.freqs_mhz, sp.avg_dbm)],
                    "entries": [(self.energy_entry(f).id if self.energy_entry(f) else None) for f in sp.freqs_mhz],
                }
            return snap
