"""The emitter catalog: what real transmitters live where, and what seeing
one actually means.

Built-in knowledge lives in catalog.json. Users add their own area's
frequencies (police/fire dispatch, county trunked system, etc.) from a CSV,
which always wins over the generic band entries.
"""
from __future__ import annotations

import csv
import json
import logging
import os
from dataclasses import asdict, dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

log = logging.getLogger(__name__)

# CC1101 datasheet bands, and the wider range the PLL actually locks over
# (used e.g. by Flipper Zero's "extended range"). Sensitivity is lower there.
CC1101_BANDS: Tuple[Tuple[float, float], ...] = ((300.0, 348.0), (387.0, 464.0), (779.0, 928.0))
CC1101_EXTENDED: Tuple[Tuple[float, float], ...] = ((281.0, 361.0), (378.0, 481.0), (749.0, 962.0))

CATEGORY_LABELS = {
    "public_safety": "Public safety", "government": "Government", "two_way_radio": "Two-way radio",
    "transport": "Transport", "cellular": "Cellular", "paging": "Paging", "weather": "Weather",
    "home_security": "Home security", "home_iot": "Smart home", "remote_control": "Remotes & openers",
    "vehicle": "Vehicles", "utility": "Utility meters", "iot": "IoT / ISM", "medical": "Medical",
    "science": "Science", "amateur": "Amateur radio", "local": "Your local list", "unknown": "Unidentified",
}

DEFAULT_PATH = os.path.join(os.path.dirname(__file__), "catalog.json")


@dataclass
class Entry:
    id: str
    name: str
    category: str
    ranges_mhz: List[Tuple[float, float]]
    detect: str = "energy"            # decode | pulses | energy
    role: str = "device"              # mobile | device | base
    regions: List[str] = field(default_factory=lambda: ["US", "EU"])
    eirp_dbm: float = 10.0
    alert: bool = False
    meaning: str = ""
    caveats: str = ""
    sensitive: bool = False
    extended: bool = False
    hopping: bool = False
    interval_s: Optional[float] = None
    sweep: Optional[dict] = None
    service: str = ""                 # police | fire | ems | ... (local list)
    source: str = "builtin"

    def contains(self, f: float) -> bool:
        return any(lo <= f <= hi for lo, hi in self.ranges_mhz)

    def width_at(self, f: float) -> float:
        return min((hi - lo for lo, hi in self.ranges_mhz if lo <= f <= hi), default=1e9)

    def to_json(self) -> dict:
        d = asdict(self)
        d["category_label"] = CATEGORY_LABELS.get(self.category, self.category)
        return d


@dataclass
class Segment:
    start_mhz: float
    stop_mhz: float
    step_khz: float
    rxbw_khz: float
    entry_id: str

    @property
    def points(self) -> int:
        if not self.step_khz:
            return 1
        return int((self.stop_mhz - self.start_mhz) * 1000 / self.step_khz + 1e-6) + 1

    def freqs(self) -> List[float]:
        return [round(self.start_mhz + i * self.step_khz / 1000, 5) for i in range(self.points)]


def tunable(f: float, extended: bool = False) -> bool:
    bands = CC1101_EXTENDED if extended else CC1101_BANDS
    return any(lo <= f <= hi for lo, hi in bands)


def clip_to_tunable(lo: float, hi: float, extended: bool) -> List[Tuple[float, float]]:
    out = []
    for blo, bhi in (CC1101_EXTENDED if extended else CC1101_BANDS):
        a, b = max(lo, blo), min(hi, bhi)
        if a <= b:
            out.append((a, b))
    return out


class Catalog:
    def __init__(self, entries: Sequence[Entry], rx_profiles: Sequence[dict], region: str = "US",
                 allow_sensitive: bool = False, extended: bool = False):
        self.region = region.upper()
        self.allow_sensitive = allow_sensitive
        self.extended = extended
        self.all_entries = list(entries)
        self.entries = [e for e in entries if self._active(e)]
        self._by_id: Dict[str, Entry] = {e.id: e for e in entries}
        self.rx_profiles = [p for p in rx_profiles
                            if (self.allow_sensitive or not p.get("sensitive"))
                            and self.region in p.get("regions", [self.region])
                            and tunable(p["freq_mhz"], extended)]

    def _active(self, e: Entry) -> bool:
        if e.sensitive and not self.allow_sensitive:
            return False
        if e.source == "builtin" and self.region not in e.regions:
            return False
        return any(clip_to_tunable(lo, hi, self.extended) for lo, hi in e.ranges_mhz)

    @classmethod
    def load(cls, path: Optional[str] = None, region: str = "US", allow_sensitive: bool = False,
             extended: bool = False, local_freqs: Optional[str] = None) -> "Catalog":
        with open(path or DEFAULT_PATH) as fh:
            raw = json.load(fh)
        entries = []
        for e in raw["entries"]:
            e = dict(e)
            e["ranges_mhz"] = [tuple(r) for r in e["ranges_mhz"]]
            entries.append(Entry(**e))
        if local_freqs:
            entries = load_local_freqs(local_freqs) + entries
        return cls(entries, raw.get("rx_profiles", []), region, allow_sensitive, extended)

    def get(self, entry_id: str) -> Optional[Entry]:
        return self._by_id.get(entry_id)

    def match(self, f: float, detect: Optional[Iterable[str]] = None) -> List[Entry]:
        """All active entries covering f, most specific first (local list wins)."""
        wanted = set(detect) if detect else None
        hits = [e for e in self.entries if e.contains(f) and (wanted is None or e.detect in wanted)]
        hits.sort(key=lambda e: (e.source != "local", e.width_at(f)))
        return hits

    def best(self, f: float, detect: Optional[Iterable[str]] = None) -> Optional[Entry]:
        hits = self.match(f, detect)
        return hits[0] if hits else None

    def sweep_plan(self, max_points: int = 600) -> List[Segment]:
        """Frequencies for the RSSI sweep, most valuable first, capped at max_points."""
        def rank(e: Entry) -> int:
            if e.source == "local":
                return 0
            if e.alert:
                return 1
            if e.sensitive:
                return 2
            return {"mobile": 3, "device": 4, "base": 5}.get(e.role, 6)

        segs: List[Tuple[int, Segment]] = []
        for e in self.entries:
            if e.detect != "energy" and e.source != "local":
                continue
            if e.source == "local":
                for lo, hi in e.ranges_mhz:
                    mid = round((lo + hi) / 2, 5)
                    if tunable(mid, self.extended):
                        segs.append((0, Segment(mid, mid, 0, 58, e.id)))
                continue
            if not e.sweep:
                continue
            for lo, hi in e.ranges_mhz:
                for a, b in clip_to_tunable(lo, hi, self.extended):
                    step = e.sweep["step_khz"]
                    a = round(a + step / 2000, 4) if b - a > step / 1000 else round((a + b) / 2, 4)
                    segs.append((rank(e), Segment(a, round(b, 4), step, e.sweep["rxbw_khz"], e.id)))
        segs = self._dedupe(segs)
        segs.sort(key=lambda s: s[0])
        plan, total = [], 0
        for _, s in segs:
            if total + s.points > max_points:
                log.warning("Sweep plan full (%d points); skipping %s %.3f-%.3f MHz",
                            max_points, s.entry_id, s.start_mhz, s.stop_mhz)
                continue
            plan.append(s)
            total += s.points
        return plan

    @staticmethod
    def _dedupe(segs: List[Tuple[int, Segment]]) -> List[Tuple[int, Segment]]:
        """Drop points of wide generic sweeps that a finer sweep already covers."""
        fine = sorted(segs, key=lambda s: (s[1].step_khz, s[1].stop_mhz - s[1].start_mhz))
        kept: List[Tuple[int, Segment]] = []
        for rank, seg in fine:
            covered = [(k.start_mhz - k.step_khz / 2000 - 1e-6, k.stop_mhz + max(k.step_khz, k.rxbw_khz) / 2000 + 1e-6)
                       for _, k in kept if k.step_khz <= seg.step_khz]
            if not covered or not seg.step_khz:
                kept.append((rank, seg))
                continue
            run: List[float] = []
            for f in seg.freqs() + [None]:
                if f is not None and not any(a <= f <= b for a, b in covered):
                    run.append(f)
                    continue
                if run:
                    kept.append((rank, Segment(run[0], run[-1], seg.step_khz if len(run) > 1 else 0,
                                               seg.rxbw_khz, seg.entry_id)))
                    run = []
        return kept

    def profiles(self, firmware: str) -> List[dict]:
        return [p for p in self.rx_profiles if p.get("fw", "any") in ("any", firmware)]

    def to_json(self) -> dict:
        return {
            "region": self.region, "extended_range": self.extended, "allow_sensitive": self.allow_sensitive,
            "bands": [list(b) for b in (CC1101_EXTENDED if self.extended else CC1101_BANDS)],
            "entries": [e.to_json() for e in self.entries],
            "categories": CATEGORY_LABELS,
        }


# --------------------------------------------------------------------------
# Local frequency lists
# --------------------------------------------------------------------------

_SERVICE_WORDS = (("police", ("law", "police", "sheriff", "pd", "trooper", "patrol")),
                  ("fire", ("fire", "fd", "rescue")),
                  ("ems", ("ems", "ambulance", "medic", "hospital")),
                  ("federal", ("federal", "fbi", "dhs", "marshal")))


def _service(text: str) -> str:
    t = text.lower()
    words = set(t.replace("/", " ").replace("-", " ").replace("(", " ").replace(")", " ").split())
    found = [svc for svc, keys in _SERVICE_WORDS if any(k in words or (len(k) > 3 and k in t) for k in keys)]
    return "/".join(found)


def _pick(row: Dict[str, str], *names: str) -> str:
    for n in names:
        for k, v in row.items():
            if k and k.strip().lower() == n and v and v.strip():
                return v.strip()
    return ""


def _freq(text: str) -> Optional[float]:
    try:
        f = float(text.replace("MHz", "").strip())
    except ValueError:
        return None
    return f / 1e6 if f > 1e5 else f


def derived_input(f_out: float, repeater: bool = True) -> Optional[float]:
    """Mobile-transmit frequency paired with a base/repeater output (US band plans).

    700/800 MHz are always base/mobile pairs. UHF can be simplex, so the
    standard +5 MHz repeater offset is only applied when the row says it's a
    repeater output.
    """
    if 851.0 <= f_out <= 869.0:       # 800 MHz: mobiles transmit 45 MHz lower
        return round(f_out - 45.0, 5)
    if 769.0 <= f_out <= 775.0:       # 700 MHz narrowband: 30 MHz higher
        return round(f_out + 30.0, 5)
    if repeater and (450.0 <= f_out < 455.0 or 460.0 <= f_out < 465.0):
        return round(f_out + 5.0, 5)  # standard UHF repeater offset
    return None


def load_local_freqs(path: str) -> List[Entry]:
    """Read a CSV of local frequencies.

    Simple format (header required):   freq_mhz,label,category,alert
    RadioReference-style exports are also understood (Frequency / Input /
    Alpha Tag / Description / Tag columns). For a repeater/trunked output
    without an input column, the mobile-transmit frequency is derived from
    the standard band plan, because that's the side that tells you a radio is
    close by.
    """
    entries: List[Entry] = []
    with open(path, newline="") as fh:
        for i, row in enumerate(csv.DictReader(fh)):
            f_out = _freq(_pick(row, "freq_mhz", "frequency", "frequency output", "output", "freq"))
            if f_out is None:
                continue
            f_in = _freq(_pick(row, "input", "frequency input", "input_mhz"))
            label = _pick(row, "label", "alpha tag", "name", "description") or f"{f_out:.4f} MHz"
            desc = _pick(row, "description", "notes")
            tag = _pick(row, "category", "tag", "service")
            service = _service(" ".join((label, desc, tag)))
            alert_txt = _pick(row, "alert").lower()
            alert = alert_txt in ("1", "yes", "true", "y") if alert_txt else bool(service)
            category = "government" if service == "federal" else "public_safety" if service else "local"
            base = dict(category=category, detect="energy", alert=alert, regions=["US", "EU"],
                        service=service, source="local", eirp_dbm=37,
                        caveats="From your local frequency list.")
            text = " ".join((label, desc, tag)).lower()
            derived = f_in is None and derived_input(f_out, any(w in text for w in ("repeater", "rptr", "output")))
            if f_in is None and derived:
                f_in = derived
            if f_in:
                entries.append(Entry(id=f"local-{i}-in", name=f"{label} (radio transmitting)",
                                     ranges_mhz=[(f_in - 0.00625, f_in + 0.00625)], role="mobile",
                                     meaning=f"A radio is transmitting on the input of {label}"
                                             f"{' (derived from band plan)' if derived else ''}. "
                                             "Signal strength reflects how close that radio is.",
                                     **base))
            entries.append(Entry(id=f"local-{i}", name=label,
                                 ranges_mhz=[(f_out - 0.00625, f_out + 0.00625)],
                                 role="base" if f_in else "mobile",
                                 meaning=(desc or label) + (" - repeater/dispatch output; activity here means the "
                                                            "channel is in use, not necessarily nearby." if f_in else ""),
                                 **{**base, "alert": alert and not f_in}))
    log.info("Loaded %d local frequency entries from %s", len(entries), path)
    return entries
