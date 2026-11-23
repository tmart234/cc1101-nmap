"""Turning raw edge timings into bit rows.

The CC1101 in asynchronous mode outputs the demodulated signal on a GDO pin;
firmware timestamps the edges. These helpers implement the same pulse
"slicers" rtl_433 uses (PWM and PCM), plus a structural summary used to tell
real signals from receiver noise.
"""
from __future__ import annotations

import re
from bisect import bisect_left, bisect_right
from dataclasses import dataclass
from statistics import median
from typing import Iterator, List, Optional, Sequence, Tuple

# The stock Evil Crow RF V2 firmware appends every capture to /logs.txt as
#   Count=<n>\n<d0>,<d1>,...,\n
# followed by its own "Rawdata corrected:" re-quantised copy, which we skip.
_STOCK_RAW = re.compile(r"(?<!Rawdata corrected:\n)Count=(\d+)\n([0-9,]+)")


def parse_stock_log(text: str) -> List[List[int]]:
    """Extract raw pulse lists from the stock firmware's /logs.txt."""
    text = text.replace("\r\n", "\n")
    out = []
    for m in _STOCK_RAW.finditer(text):
        vals = [int(v) for v in m.group(2).split(",") if v.strip().isdigit()]
        # sample[0] is the silence (>100 ms) that preceded the burst
        while vals and vals[0] > 50_000:
            vals.pop(0)
        if len(vals) >= 16:
            out.append(vals)
    return out


def polarities(pulses: Sequence[int]) -> Iterator[List[int]]:
    """Yield the pulse list as recorded and shifted by one edge.

    Edge-capture firmware can lose an edge to a noise glitch, which swaps
    mark/space for the rest of the capture. Decoders try both alignments and
    let checksums pick the right one.
    """
    yield list(pulses)
    if len(pulses) > 1:
        yield list(pulses[1:])


def slice_pwm(pulses: Sequence[int], short: float, long: float, sync: Optional[float] = None,
              gap_limit: float = 0, reset_limit: float = 10_000) -> List[str]:
    """Pulse-width slicer. Long mark -> '1', short mark -> '0'.

    A mark wider than the sync threshold, or a gap beyond gap_limit/reset_limit,
    ends the current row.
    """
    thr = (short + long) / 2
    sync_thr = (long + sync) / 2 if sync else long * 1.8
    noise = short * 0.35
    rows: List[str] = []
    cur: List[str] = []
    for i in range(0, len(pulses), 2):
        mark = pulses[i]
        gap = pulses[i + 1] if i + 1 < len(pulses) else reset_limit + 1
        if mark < noise:
            continue
        if mark >= sync_thr:
            if cur:
                rows.append("".join(cur))
                cur = []
        else:
            cur.append("1" if mark > thr else "0")
        if gap > reset_limit or (gap_limit and gap > gap_limit):
            if cur:
                rows.append("".join(cur))
                cur = []
    if cur:
        rows.append("".join(cur))
    return rows


def refine_unit(pulses: Sequence[int], nominal: float, lo: float = 0.6, hi: float = 1.45) -> float:
    """Re-estimate a symbol width from durations close to the nominal one."""
    near = [p for p in pulses if lo * nominal <= p <= hi * nominal]
    return float(median(near)) if len(near) >= 8 else float(nominal)


def slice_pcm(pulses: Sequence[int], bit_us: float, reset_limit: float) -> List[str]:
    """NRZ slicer: each duration becomes round(d / bit_us) copies of its level."""
    rows: List[str] = []
    cur: List[str] = []
    for i, d in enumerate(pulses):
        is_mark = (i % 2 == 0)
        if not is_mark and d > reset_limit:
            if cur:
                # the final half-symbol may be a space merged into the reset gap
                cur.append("00")
                rows.append("".join(cur))
                cur = []
            continue
        n = int(d / bit_us + 0.5)
        if n <= 0:
            continue
        cur.append(("1" if is_mark else "0") * min(n, 64))
    if cur:
        rows.append("".join(cur))
    return rows


@dataclass
class PulseSummary:
    marks: int
    mark_clusters: List[Tuple[int, int]]   # (width_us, count), most common first
    gap_clusters: List[Tuple[int, int]]
    structured: bool
    modulation_guess: str
    fingerprint: str


def _cluster(values: Sequence[int], tol: float = 0.2, max_clusters: int = 6) -> List[Tuple[int, int]]:
    """Greedy density clustering: repeatedly take the +/-tol window holding
    the most values. Unlike chaining, a smear of noise can't merge into one
    big cluster."""
    remaining = sorted(values)
    clusters: List[Tuple[int, int]] = []
    while remaining and len(clusters) < max_clusters:
        best_lo = best_hi = 0
        for i, v in enumerate(remaining):
            lo = bisect_left(remaining, v / (1 + tol))
            hi = bisect_right(remaining, v * (1 + tol))
            if hi - lo > best_hi - best_lo:
                best_lo, best_hi = lo, hi
        members = remaining[best_lo:best_hi]
        clusters.append((int(median(members)), len(members)))
        remaining = remaining[:best_lo] + remaining[best_hi:]
    return clusters


def summarize(pulses: Sequence[int], reset_limit: int = 10_000) -> PulseSummary:
    """Describe the timing structure of a capture.

    Real transmitters use two or three distinct mark/space widths with tight
    spread; receiver noise produces a smear of unrelated widths. "structured"
    is the test for "a real device sent this".
    """
    marks = [p for p in pulses[0::2] if p < reset_limit]
    gaps = [p for p in pulses[1::2] if p < reset_limit]
    mc = _cluster(marks) if marks else []
    gc = _cluster(gaps) if gaps else []

    def coverage(clusters, total, k=3):
        return sum(c for _, c in clusters[:k]) / total if total else 0.0

    structured = (len(marks) >= 16 and coverage(mc, len(marks)) >= 0.85
                  and coverage(gc, len(gaps)) >= 0.80)
    guess = "unknown"
    if structured:
        top_m = sorted(w for w, _ in mc[:2])
        top_g = sorted(w for w, _ in gc[:2])
        if len(top_m) == 2 and 1.6 <= top_m[1] / max(top_m[0], 1) <= 4.5:
            guess = "PWM"
        elif len(top_g) == 2 and 1.6 <= top_g[1] / max(top_g[0], 1) <= 4.5 and \
                (len(mc) == 1 or mc[0][1] > 0.8 * len(marks)):
            guess = "PPM"
        else:
            guess = "PCM/Manchester"
    base = min((w for w, c in mc[:3]), default=0)
    fp = f"{guess}:{_q(base)}:{len(marks) // 8 * 8}"
    return PulseSummary(len(marks), mc[:4], gc[:4], structured, guess, fp)


def _q(us: float) -> int:
    """Quantise a width so captures of the same device share a fingerprint."""
    if us <= 0:
        return 0
    step = 25 if us < 400 else 50 if us < 1000 else 100
    return int(round(us / step) * step)
