"""Observation types produced by radio backends and consumed by the engine.

Three kinds of observation cover everything a CC1101 can tell us:

* PulseCapture - demodulated edge timings from the CC1101's asynchronous
  serial output (what the stock Evil Crow firmware records). Decoded in
  software, rtl_433 style.
* Packet - bytes received by the CC1101's packet engine after a hardware
  sync-word match (companion firmware only). Ideal for FSK protocols.
* SpectrumFrame - RSSI per frequency from a sweep (companion firmware only).
  Lets us notice transmitters we cannot demodulate (P25/TETRA/LTE/LoRa...).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class PulseCapture:
    pulses: List[int]            # alternating mark/space durations in microseconds, pulses[0] is a mark
    freq_mhz: float
    modulation: str = "OOK"      # "OOK" or "FSK"
    t: float = field(default_factory=time.time)
    rssi: Optional[float] = None
    source: str = ""


@dataclass
class Packet:
    data: bytes                  # bytes following the sync word
    freq_mhz: float
    sync: str                    # sync word as lowercase hex, e.g. "2dd4"
    t: float = field(default_factory=time.time)
    rssi: Optional[float] = None
    lqi: Optional[int] = None
    source: str = ""


@dataclass
class SpectrumFrame:
    freqs_mhz: List[float]
    peak_dbm: List[float]        # peak-hold since the previous frame
    avg_dbm: List[float]         # mean since the previous frame
    rxbw_khz: List[float]
    sweeps: int = 1              # number of sweeps aggregated into this frame
    t: float = field(default_factory=time.time)
    source: str = ""
