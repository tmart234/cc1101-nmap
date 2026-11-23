"""Signal generators for the simulator and tests.

Each function produces exactly what a CC1101 would hand us for a real
device: pulse timings for OOK protocols, or the bytes after the sync word
for FSK packet protocols. Real-device example packets in tests/ check the
decoders independently of these.
"""
from __future__ import annotations

import random
from typing import List, Optional

from . import bits as B


def _jitter(us: float, rng: Optional[random.Random], pct: float = 0.06) -> int:
    if rng is None:
        return int(us)
    return max(1, int(us * (1 + rng.uniform(-pct, pct))))


def pwm(bits: str, one: tuple, zero: tuple, rng=None) -> List[int]:
    out: List[int] = []
    for b in bits:
        m, g = one if b == "1" else zero
        out += [_jitter(m, rng), _jitter(g, rng)]
    return out


# --- OOK devices ---------------------------------------------------------

def acurite_tower(sensor_id: int, channel: str, temp_c: float, humidity: int,
                  battery_ok: bool = True, rng=None) -> List[int]:
    ch = {"A": 3, "B": 2, "C": 0}[channel]
    b = bytearray(7)
    b[0] = (ch << 6) | ((sensor_id >> 8) & 0x3F)
    b[1] = sensor_id & 0xFF
    b[2] = (0x40 if battery_ok else 0) | 0x04
    b[3] = humidity & 0x7F
    t = int(round((temp_c + 100) * 10))
    b[4] = (t >> 7) & 0x7F
    b[5] = t & 0x7F
    for i in (2, 3, 4, 5):                       # even parity in bit 7
        if B.parity8(b[i]):
            b[i] |= 0x80
    b[6] = B.add_bytes(b[:6])
    frame = [_jitter(620, rng), _jitter(596, rng)] * 4
    frame += pwm(B.bytes_to_bits(bytes(b)), (408, 204), (220, 392), rng)
    frame[-1] = 2192
    return frame * 3


def lacrosse_tx141th(sensor_id: int, channel: int, temp_c: float, humidity: int,
                     battery_low: bool = False, rng=None) -> List[int]:
    t = int(round(temp_c * 10 + 500))
    b = bytearray([sensor_id & 0xFF, (int(battery_low) << 7) | ((channel & 3) << 4) | ((t >> 8) & 0x0F),
                   t & 0xFF, humidity & 0xFF, 0])
    b[4] = B.lfsr_digest8_reflect(bytes(b[:4]), 0x31, 0xF4)
    one_packet = [_jitter(833, rng), _jitter(833, rng)] * 4
    one_packet += pwm(B.bytes_to_bits(bytes(b)), (417, 208), (208, 417), rng)
    return one_packet * 12 + [833, 833, 833, 2000]


def honeywell(device_id: int, channel: int = 8, contact_open: bool = False, heartbeat: bool = False,
              battery_low: bool = False, rng=None) -> List[int]:
    ev = (0x80 if contact_open else 0) | (0x04 if heartbeat else 0) | (0x08 if battery_low else 0)
    b = bytearray([(channel << 4) | ((device_id >> 16) & 0x0F), (device_id >> 8) & 0xFF,
                   device_id & 0xFF, ev])
    poly = 0x8050 if channel in (0x2, 0x4, 0x9, 0xA, 0xC) else 0x8005
    crc = B.crc16(bytes(b), poly, 0)
    b += bytes([crc >> 8, crc & 0xFF])
    data_bits = "1111111111111110" + B.bytes_to_bits(bytes(b))
    raw = "".join("01" if c == "1" else "10" for c in data_bits)
    # run-length encode the half-bit stream into mark/space durations
    pulses: List[int] = []
    level, run = raw[0], 0
    if level == "0":
        raw = "1" + raw          # start on a mark (one stray half-bit is harmless)
        level = "1"
    for c in raw:
        if c == level:
            run += 1
        else:
            pulses.append(_jitter(136 * run, rng))
            level, run = c, 1
    pulses.append(_jitter(136 * run, rng))
    if len(pulses) % 2:
        pulses.append(2000)
    else:
        pulses[-1] = 2000
    return pulses * 4


def ev1527(code24: int, t_us: int = 320, repeats: int = 6, rng=None) -> List[int]:
    bits = f"{code24 & 0xFFFFFF:024b}"
    frame = pwm(bits, (3 * t_us, t_us), (t_us, 3 * t_us), rng) + [_jitter(t_us, rng), 31 * t_us]
    return frame * repeats


# --- FSK packet devices (bytes after the sync word) -------------------------

def lacrosse_itplus(sensor_id: int, temp_c: float, humidity: Optional[int] = None,
                    weak_battery: bool = False) -> bytes:
    v = int(round((temp_c + 40) * 10))
    d0, d1, d2 = v // 100, (v // 10) % 10, v % 10
    hum = 106 if humidity is None else humidity
    b = bytes([0x90 | ((sensor_id >> 2) & 0x0F), ((sensor_id & 0x3) << 6) | d0,
               (d1 << 4) | d2, (int(weak_battery) << 7) | hum])
    return b + bytes([B.crc8(b, 0x31)])


def fineoffset_wh65(sensor_id: int, temp_c: float, humidity: int, wind_dir: int = 180,
                    wind_m_s: float = 1.0, gust_m_s: float = 2.0, rain_tips: int = 0) -> bytes:
    t = int(round(temp_c * 10 + 400))
    w = int(round(wind_m_s / 0.51 / 0.125))
    b = bytearray(17)
    b[0], b[1] = 0x24, sensor_id & 0xFF
    b[2] = wind_dir & 0xFF
    b[3] = ((wind_dir >> 1) & 0x80) | ((w >> 4) & 0x10) | ((t >> 8) & 0x07)
    b[4], b[5], b[6] = t & 0xFF, humidity, w & 0xFF
    b[7] = int(round(gust_m_s / 0.51)) & 0xFF
    b[8], b[9] = (rain_tips >> 8) & 0xFF, rain_tips & 0xFF
    b[10:12] = b"\x00\x10"
    b[12:15] = (12000).to_bytes(3, "big")
    b[15] = B.crc8(bytes(b[:15]), 0x31)
    b[16] = B.add_bytes(b[:16])
    return bytes(b)


def ambient_wh31e(sensor_id: int, channel: int, temp_c: float, humidity: int) -> bytes:
    t = int(round(temp_c * 10 + 400))
    b = bytearray([0x30, sensor_id & 0xFF, 0x80 | (((channel - 1) & 7) << 4) | ((t >> 8) & 0x03),
                   t & 0xFF, humidity])
    b.append(B.crc8(bytes(b), 0x31))
    b.append(B.add_bytes(b))
    return bytes(b) + b"\x00\x00\x00\x00"


def _wmbus_block(data: bytes) -> bytes:
    crc = (~B.crc16(data, 0x3D65, 0)) & 0xFFFF
    return data + bytes([crc >> 8, crc & 0xFF])


def wmbus_block1(manufacturer: str, serial: str, version: int, dev_type: int,
                 c_field: int = 0x44, length: int = 0x2E) -> bytes:
    m = ((ord(manufacturer[0]) - 64) << 10) | ((ord(manufacturer[1]) - 64) << 5) | (ord(manufacturer[2]) - 64)
    ser = bytes.fromhex(serial)[::-1]           # BCD, little-endian on air
    return _wmbus_block(bytes([length, c_field, m & 0xFF, m >> 8]) + ser + bytes([version, dev_type]))


_3OF6_ENC = {v: k for k, v in {0x16: 0x0, 0x0D: 0x1, 0x0E: 0x2, 0x0B: 0x3, 0x1C: 0x4, 0x19: 0x5,
                               0x1A: 0x6, 0x13: 0x7, 0x2C: 0x8, 0x25: 0x9, 0x26: 0xA, 0x23: 0xB,
                               0x34: 0xC, 0x31: 0xD, 0x32: 0xE, 0x29: 0xF}.items()}


def wmbus_t1(manufacturer: str, serial: str, version: int, dev_type: int) -> bytes:
    """Mode T1 telegram start (after the 0x543D sync), 3-of-6 encoded."""
    frame = wmbus_block1(manufacturer, serial, version, dev_type) + _wmbus_block(bytes(range(0x7A, 0x8A)))
    bitstr = "".join(f"{_3OF6_ENC[b >> 4]:06b}{_3OF6_ENC[b & 0xF]:06b}" for b in frame)
    bitstr += "0" * (-len(bitstr) % 8)
    return B.bits_to_bytes(bitstr)


def wmbus_c1a(manufacturer: str, serial: str, version: int, dev_type: int) -> bytes:
    return b"\x54\xcd" + wmbus_block1(manufacturer, serial, version, dev_type) + bytes(20)
