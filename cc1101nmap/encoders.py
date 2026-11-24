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


def megacode(facility: int, serial: int, button: int = 1, t_us: int = 1000, repeats: int = 4,
             rng=None) -> List[int]:
    """Linear MegaCode 24-bit fixed-code OOK frame (318 MHz)."""
    code = (1 << 23) | ((facility & 0xF) << 19) | ((serial & 0xFFFF) << 3) | (button & 0x7)
    bits = f"{code:024b}"
    frame: List[int] = []
    for i, b in enumerate(bits):
        frame.append(_jitter(t_us, rng))
        if i + 1 == len(bits):
            guard = 11 if b == "1" else 14
            frame.append(_jitter(guard * t_us, rng))
        else:
            nxt = bits[i + 1]
            if b == "1":
                gap_t = 5 if nxt == "1" else 2
            else:
                gap_t = 8 if nxt == "1" else 5
            frame.append(_jitter(gap_t * t_us, rng))
    return frame * repeats


def schrader_tpms(sensor_id: int, pressure_kpa: float, temp_c: int, flags: int = 0x67,
                  rng=None) -> List[int]:
    """Schrader TPMS GG4 68-bit OOK Manchester frame (315 / 433.92 MHz)."""
    b = bytearray(8)
    b[0] = 0xF0 | ((flags >> 4) & 0x0F)
    b[1] = ((flags & 0x0F) << 4) | ((sensor_id >> 24) & 0x0F)
    b[2] = (sensor_id >> 16) & 0xFF
    b[3] = (sensor_id >> 8) & 0xFF
    b[4] = sensor_id & 0xFF
    b[5] = int(round(pressure_kpa / 2.5)) & 0xFF
    b[6] = (temp_c + 50) & 0xFF
    b[7] = B.crc8(bytes(b[:7]), 0x07, 0xF0)
    data_bits = "0111" + B.bytes_to_bits(bytes(b))
    raw = "".join("01" if c == "1" else "10" for c in data_bits)
    if raw[0] == "0":
        raw = "1" + raw
    pulses: List[int] = []
    level, run = raw[0], 0
    for c in raw:
        if c == level:
            run += 1
        else:
            pulses.append(_jitter(120 * run, rng))
            level, run = c, 1
    pulses.append(_jitter(120 * run, rng))
    if len(pulses) % 2:
        pulses.append(2000)
    else:
        pulses[-1] = 2000
    return pulses * 3


# --- FSK / packet devices (bytes after the sync word) -----------------------

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


_MINIMED_4B6B_ENC = {
    0x0: 0b010101, 0x1: 0b110001, 0x2: 0b110010, 0x3: 0b100011,
    0x4: 0b110100, 0x5: 0b100101, 0x6: 0b100110, 0x7: 0b010110,
    0x8: 0b011010, 0x9: 0b011001, 0xA: 0b101010, 0xB: 0b001011,
    0xC: 0b101100, 0xD: 0b001101, 0xE: 0b001110, 0xF: 0b011100,
}


def minimed(packet_type: int, serial_hex: str, payload: bytes = b"\x00\x00", pad_len: int = 0) -> bytes:
    """Medtronic MiniMed 4b6b-encoded packet (after the 0xFF00 sync)."""
    body = bytes([packet_type]) + bytes.fromhex(serial_hex) + payload
    if packet_type in (0xA8, 0xAA, 0xAB):
        crc = B.crc16(body, 0x1021, 0xFFFF)
        frame = body + bytes([crc >> 8, crc & 0xFF])
    else:
        frame = body + bytes([B.crc8(body, 0x9B, 0x00)])
    bitstr = "".join(f"{_MINIMED_4B6B_ENC[b >> 4]:06b}{_MINIMED_4B6B_ENC[b & 0xF]:06b}" for b in frame)
    bitstr += "0" * (-len(bitstr) % 8)
    out = B.bits_to_bytes(bitstr)
    return out + bytes(max(0, pad_len - len(out)))


def omnipod(pod_address_hex: str, pkt_type: str = "POD", seq: int = 1,
            body: bytes = b"\x1d\x18\x02\xad\xa8\x00\x00\x2b\xe7\xff", pad_len: int = 40) -> bytes:
    """Insulet Omnipod Eros packet (after 0x54C3 sync, Manchester-decoded bytes)."""
    code = {"PDM": 0b101, "POD": 0b111, "ACK": 0b010}[pkt_type.upper()]
    addr = bytes.fromhex(pod_address_hex)
    hdr = addr + bytes([(code << 5) | (seq & 0x1F)]) + addr
    if code == 0b010:
        frame = hdr
    else:
        msg_crc = B.crc16(bytes([0x24, len(body)]) + body, 0x1021, 0)
        seg = (body + bytes([msg_crc >> 8, msg_crc & 0xFF]))[:25]
        frame = hdr + bytes([0x24, len(body)]) + seg
    out = frame + bytes([B.crc8(frame, 0x07, 0x00)])
    return out + bytes(max(0, pad_len - len(out)))
