"""Protocol decoders for real, documented sub-GHz devices.

Every decoder here validates an integrity check (CRC, checksum, parity, or
for chips that have none, identical repeated frames plus a strict timing
check). Nothing is reported as a specific device unless it passes. Signals
that don't decode are handled by the engine as "unidentified" with band
information only - no guessing.

Packet layouts follow the public protocol documentation collected by the
rtl_433 project (https://github.com/merbanan/rtl_433) and EN 13757-4 for
wireless M-Bus. Implementations here are independent.
"""
from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from . import bits as B
from .obs import Packet, PulseCapture
from .pulses import polarities, refine_unit, slice_pcm, slice_pwm


@dataclass
class Decoded:
    model: str                      # e.g. "Acurite-Tower"
    catalog_id: str                 # catalog entry describing what this device is
    device_key: str                 # stable identity used for tracking
    fields: Dict[str, object] = field(default_factory=dict)
    integrity: str = "crc"          # crc | checksum | parity+checksum | repeat
    sensitive_fields: tuple = ()    # redacted unless --allow-sensitive


def _short_hash(text: str) -> str:
    return hashlib.sha1(text.encode()).hexdigest()[:8]


# --------------------------------------------------------------------------
# OOK pulse decoders
# --------------------------------------------------------------------------

class PulseDecoder:
    name = "base"
    modulation = "OOK"

    def decode(self, cap: PulseCapture) -> List[Decoded]:
        raise NotImplementedError


class EV1527Decoder(PulseDecoder):
    """EV1527 / PT2262-family fixed-code encoders (cheap 315/433 MHz remotes,
    doorbells, PIR and door sensors, remote outlets, gate openers).

    Frame: 24 data bits then a sync (1T mark + 31T space). '0' = 1T mark + 3T
    space, '1' = 3T mark + 1T space. T is set by a resistor (~150-700 us).
    There is no checksum, so we require >= 2 identical frames and check that
    every bit's space is the complement of its mark.
    """
    name = "ev1527"

    def decode(self, cap: PulseCapture) -> List[Decoded]:
        best: Optional[Decoded] = None
        for p in polarities(cap.pulses):
            d = self._decode(p, cap.freq_mhz)
            if d and (best is None or d.fields["repeats"] > best.fields["repeats"]):
                best = d
        return [best] if best else []

    def _decode(self, p: List[int], freq_mhz: Optional[float]) -> Optional[Decoded]:
        marks = sorted(p[0::2])
        if len(marks) < 48:
            return None
        short = marks[len(marks) // 5]
        long_ = marks[(len(marks) * 4) // 5]
        if not (100 <= short <= 900) or not (2.0 <= long_ / short <= 4.5):
            return None
        thr = (short + long_) / 2
        split = short * 8
        codes: Counter = Counter()
        row: List[str] = []
        ok = True
        for i in range(0, len(p), 2):
            mark = p[i]
            gap = p[i + 1] if i + 1 < len(p) else split + 1
            bit = "1" if mark > thr else "0"
            if gap > split:                      # sync gap: end of frame
                if ok and len(row) == 24 and bit == "0":
                    codes["".join(row)] += 1
                row, ok = [], True
                continue
            if mark > long_ * 1.6 or mark < short * 0.4:
                ok = False
            # complement check: a long mark needs a short space and vice versa
            if (bit == "1") == (gap > thr):
                ok = False
            row.append(bit)
        if not codes:
            return None
        code_bits, repeats = codes.most_common(1)[0]
        if repeats < 2:
            return None
        code = int(code_bits, 2)
        if code in (0, 0xFFFFFF):
            return None
        tristate = "".join({"00": "0", "11": "1", "01": "F", "10": "X"}[code_bits[i:i + 2]]
                           for i in range(0, 24, 2))
        chip = "PT2262" if "X" not in tristate else "EV1527"
        return Decoded(
            model="Fixed-code (EV1527/PT2262)",
            catalog_id="fixed-code-remote",
            device_key=f"fixedcode:{cap_freq_band(freq_mhz)}:{_short_hash(code_bits)}",
            fields={
                "chip_guess": chip,
                "button_bits": f"{code & 0xF:04b}",
                "repeats": repeats,
                "symbol_us": int(short),
                "code": f"{code:06X}",
                "tristate": tristate,
            },
            integrity="repeat",
            sensitive_fields=("code", "tristate"),
        )


def cap_freq_band(freq: Optional[float]) -> str:
    return "any" if freq is None else f"{freq:.0f}"


class AcuriteTowerDecoder(PulseDecoder):
    """Acurite 592TXR / 06002RM / 6044M tower temperature-humidity sensor.

    433.92 MHz OOK PWM: short 220 us, long 408 us, sync 620 us. 7 bytes:
    CCII IIII | IIII IIII | pB00 0100 | pHHH HHHH | p??T TTTT | pTTT TTTT | sum
    """
    name = "acurite_tower"

    def decode(self, cap: PulseCapture) -> List[Decoded]:
        out: Dict[str, Decoded] = {}
        for p in polarities(cap.pulses):
            for row in slice_pwm(p, 220, 408, sync=620, gap_limit=500, reset_limit=4000):
                if not 56 <= len(row) <= 63:
                    continue
                d = self._check(B.bits_to_bytes(row, 0, 7))
                if d:
                    out[d.device_key] = d
        return list(out.values())

    @staticmethod
    def _check(b: bytes) -> Optional[Decoded]:
        if len(b) < 7 or b[2] & 0x3F != 0x04:
            return None
        if B.add_bytes(b[:6]) != b[6] or B.parity_bytes(b[2:6]):
            return None
        channel = {0: "C", 2: "B", 3: "A"}.get(b[0] >> 6)
        if channel is None:
            return None
        sensor_id = ((b[0] & 0x3F) << 8) | b[1]
        humidity = b[3] & 0x7F
        temp_c = round((((b[4] & 0x7F) << 7) | (b[5] & 0x7F)) * 0.1 - 100, 1)
        if not -40 <= temp_c <= 70 or (humidity > 100 and humidity != 127):
            return None
        fields = {"id": sensor_id, "channel": channel, "battery_ok": bool(b[2] & 0x40),
                  "temperature_C": temp_c}
        if humidity != 127:
            fields["humidity_pct"] = humidity
        return Decoded("Acurite-Tower", "acurite-tower", f"acurite-tower:{sensor_id}:{channel}",
                       fields, integrity="parity+checksum")


class LaCrosseTX141THDecoder(PulseDecoder):
    """LaCrosse TX141TH-Bv2 / TFA 30.3221.02 temperature-humidity sensor.

    433.92 MHz OOK PWM, 625 us bit period (1 = 417/208 us, 0 = 208/417 us),
    40 bits: id(8) flags(4) temp(12, C*10+500) humidity(8) LFSR digest(8).
    """
    name = "lacrosse_tx141th"

    def decode(self, cap: PulseCapture) -> List[Decoded]:
        out: Dict[str, Decoded] = {}
        for p in polarities(cap.pulses):
            for row in slice_pwm(p, 208, 417, sync=833, gap_limit=625, reset_limit=1700):
                if len(row) not in (40, 41):
                    continue
                b = B.bits_to_bytes(row, 0, 5)
                if B.lfsr_digest8_reflect(b[:4], 0x31, 0xF4) != b[4]:
                    continue
                temp_c = round(((((b[1] & 0x0F) << 8) | b[2]) - 500) * 0.1, 1)
                humidity = b[3]
                if not -40 <= temp_c <= 70 or humidity > 100:
                    continue
                channel = (b[1] & 0x30) >> 4
                d = Decoded("LaCrosse-TX141TH", "lacrosse-tx141th", f"tx141th:{b[0]}:{channel}",
                            {"id": b[0], "channel": channel, "battery_ok": not (b[1] >> 7),
                             "temperature_C": temp_c, "humidity_pct": humidity},
                            integrity="lfsr-digest")
                out[d.device_key] = d
        return list(out.values())


class HoneywellDecoder(PulseDecoder):
    """Honeywell/Ademco 5800-series and 2GIG security sensors (345 MHz).

    OOK, Manchester with ~136 us half-bit. 16-bit preamble 0xFFFE, then
    channel(4) id(20) event(8) CRC-16(poly 0x8005, or 0x8050 for 2GIG types).
    Event bits: 0x80 contact open, 0x40 tamper, 0x20 reed, 0x10 alarm,
    0x08 battery low, 0x04 supervision heartbeat.
    """
    name = "honeywell"
    PREAMBLE = "010101010101010101010110"  # last 12 bits of 0xFFFE, Manchester

    def decode(self, cap: PulseCapture) -> List[Decoded]:
        out: Dict[str, Decoded] = {}
        for p in polarities(cap.pulses):
            unit = refine_unit(p, 136)
            for row in slice_pcm(p, unit, reset_limit=unit * 3):
                for candidate in (row, B.invert(row)):
                    d = self._search(candidate)
                    if d:
                        out[d.device_key] = d
        return list(out.values())

    def _search(self, row: str) -> Optional[Decoded]:
        pos = row.find(self.PREAMBLE)
        while 0 <= pos and pos + 24 + 96 <= len(row):
            dec = B.manchester_decode(row, pos + 24, 48)
            if len(dec) >= 48:
                b = B.bits_to_bytes(dec, 0, 6)
                d = self._check(b)
                if d:
                    return d
            pos = row.find(self.PREAMBLE, pos + 1)
        return None

    @staticmethod
    def _check(b: bytes) -> Optional[Decoded]:
        channel = b[0] >> 4
        device_id = ((b[0] & 0x0F) << 16) | (b[1] << 8) | b[2]
        crc = (b[4] << 8) | b[5]
        if device_id == 0 and crc == 0:
            return None
        poly = 0x8050 if channel in (0x2, 0x4, 0x9, 0xA, 0xC) else 0x8005
        if B.crc16(b[:4], poly, 0) != crc:
            return None
        ev = b[3]
        brand = "2GIG" if poly == 0x8050 else "Honeywell/Ademco"
        return Decoded(
            f"{brand} security sensor", "security-345", f"honeywell:{device_id:05x}",
            {"id": f"{device_id:05x}", "channel": channel, "brand": brand,
             "state": "open" if ev & 0x80 else "closed", "alarm": bool(ev & 0x10),
             "tamper": bool(ev & 0x40), "battery_ok": not ev & 0x08,
             "heartbeat": bool(ev & 0x04), "event": f"{ev:02x}"},
            integrity="crc")


# --------------------------------------------------------------------------
# Packet decoders (bytes after a CC1101 hardware sync-word match)
# --------------------------------------------------------------------------

class PacketDecoder:
    name = "base"
    sync = ""

    def decode(self, data: bytes, freq_mhz: float) -> Optional[Decoded]:
        raise NotImplementedError


class LaCrosseITPlusDecoder(PacketDecoder):
    """LaCrosse IT+ (TX29-IT, TX35DTH-IT, TX25U; TFA 30.3155/30.3159).

    868.3 MHz (EU) / 915 MHz (US) FSK, 17.24 or 9.58 kbps, sync 0x2DD4.
    5 bytes: 9 | id(6) | new-batt | ? | temp BCD (C*10+400) | weak-batt |
    humidity(7, 106 = none) | CRC-8 poly 0x31.
    """
    name = "lacrosse_itplus"
    sync = "2dd4"

    def decode(self, data: bytes, freq_mhz: float) -> Optional[Decoded]:
        if len(data) < 5 or data[0] >> 4 != 9 or B.crc8(data[:4], 0x31) != data[4]:
            return None
        digits = (data[1] & 0x0F, data[2] >> 4, data[2] & 0x0F)
        if any(dg > 9 for dg in digits):
            return None
        sensor_id = ((data[0] & 0x0F) << 2) | (data[1] >> 6)
        temp_c = round((digits[0] * 100 + digits[1] * 10 + digits[2]) / 10 - 40, 1)
        hum = data[3] & 0x7F
        fields = {"id": sensor_id, "temperature_C": temp_c,
                  "battery_ok": not data[3] >> 7, "new_battery": bool(data[1] & 0x20)}
        if hum <= 100:
            fields["humidity_pct"] = hum
        elif hum == 125:
            fields["probe"] = 2
        return Decoded("LaCrosse-IT+", "lacrosse-itplus", f"lacrosse-itplus:{sensor_id}", fields)


class FineOffsetWH24Decoder(PacketDecoder):
    """Fine Offset WH24/WH65 outdoor array (Ambient Weather WS-2902,
    Ecowitt WS69, Misol, Froggit...). 433/868/915 MHz FSK 17.24 kbps,
    sync 0x2DD4, 17 bytes, CRC-8 poly 0x31 + 8-bit sum. Sends every ~16 s.
    """
    name = "fineoffset_wh24"
    sync = "2dd4"

    def decode(self, data: bytes, freq_mhz: float) -> Optional[Decoded]:
        if len(data) < 17 or data[0] != 0x24:
            return None
        if B.crc8(data[:16], 0x31) != 0 or B.add_bytes(data[:16]) != data[16]:
            return None
        b = data
        temp_raw = ((b[3] & 0x07) << 8) | b[4]
        wind_dir = b[2] | ((b[3] & 0x80) << 1)
        wind_raw = b[6] | ((b[3] & 0x10) << 4)
        fields: Dict[str, object] = {"id": b[1], "battery_ok": not (b[3] & 0x08)}
        if temp_raw != 0x7FF:
            fields["temperature_C"] = round((temp_raw - 400) * 0.1, 1)
        if b[5] != 0xFF:
            fields["humidity_pct"] = b[5]
        if wind_dir != 0x1FF:
            fields["wind_dir_deg"] = wind_dir
        # WH65 scaling (the common 868/915 MHz variant); WH24 uses 1.12 m/s & 0.3 mm
        if wind_raw != 0x1FF:
            fields["wind_avg_m_s"] = round(wind_raw * 0.125 * 0.51, 1)
        if b[7] != 0xFF:
            fields["wind_gust_m_s"] = round(b[7] * 0.51, 1)
        fields["rain_mm"] = round(((b[8] << 8) | b[9]) * 0.254, 1)
        uv = (b[10] << 8) | b[11]
        if uv != 0xFFFF:
            fields["uv_raw"] = uv
        light = (b[12] << 16) | (b[13] << 8) | b[14]
        if light != 0xFFFFFF:
            fields["light_lux"] = round(light * 0.1, 1)
        return Decoded("FineOffset-WH24/WH65", "fineoffset-wh65", f"fineoffset-wh65:{b[1]}", fields,
                       integrity="crc+checksum")


class AmbientWH31EDecoder(PacketDecoder):
    """Ambient Weather WH31E / Ecowitt WH31 thermo-hygrometer (915/868 MHz).

    FSK 17.86 kbps (56 us), sync 0x2DD4, type 0x30 (0x37 = WH31B),
    CRC-8 poly 0x31 over 5 bytes + 8-bit sum.
    """
    name = "ambient_wh31e"
    sync = "2dd4"

    def decode(self, data: bytes, freq_mhz: float) -> Optional[Decoded]:
        if len(data) < 7 or data[0] not in (0x30, 0x37):
            return None
        if B.crc8(data[:6], 0x31) != 0 or B.add_bytes(data[:6]) != data[6]:
            return None
        b = data
        channel = ((b[2] & 0x70) >> 4) + 1
        temp_c = round(((((b[2] & 0x03) << 8) | b[3]) - 400) * 0.1, 1)
        model = "AmbientWeather-WH31E" if b[0] == 0x30 else "AmbientWeather-WH31B"
        return Decoded(model, "ambient-wh31", f"wh31:{b[1]:02x}",
                       {"id": f"{b[1]:02x}", "channel": channel, "battery_ok": not (b[2] & 0x04),
                        "temperature_C": temp_c, "humidity_pct": b[4]},
                       integrity="crc+checksum")


# Wireless M-Bus (EN 13757-4) -------------------------------------------------

_3OF6 = {0x16: 0x0, 0x0D: 0x1, 0x0E: 0x2, 0x0B: 0x3, 0x1C: 0x4, 0x19: 0x5, 0x1A: 0x6, 0x13: 0x7,
         0x2C: 0x8, 0x25: 0x9, 0x26: 0xA, 0x23: 0xB, 0x34: 0xC, 0x31: 0xD, 0x32: 0xE, 0x29: 0xF}

WMBUS_DEVICE_TYPES = {
    0x00: "Other", 0x01: "Oil meter", 0x02: "Electricity meter", 0x03: "Gas meter",
    0x04: "Heat meter", 0x05: "Steam meter", 0x06: "Warm water meter", 0x07: "Water meter",
    0x08: "Heat cost allocator", 0x09: "Compressed air", 0x0A: "Cooling meter",
    0x0B: "Cooling meter", 0x0C: "Heat meter", 0x0D: "Heat/cooling meter",
    0x0E: "Bus/system component", 0x15: "Hot water meter", 0x16: "Cold water meter",
    0x17: "Hot/cold water meter", 0x18: "Pressure meter", 0x19: "A/D converter",
    0x1A: "Smoke detector", 0x1B: "Room sensor", 0x1C: "Gas detector",
    0x20: "Breaker", 0x21: "Valve", 0x25: "Customer display", 0x28: "Waste water meter",
    0x29: "Garbage", 0x2A: "CO2 sensor", 0x31: "Communication controller",
    0x32: "Repeater", 0x33: "Repeater", 0x36: "Radio converter", 0x37: "Radio converter",
}

WMBUS_MANUFACTURERS = {
    "KAM": "Kamstrup", "DME": "Diehl Metering", "HYD": "Diehl (Hydrometer)", "ITW": "Itron",
    "ACW": "Itron (Actaris)", "TCH": "Techem", "QDS": "Qundis", "SON": "Sontex", "APA": "Apator",
    "LUG": "Landis+Gyr", "ELS": "Elster/Honeywell", "ZRI": "Zenner", "SEN": "Sensus",
    "EFE": "Engelmann", "IST": "ista", "BMT": "B METERS", "AMT": "Aquametro", "EMH": "EMH metering",
    "ELV": "Elvaco", "LAS": "Lansen", "GWF": "GWF", "BHG": "Brunata", "NZR": "NZR",
    "SAP": "Sappel", "MAD": "Maddalena", "WEH": "Wehrle", "ABB": "ABB", "EIE": "EI Electronics",
}

WMBUS_C_FIELD = {0x44: "SND_NR (meter reading)", 0x46: "SND_IR (installation)", 0x08: "RSP_UD",
                 0x06: "ACC_DMD", 0x47: "ACC_NR", 0x40: "SND_NKE"}


def wmbus_crc_ok(block: bytes) -> bool:
    """EN 13757 CRC-16 (poly 0x3D65, final complement) over block[:-2]."""
    if len(block) < 3:
        return False
    crc = (~B.crc16(block[:-2], 0x3D65, 0)) & 0xFFFF
    return crc == (block[-2] << 8) | block[-1]


def wmbus_decode_3of6(data: bytes) -> bytes:
    bits = B.bytes_to_bits(data)
    out = bytearray()
    for i in range(0, len(bits) - 11, 12):
        hi = _3OF6.get(int(bits[i:i + 6], 2))
        lo = _3OF6.get(int(bits[i + 6:i + 12], 2))
        if hi is None or lo is None:
            break
        out.append((hi << 4) | lo)
    return bytes(out)


def wmbus_manufacturer(m_field: int) -> str:
    return "".join(chr(((m_field >> s) & 0x1F) + 0x40) for s in (10, 5, 0))


class WMBusDecoder(PacketDecoder):
    """Wireless M-Bus link layer, modes T1 (3-of-6) and C1 (frame A/B), 868.95 MHz.

    Utility meters across Europe (water, heat, gas, electricity, heat-cost
    allocators, smoke detectors) broadcast these every few seconds to minutes.
    We decode and CRC-check block 1: manufacturer, serial, version, type.
    Meter readings are usually AES-encrypted and are not decoded.
    """
    name = "wmbus"
    sync = "543d"

    def decode(self, data: bytes, freq_mhz: float) -> Optional[Decoded]:
        if len(data) >= 14 and data[0] == 0x54 and data[1] == 0xCD:
            mode, frame = "C1", data[2:]
            block1 = frame[:12]
            if not wmbus_crc_ok(block1):
                return None
        elif len(data) >= 14 and data[0] == 0x54 and data[1] == 0x3D:
            mode, frame = "C1", data[2:]
            length = frame[0]
            if len(frame) < length + 1 or length > 125 or not wmbus_crc_ok(frame[:length + 1]):
                return None
        else:
            mode, frame = "T1", wmbus_decode_3of6(data)
            block1 = frame[:12]
            if len(block1) < 12 or not wmbus_crc_ok(block1):
                return None
        b = frame
        if b[0] < 9:
            return None
        manuf = wmbus_manufacturer((b[3] << 8) | b[2])
        if not manuf.isalpha():
            return None
        serial = "".join(f"{b[i]:02x}" for i in (7, 6, 5, 4))
        dev_type = WMBUS_DEVICE_TYPES.get(b[9], f"type 0x{b[9]:02x}")
        return Decoded(
            f"wM-Bus {dev_type}", "wmbus-meter", f"wmbus:{manuf}:{serial}",
            {"manufacturer": WMBUS_MANUFACTURERS.get(manuf, manuf), "manufacturer_code": manuf,
             "serial": serial, "device_type": dev_type, "version": b[8], "mode": mode,
             "frame": WMBUS_C_FIELD.get(b[1], f"C=0x{b[1]:02x}")},
            integrity="crc")


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

PULSE_DECODERS: List[PulseDecoder] = [
    AcuriteTowerDecoder(), LaCrosseTX141THDecoder(), HoneywellDecoder(), EV1527Decoder(),
]

PACKET_DECODERS: List[PacketDecoder] = [
    LaCrosseITPlusDecoder(), FineOffsetWH24Decoder(), AmbientWH31EDecoder(), WMBusDecoder(),
]

# Sync words the companion firmware listens for, with how many bytes to read.
SYNC_PROFILES = {"2dd4": 20, "543d": 60}


def decode_packet(pkt: Packet) -> List[Decoded]:
    out = []
    for dec in PACKET_DECODERS:
        if dec.sync != pkt.sync:
            continue
        d = dec.decode(pkt.data, pkt.freq_mhz)
        if d:
            out.append(d)
            break
    return out


def _fsk_pcm_to_packets(cap: PulseCapture) -> List[Packet]:
    """Recover sync-word packets from a raw FSK edge capture (NRZ)."""
    packets = []
    durations = [p for p in cap.pulses if p > 0]
    if not durations:
        return packets
    unit = refine_unit(durations, min(durations), lo=0.7, hi=1.4)
    for p in polarities(cap.pulses):
        for row in slice_pcm(p, unit, reset_limit=unit * 40):
            for sync, nbytes in SYNC_PROFILES.items():
                pos = row.find(B.hex_to_bits(sync))
                if pos >= 0:
                    data = B.bits_to_bytes(row, pos + 16, nbytes)
                    packets.append(Packet(data, cap.freq_mhz, sync, cap.t, cap.rssi, None, cap.source))
    return packets


def decode_capture(cap: PulseCapture) -> List[Decoded]:
    results: Dict[str, Decoded] = {}
    if cap.modulation.upper() == "FSK":
        for pkt in _fsk_pcm_to_packets(cap):
            for d in decode_packet(pkt):
                results[d.device_key] = d
    for dec in PULSE_DECODERS:
        try:
            for d in dec.decode(cap):
                results.setdefault(d.device_key, d)
        except (IndexError, ValueError, ZeroDivisionError):
            continue
    return list(results.values())


def decoder_names() -> Sequence[str]:
    return [d.name for d in PULSE_DECODERS] + [d.name for d in PACKET_DECODERS]
