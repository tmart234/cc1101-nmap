# decoders.py
from __future__ import annotations
import hashlib
import re
import math
from typing import Optional, Dict, Any, List

# Global policy: don't return or store sensitive raw payloads unless explicitly allowed.
ALLOW_SENSITIVE_BY_DEFAULT = False

def _calculate_entropy(data: bytes) -> float:
    """Shannon entropy of a byte string."""
    if not data:
        return 0.0
    counts = [0]*256
    for b in data:
        counts[b] += 1
    ent = 0.0
    length = len(data)
    for c in counts:
        if c == 0:
            continue
        p = c / length
        ent -= p * math.log2(p)
    return ent

class BaseDecoder:
    """Base class for decoders; decode returns a dict or None."""
    sensitive: bool = False  # If True, treat output as potentially sensitive (do not include raw payload by default)
    name: str = "Base"

    def decode(self, data: bytes, radio_config: str, allow_sensitive: bool = ALLOW_SENSITIVE_BY_DEFAULT) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    @staticmethod
    def make_id(prefix: str, data: bytes, length: int = 8) -> str:
        return f"{prefix}-{hashlib.sha1(data).hexdigest()[:length]}"

# --- Specific decoders ---
class CreditCardSkimmerDecoder(BaseDecoder):
    """Detects magnetic stripe Track 1/2 patterns. Marked sensitive."""
    sensitive = True
    name = "CreditCardSkimmer"

    def decode(self, data: bytes, radio_config: str, allow_sensitive: bool = ALLOW_SENSITIVE_BY_DEFAULT):
        try:
            text = data.decode('ascii', errors='ignore')
            # Track 2 e.g. ;<PAN>=<exp><svc>...?
            track2 = re.search(r';(\d{10,19})=(\d{4})(\d*?)\?', text)
            if track2:
                pan = track2.group(1)
                masked = pan[:4] + 'x'*(len(pan)-8) + pan[-4:] if len(pan) >= 8 else 'x'*len(pan)
                out = {
                    'protocol': 'CreditCardSkimmer (Track2)',
                    'id': self.make_id('skimmer', data),
                    'data': {'alert': 'Possible Track2 magnetic stripe data', 'masked_pan': masked}
                }
                # Do not include raw payload unless allowed explicitly
                if allow_sensitive:
                    out['data']['payload_hex'] = data.hex()
                return out

            # Track 1 e.g. %B<PAN>^NAME^YYMM...
            track1 = re.search(r'%B(\d{10,19})\^([^^]+)\^(\d{4})', text)
            if track1:
                pan = track1.group(1)
                masked = pan[:4] + 'x'*(len(pan)-8) + pan[-4:] if len(pan) >= 8 else 'x'*len(pan)
                out = {
                    'protocol': 'CreditCardSkimmer (Track1)',
                    'id': self.make_id('skimmer', data),
                    'data': {'alert': 'Possible Track1 magnetic stripe data', 'masked_pan': masked}
                }
                if allow_sensitive:
                    out['data']['payload_hex'] = data.hex()
                return out
        except Exception:
            return None
        return None

class MedRadioDecoder(BaseDecoder):
    """Flag MedRadio physical-layer shows up. Always sensitive: do not include payloads."""
    sensitive = True
    name = "MedRadio"

    def decode(self, data: bytes, radio_config: str, allow_sensitive: bool = ALLOW_SENSITIVE_BY_DEFAULT):
        if radio_config and 'MEDRADIO' in radio_config.upper():
            return {
                'protocol': 'MedRadio (physical-layer match)',
                'id': self.make_id('medradio', data),
                'data': {'alert': 'MedRadio physical layer detected. Payload suppressed for privacy.' , 'payload_len': len(data)}
            }
        return None

class DigitalSignalBurstDecoder(BaseDecoder):
    """Detect short, moderately high-entropy bursts typical of IDs or short data frames."""
    name = "DigitalSignalBurst"

    def decode(self, data: bytes, radio_config: str, allow_sensitive: bool = ALLOW_SENSITIVE_BY_DEFAULT):
        if not radio_config or 'FSK' not in radio_config.upper():
            return None
        if not (2 <= len(data) <= 32):
            return None

        entropy = _calculate_entropy(data)
        score = 0
        if entropy > 3.0:
            score += 40
        if len(set(data)) > len(data)/2:
            score += 30
        if len(data) not in (4,8,12,16):
            score += 15
        if all(b == 0x00 for b in data) or all(b == 0xFF for b in data):
            score = 0

        if score >= 60:
            out = {
                'protocol': 'DigitalSignalBurst',
                'id': self.make_id('burst', data),
                'data': {'alert': 'High-entropy FSK packet', 'score': score, 'entropy': round(entropy,2)}
            }
            # Small hex okay to include for analysis; allow_sensitive only affects high-PII decoders
            out['data']['payload_hex'] = data.hex()
            return out
        return None

class GPSTrackerDecoder(BaseDecoder):
    """Detects NMEA sentences; this reveals location so it's treated as semi-sensitive."""
    sensitive = True
    name = "GPSTracker"

    def decode(self, data: bytes, radio_config: str, allow_sensitive: bool = ALLOW_SENSITIVE_BY_DEFAULT):
        try:
            text = data.decode('ascii', errors='ignore')
            # find GPRMC or GPGGA with numeric coordinates
            gprmc = re.search(r'\$GPRMC,(\d{6}\.\d{2}),[AV],(\d{4}\.\d+),([NS]),(\d{5}\.\d+),([EW])', text)
            if gprmc:
                # convert lat/lon
                time_str = gprmc.group(1)
                lat_raw = gprmc.group(2); lat_dir = gprmc.group(3)
                lon_raw = gprmc.group(4); lon_dir = gprmc.group(5)
                lat = (float(lat_raw[:2]) + float(lat_raw[2:]) / 60.0) * (1 if lat_dir == 'N' else -1)
                lon = (float(lon_raw[:3]) + float(lon_raw[3:]) / 60.0) * (1 if lon_dir == 'E' else -1)
                out = {
                    'protocol': 'GPS (NMEA)',
                    'id': self.make_id('gps', data),
                    'data': {'latitude': round(lat,6), 'longitude': round(lon,6)}
                }
                if allow_sensitive:
                    out['data']['raw'] = text.strip()
                return out
        except Exception:
            return None
        return None

class TPMSDecoder(BaseDecoder):
    """Basic heuristic for a common 9-byte TPMS layout (very heuristic)."""
    name = "TPMS"

    def decode(self, data: bytes, radio_config: str, allow_sensitive: bool = ALLOW_SENSITIVE_BY_DEFAULT):
        if 'FSK' not in (radio_config or '').upper():
            return None
        if len(data) != 9:
            return None
        try:
            sensor_id = data[0:4].hex().upper()
            pressure_kpa = data[4] * 2.5
            temp_c = data[5] - 40
            status = data[6]
            checksum = data[8]
            calc = sum(data[0:8]) & 0xFF
            if checksum != calc:
                return None
            return {
                'protocol': 'TPMS',
                'id': f"tpms-{sensor_id}",
                'data': {'pressure_kpa': round(pressure_kpa,1), 'temperature_C': temp_c, 'status': hex(status)}
            }
        except Exception:
            return None

class WirelessAlarmSensorDecoder(BaseDecoder):
    """Common ASK/OOK household sensors (heuristic)."""
    name = "WirelessAlarmSensor"

    def decode(self, data: bytes, radio_config: str, allow_sensitive: bool = ALLOW_SENSITIVE_BY_DEFAULT):
        if 'OOK' not in (radio_config or '').upper():
            return None
        if len(data) not in (6,7):
            return None
        try:
            sensor_id = data[1:4].hex().upper()
            status = data[4]
            is_tripped = bool(status & 0b00000100)
            low_batt = bool(status & 0b00001000)
            return {
                'protocol': 'WirelessAlarmSensor',
                'id': f"alarm-{sensor_id}",
                'data': {'tripped': is_tripped, 'low_battery': low_batt, 'status_byte': hex(status)}
            }
        except Exception:
            return None

class Acurite5n1Decoder(BaseDecoder):
    """Acurite 5-in-1 weather station (heuristic, with checksum)."""
    name = "Acurite5n1"

    def decode(self, data: bytes, radio_config: str, allow_sensitive: bool = ALLOW_SENSITIVE_BY_DEFAULT):
        if len(data) != 7:
            return None
        try:
            sensor_id = (data[0] << 8) | data[1]
            temp_raw = ((data[3] & 0x0F) << 7) | (data[4] & 0x7F)
            temperature_C = (temp_raw - 400) / 10.0
            humidity = data[5] & 0x7F
            if (sum(data[0:6]) & 0xFF) != data[6]:
                return None
            return {'protocol': 'Acurite5n1', 'id': f'acurite-{sensor_id}', 'data': {'temperature_C': round(temperature_C,1), 'humidity': humidity}}
        except Exception:
            return None

class POCSAGDecoder(BaseDecoder):
    """Heuristic POCSAG pager content detector (returns message text)."""
    name = "POCSAG"

    def decode(self, data: bytes, radio_config: str, allow_sensitive: bool = ALLOW_SENSITIVE_BY_DEFAULT):
        try:
            text = data.decode('ascii', errors='ignore')
            printable = sum(1 for c in text if c.isprintable() or c in '\r\n\t')
            if len(text) > 8 and (printable/len(text) > 0.7) and any(ch.isdigit() for ch in text):
                return {'protocol': 'POCSAG', 'id': self.make_id('pocsag', data), 'data': {'message': text.strip()}}
        except Exception:
            return None
        return None

class ImplantHeartbeatDecoder(BaseDecoder):
    """Short low-entropy pings that may indicate a periodic beacon."""
    name = "ImplantHeartbeat"

    def decode(self, data: bytes, radio_config: str, allow_sensitive: bool = ALLOW_SENSITIVE_BY_DEFAULT):
        if 2 <= len(data) <= 8:
            ent = _calculate_entropy(data)
            if ent < 2.5:
                return {'protocol': 'ImplantHeartbeat', 'id': self.make_id('implant', data), 'data': {'alert': 'Low-entropy short packet', 'entropy': round(ent,2), 'payload_hex': data.hex()}}
        return None

class GenericDecoder(BaseDecoder):
    """Fallback for any payloads not recognized by other decoders."""
    name = "Generic"

    def decode(self, data: bytes, radio_config: str, allow_sensitive: bool = ALLOW_SENSITIVE_BY_DEFAULT):
        if not data:
            return None
        return {'protocol': 'Unknown', 'id': f'unknown-{hashlib.sha1(data[:8]).hexdigest()[:10]}', 'data': {'payload_len': len(data), 'payload_hex': data.hex()}}

# Ordered pipeline: specific -> generic last
DECODER_PIPELINE: List[BaseDecoder] = [
    CreditCardSkimmerDecoder(),
    MedRadioDecoder(),
    DigitalSignalBurstDecoder(),
    GPSTrackerDecoder(),
    TPMSDecoder(),
    WirelessAlarmSensorDecoder(),
    Acurite5n1Decoder(),
    POCSAGDecoder(),
    ImplantHeartbeatDecoder(),
    GenericDecoder(),
]
