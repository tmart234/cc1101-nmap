import hashlib
import re
import math

class BaseDecoder:
    """Base class for all decoders. Ensures a common interface."""
    def decode(self, data_bytes, radio_config):
        raise NotImplementedError

def _calculate_entropy(data):
    """Calculates the Shannon entropy of a byte string."""
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

class CreditCardSkimmerDecoder(BaseDecoder):
    """Looks for the specific format of raw credit card magnetic stripe data."""
    def decode(self, data, radio_config):
        try:
            text = data.decode('ascii', errors='ignore')
            track2_match = re.search(r';(\d{10,19}=\d{4,})(\d+)\?', text)
            if track2_match:
                return {'protocol': '!!! Credit Card Skimmer !!!', 'id': f'skimmer-alert-{hashlib.sha1(data).hexdigest()[:8]}', 'data': {'alert': 'High confidence skimmer detected', 'type': 'Track 2 Data', 'masked_pan': track2_match.group(1)[:4] + 'x' * (len(track2_match.group(1)) - 8) + track2_match.group(1)[-4:]}}
            track1_match = re.search(r'%B(\d{10,19})\^([^\^]+)\^(\d{4,})\?', text)
            if track1_match:
                 return {'protocol': '!!! Credit Card Skimmer !!!', 'id': f'skimmer-alert-{hashlib.sha1(data).hexdigest()[:8]}', 'data': {'alert': 'High confidence skimmer detected', 'type': 'Track 1 Data', 'masked_pan': track1_match.group(1)[:4] + 'x' * (len(track1_match.group(1)) - 8) + track1_match.group(1)[-4:]}}
        except: return None
        return None

class MedRadioDecoder(BaseDecoder):
    """Heuristic decoder that flags any signal using the MedRadio config."""
    def decode(self, data, radio_config):
        if radio_config == 'FSK_MANCHESTER_MEDRADIO':
            return {'protocol': '!!! MedRadio Signal !!!', 'id': f'medradio-{hashlib.sha1(data).hexdigest()[:8]}', 'data': {'alert': 'Signal matching MedRadio physical layer detected. Do not log payload.', 'payload_len': len(data)}}
        return None

class DigitalSignalBurstDecoder(BaseDecoder):
    """
    Identifies short, high-entropy digital bursts characteristic of signals like
    MDC-1200, Fleetsync, or other public safety data transmissions.
    """
    def decode(self, data, radio_config):
        if 'FSK' not in radio_config or not (2 <= len(data) <= 16):
            return None
        suspicion_score = 0
        entropy = _calculate_entropy(data)
        if entropy > 3.0: suspicion_score += 40
        if len(set(data)) > len(data) / 2: suspicion_score += 30
        if len(data) not in [4, 8]: suspicion_score += 20
        if all(b == 0x00 for b in data) or all(b == 0xFF for b in data): suspicion_score = 0
        if suspicion_score >= 60:
            return {'protocol': 'Digital Data Burst (Public Safety?)', 'id': f'burst-{hashlib.sha1(data).hexdigest()[:8]}', 'data': {'alert': 'High-entropy FSK packet detected.', 'score': suspicion_score, 'entropy': round(entropy, 2), 'payload_hex': data.hex()}}
        return None

class GPSTrackerDecoder(BaseDecoder):
    """Looks for NMEA-formatted GPS data sentences."""
    def decode(self, data, radio_config):
        try:
            text = data.decode('ascii', errors='ignore')
            # Look for a common NMEA sentence like $GPRMC
            gprmc_match = re.search(r'\$GPRMC,(\d{6}\.\d{2}),A,(\d{4}\.\d{4}),([NS]),(\d{5}\.\d{4}),([EW])', text)
            if gprmc_match:
                lat_raw, lat_dir, lon_raw, lon_dir = gprmc_match.group(2, 3, 4, 5)
                lat = round(float(lat_raw[:2]) + float(lat_raw[2:]) / 60, 6) * (1 if lat_dir == 'N' else -1)
                lon = round(float(lon_raw[:3]) + float(lon_raw[3:]) / 60, 6) * (1 if lon_dir == 'E' else -1)
                return {'protocol': 'GPS Tracker (NMEA)', 'id': f'gps-nmea-{hashlib.sha1(data).hexdigest()[:8]}', 'data': {'latitude': lat, 'longitude': lon}}
        except: return None
        return None

class TPMSDecoder(BaseDecoder):
    """Decodes common Tire Pressure Monitoring System (TPMS) packets."""
    def decode(self, data, radio_config):
        # Many TPMS sensors (like Schrader) use a 9-byte packet
        if len(data) != 9:
            return None
        try:
            # A common format is a 4-byte ID, pressure, temp, status, and checksum
            sensor_id = data[0:4].hex().upper()
            pressure_kpa = data[4] * 2.5 # Example conversion
            temp_c = data[5] - 40       # Example conversion
            status = data[6]
            checksum = data[8]
            calculated_checksum = sum(data[0:8]) & 0xFF
            if checksum == calculated_checksum:
                return {
                    'protocol': 'TPMS (Tire Sensor)',
                    'id': f'tpms-{sensor_id}',
                    'data': {'pressure_kpa': pressure_kpa, 'temperature_C': temp_c, 'status': hex(status)}
                }
        except: return None
        return None

class WirelessAlarmSensorDecoder(BaseDecoder):
    """Decodes common wireless alarm sensor packets (e.g., Honeywell 5800 series)."""
    def decode(self, data, radio_config):
        # Honeywell 5800 series packets are often 6 bytes
        if len(data) != 6:
            return None
        try:
            # Format: Preamble, Sensor ID (3 bytes), Status, CRC
            sensor_id = data[1:4].hex().upper()
            status = data[4]
            # Bit flags in the status byte are important
            is_tripped = (status & 0b00000100) > 0
            low_battery = (status & 0b00001000) > 0
            # A real implementation would have a proper CRC check here
            return {
                'protocol': 'Wireless Alarm Sensor',
                'id': f'alarm-{sensor_id}',
                'data': {'tripped': is_tripped, 'low_battery': low_battery, 'status_byte': hex(status)}
            }
        except: return None
        return None

class Acurite5n1Decoder(BaseDecoder):
    """Decodes packets from Acurite 5-in-1 Weather Stations."""
    def decode(self, data, radio_config):
        if len(data) != 7: return None
        try:
            sensor_id = (data[0] << 8) | data[1]
            temp_raw = ((data[3] & 0x0F) << 7) | (data[4] & 0x7F)
            temperature_C = (temp_raw - 400) / 10.0
            humidity = data[5] & 0x7F
            if sum(data[0:6]) & 0xFF != data[6]: return None
            return {'protocol': 'Acurite 5n1 Weather', 'id': f'acurite-{sensor_id}', 'data': {'temperature_C': round(temperature_C, 1), 'humidity': humidity}}
        except: return None

class POCSAGDecoder(BaseDecoder):
    """Heuristic decoder for POCSAG pager messages."""
    def decode(self, data, radio_config):
        try:
            text = data.decode('ascii', errors='ignore')
            printable_chars = sum(1 for c in text if c.isprintable() or c in '\r\n\t')
            if len(text) > 8 and (printable_chars / len(text)) > 0.7:
                return {'protocol': 'POCSAG Pager (Likely)', 'id': f'pocsag-{hashlib.sha1(data).hexdigest()[:8]}', 'data': {'message': text.strip()}}
        except: return None
        return None

class ImplantHeartbeatDecoder(BaseDecoder):
    """Heuristic decoder for suspicious short packets that could be heartbeats."""
    def decode(self, data, radio_config):
        # Refined rule: Check for short packets with LOW entropy. A simple ID is not random.
        if 2 <= len(data) <= 8:
            entropy = _calculate_entropy(data)
            if entropy < 2.5: # Low entropy suggests a simple, repeating ID
                return {'protocol': 'Suspicious Heartbeat (Implant?)', 'id': f'implant-ping-{hashlib.sha1(data).hexdigest()[:8]}', 'data': {'alert': 'Short, low-entropy packet detected. Monitor for periodicity.', 'entropy': round(entropy, 2), 'payload_hex': data.hex()}}
        return None

class GenericDecoder(BaseDecoder):
    """A fallback decoder for unknown protocols."""
    def decode(self, data, radio_config):
        if not data: return None
        return {'protocol': 'Unknown', 'id': f'unknown-{hashlib.sha1(data[:8]).hexdigest()[:10]}', 'data': {'payload_len': len(data), 'payload_hex': data.hex()}}

# --- The main pipeline. More specific decoders are placed first. ---
DECODER_PIPELINE = [
    CreditCardSkimmerDecoder(),
    MedRadioDecoder(),
    DigitalSignalBurstDecoder(),
    GPSTrackerDecoder(),
    TPMSDecoder(),
    WirelessAlarmSensorDecoder(),
    Acurite5n1Decoder(),
    POCSAGDecoder(),
    ImplantHeartbeatDecoder(),
    GenericDecoder(), # Always last
]

