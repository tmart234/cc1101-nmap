#!/usr/bin/env python3
import time
import json
import argparse
import requests
import logging
import hashlib
import re
import math
from datetime import datetime, timezone
from typing import Tuple, Optional, Dict, Any, List
from collections import Counter

try:
    from manchester import decode as manchester_decode # pip install python-manchester-code
except ImportError:
    logging.error("Manchester library not found. Please run 'pip install python-manchester-code'")
    manchester_decode = None

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)-8s] --- %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# --- Decoder Engine ---
ALLOW_SENSITIVE_BY_DEFAULT = False

def _calculate_entropy(data: bytes) -> float:
    """Calculates the Shannon entropy of a byte string."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


class BaseDecoder:
    name: str = "Base"
    sensitive: bool = False

    def decode(
        self, data: bytes, radio_config: str, allow_sensitive: bool = ALLOW_SENSITIVE_BY_DEFAULT
    ) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    @staticmethod
    def make_id(prefix: str, data: bytes, length: int = 8) -> str:
        return f"{prefix}-{hashlib.sha1(data).hexdigest()[:length]}"

# --- Full Decoder Pipeline  ---
class CreditCardSkimmerDecoder(BaseDecoder):
    sensitive, name = True, "CreditCardSkimmer"
    def decode(self, data: bytes, radio_config: str, allow_sensitive: bool = ALLOW_SENSITIVE_BY_DEFAULT):
        try:
            text = data.decode("ascii", errors="ignore")
            track2 = re.search(r";(\d{10,19})=(\d{4})(\d*?)\?", text)
            if track2:
                pan = track2.group(1)
                masked = pan[:4] + "x" * (len(pan) - 8) + pan[-4:] if len(pan) >= 8 else "x" * len(pan)
                out = {"protocol": "CreditCardSkimmer (Track2)", "id": self.make_id("skimmer", data), "data": {"alert": "Possible Track2 data", "masked_pan": masked}}
                if allow_sensitive: out["data"]["payload_hex"] = data.hex()
                return out
            track1 = re.search(r"%B(\d{10,19})\^([^^]+)\^(\d{4})", text)
            if track1:
                pan = track1.group(1)
                masked = pan[:4] + "x" * (len(pan) - 8) + pan[-4:] if len(pan) >= 8 else "x" * len(pan)
                out = {"protocol": "CreditCardSkimmer (Track1)", "id": self.make_id("skimmer", data), "data": {"alert": "Possible Track1 data", "masked_pan": masked}}
                if allow_sensitive: out["data"]["payload_hex"] = data.hex()
                return out
        except Exception: return None
        return None

class MedRadioDecoder(BaseDecoder):
    sensitive, name = True, "MedRadio"
    def decode(self, data: bytes, radio_config: str, allow_sensitive: bool = ALLOW_SENSITIVE_BY_DEFAULT):
        if radio_config and "MEDRADIO" in radio_config.upper():
            decoded_info = {}
            if manchester_decode:
                try:
                    bitlist = [bit for b in data for bit in f"{b:08b}"]
                    decoded_bits = manchester_decode(bitlist)
                    
                    if isinstance(decoded_bits, list):
                        preview = "".join(str(b) for b in decoded_bits[:64])
                        if len(decoded_bits) > 64:
                            preview += "..."
                        decoded_info['decoded_bits_preview'] = preview
                    else:
                        decoded_info['decoded_bits'] = str(decoded_bits)
                except Exception:
                    decoded_info['decoding_error'] = 'Manchester decoding failed'
            else:
                decoded_info['note'] = "Manchester decode unavailable"
            
            return {
                "protocol": "MedRadio", "id": self.make_id("medradio", data),
                "data": {"alert": "MedRadio physical layer detected. Payload suppressed.", "payload_len": len(data), **decoded_info},
            }
        return None

class DigitalSignalBurstDecoder(BaseDecoder):
    name = "DigitalSignalBurst"
    def decode(self, data: bytes, radio_config: str, allow_sensitive: bool = ALLOW_SENSITIVE_BY_DEFAULT):
        if not radio_config or "FSK" not in radio_config.upper() or not (2 <= len(data) <= 32): return None
        entropy, score = _calculate_entropy(data), 0
        if entropy > 3.0: score += 40
        if len(set(data)) > len(data) / 2: score += 30
        if len(data) not in (4, 8, 12, 16): score += 15
        if all(b in (0x00, 0xFF) for b in data): score = 0
        if score >= 60:
            return {"protocol": "DigitalSignalBurst", "id": self.make_id("burst", data), "data": {"alert": "High-entropy FSK packet", "score": score, "entropy": round(entropy, 2), "payload_hex": data.hex()}}
        return None

class GPSTrackerDecoder(BaseDecoder):
    sensitive, name = True, "GPSTracker"
    def decode(self, data: bytes, radio_config: str, allow_sensitive: bool = ALLOW_SENSITIVE_BY_DEFAULT):
        try:
            text = data.decode("ascii", errors="ignore")
            gprmc = re.search(r"\$GPRMC,(\d{6}\.\d{2}),[AV],(\d{4}\.\d+),([NS]),(\d{5}\.\d+),([EW])", text)
            if gprmc:
                lat_raw, lat_dir, lon_raw, lon_dir = gprmc.group(2, 3, 4, 5)
                lat = (float(lat_raw[:2]) + float(lat_raw[2:]) / 60.0) * (1 if lat_dir == "N" else -1)
                lon = (float(lon_raw[:3]) + float(lon_raw[3:]) / 60.0) * (1 if lon_dir == "E" else -1)
                out = {"protocol": "GPS (NMEA)", "id": self.make_id("gps", data), "data": {"latitude": round(lat, 6), "longitude": round(lon, 6)}}
                if allow_sensitive: out["data"]["raw"] = text.strip()
                return out
        except Exception: return None
        return None

class TPMSDecoder(BaseDecoder):
    name = "TPMS"
    def decode(self, data: bytes, radio_config: str, allow_sensitive: bool = ALLOW_SENSITIVE_BY_DEFAULT):
        if 'FSK' not in (radio_config or '').upper() or len(data) != 9: return None
        try:
            sensor_id = data[0:4].hex().upper()
            pressure_kpa = data[4] * 2.5
            temp_c = data[5] - 40
            status = data[6]
            if sum(data[0:8]) & 0xFF != data[8]: return None
            return {'protocol': 'TPMS', 'id': f"tpms-{sensor_id}", 'data': {'pressure_kpa': round(pressure_kpa,1), 'temperature_C': temp_c, 'status': hex(status)}}
        except Exception: return None

class WirelessAlarmSensorDecoder(BaseDecoder):
    name = "WirelessAlarmSensor"
    def decode(self, data: bytes, radio_config: str, allow_sensitive: bool = ALLOW_SENSITIVE_BY_DEFAULT):
        if 'OOK' not in (radio_config or '').upper() or len(data) not in (6,7): return None
        try:
            sensor_id = data[1:4].hex().upper()
            status = data[4]
            return {'protocol': 'WirelessAlarmSensor', 'id': f"alarm-{sensor_id}", 'data': {'tripped': bool(status & 0b00000100), 'low_battery': bool(status & 0b00001000), 'status_byte': hex(status)}}
        except Exception: return None

class Acurite5n1Decoder(BaseDecoder):
    name = "Acurite5n1"
    def decode(self, data: bytes, radio_config: str, allow_sensitive: bool = ALLOW_SENSITIVE_BY_DEFAULT):
        if len(data) != 7: return None
        try:
            sensor_id = (data[0] << 8) | data[1]
            temp_raw = ((data[3] & 0x0F) << 7) | (data[4] & 0x7F)
            if (sum(data[0:6]) & 0xFF) != data[6]: return None
            return {'protocol': 'Acurite5n1', 'id': f'acurite-{sensor_id}', 'data': {'temperature_C': round((temp_raw - 400) / 10.0, 1), 'humidity': data[5] & 0x7F}}
        except Exception: return None

class POCSAGDecoder(BaseDecoder):
    name = "POCSAG"
    def decode(self, data: bytes, radio_config: str, allow_sensitive: bool = ALLOW_SENSITIVE_BY_DEFAULT):
        try:
            text = data.decode('ascii', errors='ignore')
            if len(text) > 8 and (sum(1 for c in text if c.isprintable() or c in '\r\n\t') / len(text) > 0.7) and any(ch.isdigit() for ch in text):
                return {'protocol': 'POCSAG', 'id': self.make_id('pocsag', data), 'data': {'message': text.strip()}}
        except Exception: return None
        return None

class ImplantHeartbeatDecoder(BaseDecoder):
    name = "ImplantHeartbeat"
    def decode(self, data: bytes, radio_config: str, allow_sensitive: bool = ALLOW_SENSITIVE_BY_DEFAULT):
        if 2 <= len(data) <= 8:
            ent = _calculate_entropy(data)
            if ent < 2.5:
                return {'protocol': 'ImplantHeartbeat', 'id': self.make_id('implant', data), 'data': {'alert': 'Low-entropy short packet', 'entropy': round(ent,2), 'payload_hex': data.hex()}}
        return None

class GenericDecoder(BaseDecoder):
    name = "Generic"
    def decode(self, data: bytes, radio_config: str, allow_sensitive: bool = ALLOW_SENSITIVE_BY_DEFAULT):
        if not data: return None
        return {"protocol": "Unknown", "id": f"unknown-{hashlib.sha1(data[:8]).hexdigest()[:10]}", "data": {"payload_len": len(data), "payload_hex": data.hex()}}

DECODER_PIPELINE: List[BaseDecoder] = [
    CreditCardSkimmerDecoder(), MedRadioDecoder(), DigitalSignalBurstDecoder(),
    GPSTrackerDecoder(), TPMSDecoder(), WirelessAlarmSensorDecoder(), Acurite5n1Decoder(),
    POCSAGDecoder(), ImplantHeartbeatDecoder(),
    GenericDecoder(),
]

# --- EvilCrow Client ---
class EvilCrow:
    """Tolerant client for Evil Crow RF V2 HTTP API (WiFi)."""
    def __init__(self, ip_address: str = "192.168.4.1", timeout: float = 5.0, retries: int = 2):
        self.base_url = f"http://{ip_address}"
        self.session = requests.Session()
        self.timeout = timeout
        self.retries = retries
        for attempt in range(self.retries + 1):
            try:
                r = self.session.get(self.base_url, timeout=self.timeout)
                r.raise_for_status()
                logging.debug("Connected to EvilCrow UI.")
                break
            except requests.RequestException as e:
                if attempt == self.retries:
                    raise ConnectionError(f"Cannot connect to EvilCrow at {self.base_url}: {e}")
                logging.warning(f"Connection attempt {attempt+1} failed. Retrying...")
                time.sleep(1)

    def _get(self, endpoint: str, params: dict = None) -> Optional[str]:
        try:
            r = self.session.get(f"{self.base_url}/{endpoint.lstrip('/')}", params=params, timeout=self.timeout)
            r.raise_for_status()
            return r.text.strip()
        except requests.RequestException as e:
            logging.debug(f"HTTP error calling {endpoint}: {e}")
            return None

    def _send_command(self, command: str, radio: str):
        return self._get("api", {"radio": radio, "command": command})

    def set_radio_config(self, radio: str, config: Dict[str, Any]) -> bool:
        try:
            freq_hz = int(config["freq"] * 1_000_000)
            self._send_command(f"set_freq {freq_hz}", radio)
            mod = config["name"]
            if "MEDRADIO" in mod.upper():
                self._send_command("set_mod GFSK_38_4_KB", radio) # Use a compatible base modulation
            else:
                self._send_command(f"set_mod {mod}", radio)
            return True
        except Exception as e:
            logging.debug(f"Failed to set radio config: {e}")
            return False

    def get_rssi(self, radio: str, freq_mhz: int) -> Optional[int]:
        self._send_command(f"set_freq {int(freq_mhz * 1_000_000)}", radio)
        out = self._send_command("get_rssi", radio)
        if out is None: return None
        try:
            return int(out.strip())
        except ValueError:
            m = re.search(r"-\d+", out)
            return int(m.group(0)) if m else None

    def receive_packet(self, radio: str) -> Tuple[Optional[bytes], Optional[int], Optional[int]]:
        out = self._send_command("rx_sniff on", radio)
        if not out: return None, None, None
        try:
            m_hex = re.search(r"([0-9A-Fa-f ]{4,})", out)
            m_rssi = re.search(r"RSSI[:=]?\s*(-?\d+)", out)
            m_lqi = re.search(r"LQI[:=]?\s*(\d+)", out)
            payload = bytes.fromhex(m_hex.group(1).replace(" ", "")) if m_hex else None
            rssi = int(m_rssi.group(1)) if m_rssi else None
            lqi = int(m_lqi.group(1)) if m_lqi else None
            return payload, rssi, lqi
        except Exception as e:
            logging.debug(f"Failed to parse RX output: {out} / {e}")
            return None, None, None

# --- Scanner Logic ---
SCAN_CONFIGS = [
    {"name": "OOK_4_8_KB", "freq": 433}, {"name": "GFSK_38_4_KB", "freq": 433},
    {"name": "OOK_4_8_KB", "freq": 315}, {"name": "GFSK_38_4_KB", "freq": 315},
    {"name": "GFSK_38_4_KB", "freq": 915}, {"name": "GFSK_100_KB", "freq": 915},
    {"name": "GFSK_38_4_KB", "freq": 868}, {"name": "FSK_MANCHESTER_MEDRADIO", "freq": 405},
]
ANALYSIS_DURATION = 10
known_devices: Dict[str, Dict[str, Any]] = {}

def process_packet(payload: bytes, rssi: int, lqi: int, config_name: str, allow_sensitive: bool):
    global known_devices
    if not payload: return

    for decoder in DECODER_PIPELINE:
        try:
            result = decoder.decode(payload, config_name, allow_sensitive=allow_sensitive)
            if result:
                device_id = result["id"]
                now = time.time()
                if device_id not in known_devices:
                    logging.info(f"NEW DEVICE: {device_id} ({result['protocol']})")
                    known_devices[device_id] = {"first_seen": now, "detections": [], "count": 0}

                known_devices[device_id].update(
                    {"last_seen": now, "rssi": rssi, "lqi": lqi, "protocol": result["protocol"], "config_name": config_name, "count": known_devices[device_id]["count"] + 1}
                )
                
                new_data_str = json.dumps(result["data"], sort_keys=True)
                if not any(json.dumps(d.get("data", {}), sort_keys=True) == new_data_str for d in known_devices[device_id]["detections"]):
                    known_devices[device_id]["detections"].append(result)
                    print_device_report(device_id, allow_sensitive)

                if decoder.name != "Generic": break
        except Exception as e:
            logging.error(f"Decoder {decoder.name} failed: {e}", exc_info=True)

def print_device_report(device_id: str, allow_sensitive: bool):
    device = known_devices.get(device_id)
    if not device: return
    
    report_detections = []
    SENSITIVE_PROTOCOLS = ('CreditCardSkimmer (Track1)', 'CreditCardSkimmer (Track2)', 'GPS (NMEA)', 'MedRadio')
    for det in device.get("detections", []):
        report_data = det.get('data', {}).copy()
        if not allow_sensitive and det.get('protocol') in SENSITIVE_PROTOCOLS:
            report_data.pop('payload_hex', None)
            report_data.pop('raw', None)
            report_data.pop('decoded_bits_preview', None)
        report_detections.append(report_data)

    report = {
        "id": device_id, "protocol": device.get("protocol", "Unknown"),
        "first_seen": datetime.fromtimestamp(device["first_seen"], tz=timezone.utc).isoformat(),
        "last_seen": datetime.fromtimestamp(device["last_seen"], tz=timezone.utc).isoformat(),
        "rssi": device.get("rssi"), "lqi": device.get("lqi"), "count": device.get("count"),
        "config_name": device.get("config_name"),
        "data_logs": report_detections,
    }
    print(json.dumps(report, indent=2))

def check_for_gone_devices(interval: int):
    now = time.time()
    gone_timeout = interval * 2.5
    for dev_id, info in list(known_devices.items()):
        if now - info["last_seen"] > gone_timeout:
            logging.info(f"DEVICE GONE: {info.get('protocol')} ({dev_id}), last seen {int(now - info['last_seen'])}s ago")
            del known_devices[dev_id]

def main(args):
    try:
        crow = EvilCrow(args.ip)
        logging.info(f"Connected to Evil Crow RF V2 at {args.ip}.")
    except ConnectionError as e:
        logging.error(f"Fatal connection error: {e}")
        return

    allowed_freqs = [int(f.strip()) for f in args.freqs.split(",") if f.strip()]
    active_scan_configs = [c for c in SCAN_CONFIGS if c["freq"] in allowed_freqs]
    scan_freqs = sorted({c["freq"] for c in active_scan_configs})
    logging.info(f"Scanner starting. Frequencies: {scan_freqs} MHz. Interval: {args.interval}s.")
    
    hunter, analyst = "A", "B"

    while True:
        logging.info("--- New scan cycle ---")
        active_freq = None
        for freq in scan_freqs:
            try:
                rssi = crow.get_rssi(hunter, freq)
                if rssi is not None and rssi > args.rssi_threshold:
                    logging.info(f"Activity @ {freq} MHz (RSSI {rssi})")
                    active_freq = freq
                    break
            except Exception as e:
                logging.warning(f"Error on hunt phase {freq} MHz: {e}")

        if active_freq:
            analysis_start = time.time()
            while time.time() - analysis_start < ANALYSIS_DURATION:
                for cfg in (c for c in active_scan_configs if c["freq"] == active_freq):
                    try:
                        crow.set_radio_config(analyst, cfg)
                        payload, rssi, lqi = crow.receive_packet(analyst)
                        if payload:
                            process_packet(payload, rssi, lqi, cfg["name"], args.allow_sensitive)
                    except Exception as e:
                        logging.warning(f"Error during analysis {cfg['name']}: {e}")
        else:
            logging.info("No activity detected this cycle.")

        check_for_gone_devices(args.interval)
        logging.info(f"Cycle complete. {len(known_devices)} devices tracked.")
        time.sleep(args.interval)

# --- CLI Entrypoint ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Robust EvilCrow RF V2 Nmap-like scanner.")
    parser.add_argument("--interval", type=int, default=900, help="Seconds between scans (default: 900)")
    parser.add_argument("--ip", type=str, default="192.168.4.1", help="Evil Crow IP")
    parser.add_argument("--freqs", type=str, default="433,915,315,868,405", help="Comma-separated freqs in MHz")
    parser.add_argument("--allow-sensitive", action="store_true", help="Display sensitive payloads (credit card, medradio, gps)")
    parser.add_argument("--rssi-threshold", type=float, default=-100.0, help="RSSI threshold for valid signals")
    args = parser.parse_args()
    try:
        main(args)
    except KeyboardInterrupt:
        logging.info("Exiting on user interrupt.")
    except Exception as e:
        logging.critical(f"Unhandled exception: {e}", exc_info=True)

