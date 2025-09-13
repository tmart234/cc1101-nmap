#!/usr/bin/env python3
# scan.py
from __future__ import annotations
import time
import json
import argparse
import requests
import logging
from datetime import datetime, timezone
from typing import Tuple, Optional, Dict, Any
from decoders import DECODER_PIPELINE, BaseDecoder

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')

# --- Evil Crow RF V2 API Client ---
class EvilCrow:
    """A small, tolerant client for Evil Crow RF V2 HTTP API (WiFi)."""
    def __init__(self, ip_address: str = "192.168.4.1", timeout: float = 5.0, retries: int = 2):
        self.base_url = f"http://{ip_address}"
        self.session = requests.Session()
        self.timeout = timeout
        self.retries = retries
        # Basic connectivity check
        for attempt in range(self.retries + 1):
            try:
                r = self.session.get(self.base_url, timeout=self.timeout)
                r.raise_for_status()
                logging.debug("Connected to EvilCrow UI.")
                break
            except requests.RequestException as e:
                if attempt == self.retries:
                    raise ConnectionError(f"Cannot connect to EvilCrow at {self.base_url}: {e}")
                time.sleep(0.5)

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
        # config expected to have keys 'freq' (MHz) and 'name' (mod string)
        try:
            freq_hz = int(config['freq'] * 1_000_000)
            self._send_command(f"set_freq {freq_hz}", radio)
            self._send_command(f"set_mod {config['name']}", radio)
            return True
        except Exception as e:
            logging.debug(f"Failed to set radio config: {e}")
            return False

    def get_rssi(self, radio: str, freq_mhz: int) -> Optional[int]:
        # Attempt to set the freq and call a get_rssi command; returns integer or None
        self._send_command(f"set_freq {int(freq_mhz * 1_000_000)}", radio)
        out = self._send_command("get_rssi", radio)
        if out is None:
            return None
        try:
            return int(out.strip())
        except ValueError:
            # sometimes the device returns "RSSI:-75"
            m = None
            try:
                import re
                m = re.search(r'-\d+', out)
            except Exception:
                pass
            if m:
                return int(m.group(0))
            return None

    def receive_packet(self, radio: str, timeout_ms: int = 500) -> Tuple[Optional[bytes], Optional[int], Optional[int]]:
        # Start RX sniffing and parse simple expected format
        out = self._send_command("rx_sniff on", radio)
        if not out:
            return None, None, None
        # Try to parse: flexible parsing
        try:
            # look for hex payload anywhere
            import re
            m_hex = re.search(r'([0-9A-Fa-f]{4,})', out)
            m_rssi = re.search(r'RSSI[:=]?\s*(-?\d+)', out)
            m_lqi = re.search(r'LQI[:=]?\s*(\d+)', out)
            payload = bytes.fromhex(m_hex.group(1)) if m_hex else None
            rssi = int(m_rssi.group(1)) if m_rssi else None
            lqi = int(m_lqi.group(1)) if m_lqi else None
            return payload, rssi, lqi
        except Exception as e:
            logging.debug(f"Failed to parse RX output: {out} / {e}")
            return None, None, None

# --- Scanner configs ---
SCAN_CONFIGS = [
    {'name': 'OOK_4_8_KB', 'freq': 433},
    {'name': 'GFSK_38_4_KB', 'freq': 433},
    {'name': 'OOK_4_8_KB', 'freq': 315},
    {'name': 'GFSK_38_4_KB', 'freq': 315},
    {'name': 'GFSK_38_4_KB', 'freq': 915},
    {'name': 'GFSK_100_KB', 'freq': 915},
    {'name': 'GFSK_38_4_KB', 'freq': 868},
]
RSSI_THRESHOLD = -85
ANALYSIS_DURATION = 10  # seconds per found signal
GONE_TIMEOUT = 300  # seconds before a device is considered gone

# Memory of seen devices
known_devices: Dict[str, Dict[str, Any]] = {}

# --- packet processing & device bookkeeping ---
def process_packet(payload: bytes, rssi: int, lqi: int, config_name: str, allow_sensitive: bool = False):
    """Run the payload through the decoder pipeline and update known_devices."""
    if not payload:
        return

    # Quick fingerprint
    short_hash = hashlib_sha1_short(payload)
    now = time.time()
    seen = known_devices.get(short_hash)
    if seen:
        seen['count'] += 1
        seen['last_seen'] = now
        if rssi is not None:
            seen['rssi'] = rssi
        if lqi is not None:
            seen['lqi'] = lqi
    else:
        known_devices[short_hash] = {
            'id': short_hash,
            'first_seen': now,
            'last_seen': now,
            'count': 1,
            'rssi': rssi,
            'lqi': lqi,
            'freq_mode': config_name,
            'detections': []
        }

    # Run decoders in order; stop at first match that returns something (except Generic -> still record)
    decoded_any = False
    for decoder in DECODER_PIPELINE:
        try:
            result = decoder.decode(payload, config_name, allow_sensitive=allow_sensitive)
        except Exception as e:
            logging.debug(f"Decoder {decoder.__class__.__name__} crashed: {e}")
            result = None
        if result:
            decoded_any = True
            # Append result; if decoder flagged sensitive, redact hex unless allowed
            if getattr(decoder, 'sensitive', False) and not allow_sensitive:
                # Remove payload_hex/raw fields
                if isinstance(result.get('data'), dict):
                    result['data'].pop('payload_hex', None)
                    result['data'].pop('raw', None)
            known_devices[short_hash]['detections'].append({
                'time': now,
                'decoder': decoder.__class__.__name__,
                'result': result
            })
            # stop on strong non-generic decoders (keep generic if nothing else matched)
            if decoder.__class__.__name__ != 'Generic':
                break

    # If nothing specifically matched, run Generic to store basic payload length/hex (but respect sensitivity flag)
    if not decoded_any:
        from decoders import GenericDecoder
        gd = GenericDecoder()
        res = gd.decode(payload, config_name, allow_sensitive=allow_sensitive)
        if not allow_sensitive:
            # still include hex for generic entries; that's useful for fingerprinting
            pass
        known_devices[short_hash]['detections'].append({
            'time': now,
            'decoder': 'Generic',
            'result': res
        })

def hashlib_sha1_short(data: bytes, length: int = 8) -> str:
    import hashlib
    return hashlib.sha1(data).hexdigest()[:length]

def print_device_report(device_id: str):
    """Pretty-print an entry from known_devices as JSON to stdout/log."""
    entry = known_devices.get(device_id)
    if not entry:
        logging.warning(f"No device with id {device_id}")
        return
    # Build a sanitized report (mask sensitive fields by default)
    report = {
        'id': entry['id'],
        'first_seen': datetime.fromtimestamp(entry['first_seen'], tz=timezone.utc).isoformat(),
        'last_seen': datetime.fromtimestamp(entry['last_seen'], tz=timezone.utc).isoformat(),
        'count': entry['count'],
        'rssi': entry.get('rssi'),
        'lqi': entry.get('lqi'),
        'freq_mode': entry.get('freq_mode'),
        'detections': []
    }
    for d in entry['detections']:
        det = d['result'].copy()
        # If the decoder result contains raw payload fields, remove them by default
        if isinstance(det.get('data'), dict):
            det['data'] = dict(det['data'])  # shallow copy
            det['data'].pop('payload_hex', None)
            det['data'].pop('raw', None)
        report['detections'].append({'time': datetime.fromtimestamp(d['time'], tz=timezone.utc).isoformat(), 'decoder': d['decoder'], 'result': det})
    print(json.dumps(report, indent=2))

def check_for_gone_devices(scan_start_time: float, interval: int):
    """Remove devices not seen for GONE_TIMEOUT and log them as gone."""
    now = time.time()
    gone = []
    for dev_id, info in list(known_devices.items()):
        if now - info['last_seen'] > GONE_TIMEOUT:
            gone.append(dev_id)
    for dev_id in gone:
        logging.info(f"[GONE] Device {dev_id} last seen at {datetime.fromtimestamp(known_devices[dev_id]['last_seen']).strftime('%Y-%m-%d %H:%M:%S')}; removing.")
        # Optionally print a full report before removing
        print_device_report(dev_id)
        del known_devices[dev_id]

# --- Main loop ---
def main(args):
    try:
        crow = EvilCrow(args.ip)
        logging.info("Connected to Evil Crow.")
    except ConnectionError as e:
        logging.error(f"Fatal: {e}")
        return

    allowed_freqs = [int(f.strip()) for f in args.freqs.split(',') if f.strip()]
    active_scan_configs = [c for c in SCAN_CONFIGS if c['freq'] in allowed_freqs]
    scan_freqs = sorted({c['freq'] for c in active_scan_configs})
    logging.info(f"Scanning frequencies: {', '.join(map(str,scan_freqs))} MHz every {args.interval}s.")

    hunter = args.hunter_radio
    analyst = args.analyst_radio

    while True:
        scan_time = time.time()
        logging.info(f"--- Starting scan at {datetime.fromtimestamp(scan_time).strftime('%H:%M:%S')} ---")

        # Hunt phase: quick RSSI sweep
        active_freq = None
        for freq in scan_freqs:
            rssi = crow.get_rssi(hunter, freq)
            if rssi is not None:
                logging.debug(f"Hunter RSSI at {freq} MHz: {rssi}")
                if rssi > RSSI_THRESHOLD:
                    logging.info(f"Activity detected on {freq} MHz (RSSI {rssi}).")
                    active_freq = freq
                    break

        # Analyze phase
        if active_freq is not None:
            logging.info(f"Analyst tuning to {active_freq} MHz for {ANALYSIS_DURATION}s.")
            analysis_start = time.time()
            while time.time() - analysis_start < ANALYSIS_DURATION:
                for cfg in (c for c in active_scan_configs if c['freq'] == active_freq):
                    crow.set_radio_config(analyst, cfg)
                    payload, rssi, lqi = crow.receive_packet(analyst)
                    if payload:
                        try:
                            process_packet(payload, rssi, lqi, cfg['name'], allow_sensitive=args.allow_sensitive)
                        except Exception as e:
                            logging.debug(f"process_packet error: {e}")
        else:
            logging.debug("No active frequency detected this cycle.")

        # Cleanup and wait
        check_for_gone_devices(scan_time, args.interval)
        logging.info(f"Scan complete. {len(known_devices)} devices tracked.")
        time.sleep(args.interval)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="EvilCrow RF V2 Nmap-like scanner (improved).")
    parser.add_argument('--interval', type=int, default=120, help='Seconds between scans.')
    parser.add_argument('--ip', type=str, default="192.168.4.1", help='Evil Crow IP.')
    parser.add_argument('--freqs', type=str, default="433,915", help='Comma-separated freqs in MHz.')
    parser.add_argument('--allow-sensitive', action='store_true', help='Allow storing/displaying potentially sensitive payloads (credit card, medradio, gps).')
    parser.add_argument('--hunter-radio', type=str, default='A', help='Hunter radio letter (default A).')
    parser.add_argument('--analyst-radio', type=str, default='B', help='Analyst radio letter (default B).')
    args = parser.parse_args()
    try:
        main(args)
    except KeyboardInterrupt:
        logging.info("Exiting on user interrupt.")
