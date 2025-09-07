#!/usr/bin/env python3
import time
import json
import argparse
from datetime import datetime
from cc1101_driver import CC1101
from decoders import DECODER_PIPELINE

# --- Comprehensive Scanner Configurations ---
SCAN_CONFIGS = [
    # 433 MHz Band (Very Common IoT, Remotes)
    {'name': 'OOK_4_8_KB', 'freq': 433},
    {'name': 'GFSK_1_2_KB', 'freq': 433},
    {'name': 'GFSK_38_4_KB', 'freq': 433},
    {'name': 'GFSK_100_KB', 'freq': 433},
    {'name': 'MSK_250_KB', 'freq': 433},

    # 315 MHz Band (Older Remotes, Keyfobs, TPMS)
    {'name': 'OOK_4_8_KB', 'freq': 315},
    {'name': 'GFSK_1_2_KB', 'freq': 315},
    {'name': 'GFSK_38_4_KB', 'freq': 315},

    # 915 MHz Band (Modern IoT, Pagers, GPS Trackers in US)
    {'name': 'GFSK_38_4_KB', 'freq': 915},
    {'name': 'GFSK_100_KB', 'freq': 915},
    {'name': 'MSK_250_KB', 'freq': 915},
    {'name': 'MSK_500_KB', 'freq': 915},
    
    # 868 MHz Band (EU IoT and SRD)
    {'name': 'GFSK_38_4_KB', 'freq': 868},
    {'name': 'GFSK_100_KB', 'freq': 868},
    {'name': 'MSK_250_KB', 'freq': 868},
    
    # 405 MHz MedRadio Band
    {'name': 'FSK_MANCHESTER_MEDRADIO', 'freq': 405},
]
RSSI_THRESHOLD = -90.0  # dBm - more sensitive
ANALYSIS_DURATION = 10  # Seconds to listen on an active frequency

# --- Stateful Device Tracking ---
known_devices = {}

def process_packet(payload, rssi, lqi, config_name):
    """Runs a payload through the decoder pipeline and updates device state."""
    global known_devices
    
    for decoder in DECODER_PIPELINE:
        decoded_data = decoder.decode(payload, config_name)
        if decoded_data:
            device_id = decoded_data['id']
            current_time = time.time()
            
            if device_id not in known_devices:
                # NEW DEVICE FOUND
                print(f"\n[+] NEW DEVICE DETECTED: {device_id}")
                known_devices[device_id] = {
                    'first_seen': current_time,
                    'protocol': decoded_data['protocol'],
                    'last_seen': current_time,
                    'last_rssi': rssi,
                    'last_lqi': lqi, # CHANGED: Added LQI
                    'last_data': decoded_data['data'],
                    'last_config': config_name
                }
                print_device_report(device_id)
            else:
                # Update existing device
                known_devices[device_id]['last_seen'] = current_time
                known_devices[device_id]['last_rssi'] = rssi
                known_devices[device_id]['last_lqi'] = lqi # CHANGED: Added LQI
                if known_devices[device_id]['last_data'] != decoded_data['data']:
                    known_devices[device_id]['last_data'] = decoded_data['data']
                    print(f"[*] Device {device_id} updated with new data.")
                    print_device_report(device_id)

            return device_id
    return None

def print_device_report(device_id):
    """Prints a formatted report for a device."""
    device = known_devices[device_id]
    print("---------------------------------------------------")
    print(f"  ID:         {device_id}")
    print(f"  Protocol:   {device['protocol']}")
    print(f"  Last Seen:  {datetime.fromtimestamp(device['last_seen']).strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  RSSI:       {device['last_rssi']:.1f} dBm")
    print(f"  LQI:        {device['last_lqi']}") # CHANGED: Added LQI
    print(f"  Radio Cfg:  {device['last_config']}")
    print(f"  Data:       {json.dumps(device['data'])}")
    print("---------------------------------------------------\n")

def hunt(radio):
    """
    CHANGED: This function now uses the driver's dedicated get_rssi_dbm() method
    for a much more reliable and faster signal hunt.
    """
    print("--- HUNTING ---")
    scan_freqs = sorted(list(set(cfg['freq'] for cfg in SCAN_CONFIGS)))
    
    for freq in scan_freqs:
        radio.set_frequency_band(freq)
        rssi = radio.get_rssi_dbm()
        if rssi and rssi > RSSI_THRESHOLD:
            print(f"[+] Activity detected at {freq} MHz (RSSI: {rssi:.1f} dBm)")
            return freq
    
    print("[-] No signals found.")
    return None
    
def analyze(radio, target_freq):
    """Analyzes a signal on a specific frequency for a set duration."""
    print(f"--- ANALYZING {target_freq} MHz for {ANALYSIS_DURATION} seconds ---")
    seen_in_this_analysis = set()
    start_time = time.time()
    
    while time.time() - start_time < ANALYSIS_DURATION:
        for config in SCAN_CONFIGS:
            if config['freq'] != target_freq: continue
            
            try:
                radio.apply_config_profile(config['name'])
                radio.set_frequency_band(config['freq'])
                radio.set_packet_handling_mode() # CHANGED: Explicitly set packet mode
                
                # CHANGED: Unpack the new LQI value from the driver's response
                payload, rssi, lqi = radio.receive_packet(timeout_ms=100)
                
                if payload:
                    # CHANGED: Pass LQI to the processing function
                    device_id = process_packet(payload, rssi, lqi, config['name'])
                    if device_id: seen_in_this_analysis.add(device_id)
            except Exception as e:
                print(f"Error during analysis: {e}")
                
    return seen_in_this_analysis

def check_for_gone_devices(scan_start_time, interval):
    """Checks if any known devices have not been seen for a while."""
    global known_devices
    timeout = interval * 2.5
    for device_id in list(known_devices.keys()):
        if scan_start_time - known_devices[device_id]['last_seen'] > timeout:
            print(f"[-] DEVICE GONE: {device_id} (Last seen {int(scan_start_time - known_devices[device_id]['last_seen'])}s ago)")
            del known_devices[device_id]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Nmap-like scanner for the Sub-GHz spectrum using a CC1101.")
    parser.add_argument('--interval', type=int, default=120, help='Time in seconds between scans.')
    # CHANGED: Added GPIO chip and CS pin arguments for flexibility
    parser.add_argument('--gpiochip', type=str, default='gpiochip4', help='GPIO chip for CSn pin (e.g., gpiochip0 on RPi 4, gpiochip4 on RPi 5/Zero2W).')
    parser.add_argument('--cspin', type=int, default=8, help='GPIO pin number for CSn (CE0 is BCM pin 8).')
    args = parser.parse_args()

    try:
        # CHANGED: Updated constructor call
        radio = CC1101(chip_name=args.gpiochip, cs_pin=args.cspin)
        radio.reset()
        if radio.get_version() != 0x14:
            raise IOError("CC1101 not found or version mismatch!")
        print("RF Nmap Scanner Initialized. Press Ctrl+C to exit.")
        print(f"Scanning every {args.interval} seconds.")

        while True:
            scan_time = time.time()
            print(f"\n--- Starting Scan @ {datetime.fromtimestamp(scan_time).strftime('%H:%M:%S')} ---")
            
            seen_this_scan = set()
            active_freq = hunt(radio)

            if active_freq:
                seen_in_analysis = analyze(radio, active_freq)
                seen_this_scan.update(seen_in_analysis)
            
            check_for_gone_devices(scan_time, args.interval)
            
            print(f"--- Scan complete. {len(known_devices)} devices currently tracked. Waiting for next interval. ---")
            time.sleep(args.interval)

    except IOError as e:
        print(f"\n[FATAL] A hardware error occurred: {e}")
    except KeyboardInterrupt:
        print("\nExiting.")

