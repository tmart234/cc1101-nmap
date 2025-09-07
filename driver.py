import spidev
import time
import gpiod

# --- Register and Command Definitions (from Datasheet Section 29) ---
SRES, SRX, STX, SIDLE, SFRX, SFTX = 0x30, 0x34, 0x35, 0x36, 0x3A, 0x3B
WRITE_BURST, READ_SINGLE, READ_BURST = 0x40, 0x80, 0xC0
PKTCTRL1, PKTCTRL0, CHANNR, FREQ2, FREQ1, FREQ0 = 0x07, 0x08, 0x0A, 0x0D, 0x0E, 0x0F
MDMCFG2, PKTLEN = 0x12, 0x06
PATABLE, VERSION, RSSI, MARCSTATE, RXBYTES = 0x3E, 0xF1, 0xF4, 0xF5, 0xFB
RXFIFO = 0x3F

# --- Pre-calculated Register Configuration Profiles ---
CONFIG_PROFILES = {
    'GFSK_1_2_KB': bytes([0x07, 0x2E, 0x80, 0x07, 0x57, 0x43, 0x3E, 0x0E, 0x45, 0xFF, 0x00, 0x08, 0x00, 0x21, 0x65, 0x6A, 0xF5, 0x83, 0x13, 0xA0, 0xF8, 0x15, 0x07, 0x0C, 0x18, 0x16, 0x6C, 0x03, 0x40, 0x91, 0x02, 0x26, 0x09, 0x56, 0x17, 0xA9, 0x0A, 0x00, 0x11, 0x41, 0x00, 0x59, 0x7F, 0x3F, 0x81, 0x3F, 0x0B]),
    'GFSK_38_4_KB': bytes([0x07, 0x2E, 0x80, 0x07, 0x57, 0x43, 0x3E, 0x0E, 0x45, 0xFF, 0x00, 0x06, 0x00, 0x21, 0x65, 0x6A, 0xCA, 0x83, 0x13, 0xA0, 0xF8, 0x34, 0x07, 0x0C, 0x18, 0x16, 0x6C, 0x43, 0x40, 0x91, 0x02, 0x26, 0x09, 0x56, 0x17, 0xA9, 0x0A, 0x00, 0x11, 0x41, 0x00, 0x59, 0x7F, 0x3F, 0x81, 0x3F, 0x0B]),
    'GFSK_100_KB': bytes([0x07, 0x2E, 0x80, 0x07, 0x57, 0x43, 0x3E, 0x0E, 0x45, 0xFF, 0x00, 0x08, 0x00, 0x21, 0x65, 0x6A, 0x5B, 0xF8, 0x13, 0xA0, 0xF8, 0x47, 0x07, 0x0C, 0x18, 0x1D, 0x1C, 0xC7, 0x00, 0xB2, 0x02, 0x26, 0x09, 0xB6, 0x17, 0xEA, 0x0A, 0x00, 0x11, 0x41, 0x00, 0x59, 0x7F, 0x3F, 0x81, 0x3F, 0x0B]),
    'MSK_250_KB': bytes([0x07, 0x2E, 0x80, 0x07, 0x57, 0x43, 0x3E, 0x0E, 0x45, 0xFF, 0x00, 0x0B, 0x00, 0x21, 0x65, 0x6A, 0x2D, 0x3B, 0x73, 0xA0, 0xF8, 0x00, 0x07, 0x0C, 0x18, 0x1D, 0x1C, 0xC7, 0x00, 0xB2, 0x02, 0x26, 0x09, 0xB6, 0x17, 0xEA, 0x0A, 0x00, 0x11, 41, 0x00, 0x59, 0x7F, 0x3F, 0x81, 0x3F, 0x0B]),
    'MSK_500_KB': bytes([0x07, 0x2E, 0x80, 0x07, 0x57, 0x43, 0x3E, 0x0E, 0x45, 0xFF, 0x00, 0x0C, 0x00, 0x21, 0x65, 0x6A, 0x0E, 0x3B, 0x73, 0xA0, 0xF8, 0x00, 0x07, 0x0C, 0x18, 0x1D, 0x1C, 0xC7, 0x40, 0xB2, 0x02, 0x26, 0x09, 0xB6, 0x17, 0xEA, 0x0A, 0x00, 0x19, 0x41, 0x00, 0x59, 0x7F, 0x3F, 0x81, 0x3F, 0x0B]),
    'OOK_4_8_KB': bytes([0x06, 0x2E, 0x06, 0x47, 0x57, 0x43, 0xFF, 0x04, 0x05, 0x00, 0x00, 0x06, 0x00, 0x21, 0x65, 0x6A, 0x87, 0x83, 0x3B, 0x22, 0xF8, 0x15, 0x07, 0x30, 0x18, 0x14, 0x6C, 0x07, 0x00, 0x92, 0x87, 0x6B, 0xFB, 0x56, 0x17, 0xE9, 0x2A, 0x00, 0x1F, 0x41, 0x00, 0x59, 0x7F, 0x3F, 0x81, 0x35, 0x09]),
    'FSK_MANCHESTER_MEDRADIO': bytes([0x07, 0x2E, 0x80, 0x07, 0x57, 0x43, 0x3E, 0x0E, 0x45, 0xFF, 0x00, 0x06, 0x00, 0x21, 0x65, 0x6A, 0xCA, 0x83, 0x1B, 0xA0, 0xF8, 0x34, 0x07, 0x0C, 0x18, 0x16, 0x6C, 0x43, 0x40, 0x91, 0x02, 0x26, 0x09, 0x56, 0x17, 0xA9, 0x0A, 0x00, 0x11, 0x41, 0x00, 0x59, 0x7F, 0x3F, 0x81, 0x3F, 0x0B]),
}

FREQ_TABLE = {315: (0x0C, 0x1D, 0x89), 405: (0x0F, 0x9A, 0x2B), 433: (0x10, 0xB0, 0x71), 868: (0x21, 0x65, 0x6A), 915: (0x23, 0x31, 0x3B)}
PATABLE_TABLE = {315: b'\x17\x1d\x26\x69\x51\x86\xcc\xc3', 405: b'\x6c\x1c\x06\x3a\x51\x85\xc8\xc0', 433: b'\x6c\x1c\x06\x3a\x51\x85\xc8\xc0', 868: b'\x03\x17\x1d\x26\x50\x86\xcd\xc0', 915: b'\x0b\x1b\x6d\x67\x50\x85\xc9\xc1'}

class CC1101:
    """A Python driver for the TI CC1101 radio transceiver, enhanced for reliability."""
    def __init__(self, bus=0, device=0, speed=5000000, chip_name='gpiochip4', cs_pin=8):
        self.spi = spidev.SpiDev()
        try:
            self.spi.open(bus, device)
            self.spi.max_speed_hz = speed
            # Use gpiod for explicit CSn control, bypassing spidev's limitations
            self.chip = gpiod.Chip(chip_name)
            self.cs_line = self.chip.get_line(cs_pin)
            self.cs_line.request(consumer="cc1101", type=gpiod.Line.DIRECTION_OUTPUT, default_vals=[1])
        except FileNotFoundError:
            raise IOError("SPI device or GPIO chip not found. Ensure SPI is enabled and chip name is correct.")
        
    def _transfer(self, data):
        """Manually control CSn for robust SPI communication."""
        self.cs_line.set_value(0)
        time.sleep(0.00001)
        response = self.spi.xfer2(data)
        self.cs_line.set_value(1)
        return response

    def _send_strobe(self, command):
        self._transfer([command])

    def _read_register(self, address):
        return self._transfer([address | READ_SINGLE, 0x00])[1]

    def _write_register(self, address, value):
        self._transfer([address, value])
        
    def _write_burst(self, start_address, data):
        self._transfer([start_address | WRITE_BURST] + list(data))

    def _wait_for_chip_ready(self, timeout_s=1):
        """
        Polls the SO line until chip is ready, as per datasheet Section 10.1, Page 31.
        The first byte received after CSn goes low is the status byte. The CHIP_RDYn
        signal (MSB) must be low.
        """
        start = time.time()
        while time.time() - start < timeout_s:
            self.cs_line.set_value(0)
            status = self.spi.xfer2([0x3D, 0x00])[0] # SNOP to get status
            self.cs_line.set_value(1)
            if not (status & 0x80): # Check if CHIP_RDYn bit (MSB) is 0
                return
            time.sleep(0.001)
        raise IOError("Timeout waiting for CC1101 chip ready signal.")

    def reset(self):
        """
        Performs a full manual reset sequence as recommended by datasheet Section 19.1.2, Page 51.
        """
        self.cs_line.set_value(0)
        time.sleep(0.00001)
        self.cs_line.set_value(1)
        time.sleep(0.00004)
        
        self._send_strobe(SRES)
        self._wait_for_chip_ready()

    def get_version(self):
        return self._read_register(VERSION)

    def sidle(self):
        self._send_strobe(SIDLE)
        while self._read_register(MARCSTATE) != 0x01: time.sleep(0.001)
            
    def apply_config_profile(self, profile_name):
        if profile_name not in CONFIG_PROFILES:
            raise ValueError(f"Profile '{profile_name}' not found.")
        self.sidle()
        self._write_burst(0x00, CONFIG_PROFILES[profile_name])

    def set_frequency_band(self, freq_mhz):
        if freq_mhz not in FREQ_TABLE:
            raise ValueError(f"Frequency {freq_mhz} MHz not supported.")
        self.sidle()
        self._write_register(FREQ2, FREQ_TABLE[freq_mhz][0])
        self._write_register(FREQ1, FREQ_TABLE[freq_mhz][1])
        self._write_register(FREQ0, FREQ_TABLE[freq_mhz][2])
        self._write_burst(PATABLE, PATABLE_TABLE[freq_mhz])
        
    def set_packet_handling_mode(self, crc_en=True, append_status=True, var_len=True):
        """
        Explicitly configures key packet handling registers.
        See PKTCTRL0 (p. 74) and PKTCTRL1 (p. 73).
        """
        pktctrl0 = 0x00
        if var_len: pktctrl0 |= 0x01
        if crc_en: pktctrl0 |= 0x04
        self._write_register(PKTCTRL0, pktctrl0)

        pktctrl1 = 0x00
        if append_status: pktctrl1 |= 0x04
        self._write_register(PKTCTRL1, pktctrl1)

    def receive(self):
        self.sidle()
        self._send_strobe(SRX)
        
    def get_rssi_dbm(self):
        """Reads the RSSI status register directly, as per datasheet Section 17.3, p. 44."""
        self.receive()
        time.sleep(0.01) # Allow AGC to settle
        rssi_raw = self._read_register(RSSI)
        return (rssi_raw - 256) / 2 - 74 if rssi_raw >= 128 else rssi_raw / 2 - 74

    def receive_packet(self, timeout_ms=500):
        """
        Listens for a packet and returns it.
        Returns a tuple of (payload_bytes, rssi_dbm, lqi) or (None, None, None).
        """
        self.receive()
        start_time = time.time()
        while (time.time() - start_time) * 1000 < timeout_ms:
            bytes_in_fifo = self._read_register(RXBYTES) & 0x7F
            if bytes_in_fifo > 0:
                # Per datasheet, first byte in FIFO is length
                packet_length = self._read_register(RXFIFO | READ_SINGLE)
                
                # Check for plausible length and that we have enough bytes
                if 0 < packet_length <= 64 and bytes_in_fifo >= packet_length + 2:
                    data = self._transfer([RXFIFO | READ_BURST] * (packet_length + 2))
                    
                    payload = bytes(data[1 : packet_length + 1])
                    rssi_raw = data[packet_length + 1]
                    lqi_raw = data[packet_length + 2]
                    
                    self.sidle()
                    self._send_strobe(SFRX)
                    
                    crc_ok = (lqi_raw & 0x80) != 0
                    if crc_ok:
                        rssi_dbm = (rssi_raw - 256) / 2 - 74 if rssi_raw >= 128 else rssi_raw / 2 - 74
                        lqi = lqi_raw & 0x7F # LQI is bits 0-6
                        return payload, rssi_dbm, lqi
            time.sleep(0.005)
            
        self.sidle()
        self._send_strobe(SFRX)
        return None, None, None

