software-tunable CC1101 RF module for the Raspberry Pi

- Core Transceiver: Texas Instruments CC1101.
- Supported Frequency Bands: 315MHz, 433MHz, 868MHz, and 915MHz.
- Software-Tunable Front-End: A Skyworks SKY13370-374LF SP4T RF switch programmatically selects one of four dedicated, impedance-matched RF networks.
- Datasheet-Correct RF Networks: Each of the four matching networks (balun and filter) uses the exact inductor and capacitor values specified in Table 21 of the CC1101 datasheet for optimal performance in that band.
- Power and Signal Integrity: The design includes robust power supply decoupling for all ICs, a ferrite bead for input noise filtering, and series resistors on the SPI lines for GPIO protection.
- Host Interface: A standard 2x5 (10-pin) 2.54mm header provides a clean connection to the Raspberry Pi GPIO for power, SPI, RF switch control, and two GDO interrupt lines (GDO0, GDO2) for event-driven signaling.
- Robust Switch Control: Pull-down resistors are included on the RF switch control lines to ensure the switch is in a known-good state during system boot-up.
- Antenna Connector: A standard 50-Ohm SMA connector is provided for use with a single broadband antenna.
