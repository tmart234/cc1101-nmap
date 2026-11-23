import random
import unittest

from cc1101nmap import bits as B
from cc1101nmap import decoders as D
from cc1101nmap import encoders as E
from cc1101nmap.obs import Packet, PulseCapture
from cc1101nmap.pulses import parse_stock_log, summarize


class TestChecksums(unittest.TestCase):
    def test_crc16_catalogue_check_values(self):
        # CRC-16/UMTS (poly 0x8005) and CRC-16/EN-13757 (poly 0x3D65, xorout 0xFFFF)
        self.assertEqual(B.crc16(b"123456789", 0x8005), 0xFEE8)
        self.assertEqual(B.crc16(b"123456789", 0x3D65) ^ 0xFFFF, 0xC2B7)

    def test_manchester(self):
        self.assertEqual(B.manchester_decode("0110100101"), "10011")
        self.assertEqual(B.manchester_decode("011100"), "1")  # stops at invalid "11"


class TestRealDevicePackets(unittest.TestCase):
    """Packets captured from real devices, as published in protocol docs."""

    def test_lacrosse_tx29_example(self):
        # aa 2d d4 | 92 84 48 6a ec  -> TX29-IT, id 10, 4.8 C, no humidity sensor
        d = D.LaCrosseITPlusDecoder().decode(bytes.fromhex("9284486aec"), 868.3)
        self.assertIsNotNone(d)
        self.assertEqual(d.fields["id"], 10)
        self.assertEqual(d.fields["temperature_C"], 4.8)
        self.assertNotIn("humidity_pct", d.fields)

    def test_fineoffset_wh24_example(self):
        # documented reading: id 191, 11.8 C, 78 %, wind dir 266 deg, 74 rain tips
        data = bytes.fromhex("24bf0ae2064e0802004a00010000008f07")
        d = D.FineOffsetWH24Decoder().decode(data, 868.3)
        self.assertIsNotNone(d)
        self.assertEqual(d.fields["id"], 191)
        self.assertEqual(d.fields["temperature_C"], 11.8)
        self.assertEqual(d.fields["humidity_pct"], 78)
        self.assertEqual(d.fields["wind_dir_deg"], 266)

    def test_wh31e_example_payloads(self):
        for hexs in ("30c381d55c2acf0835442c", "3035c22f3c0fa10752299f", "30c9a21e400c050734c6b1"):
            d = D.AmbientWH31EDecoder().decode(bytes.fromhex(hexs), 915.0)
            self.assertIsNotNone(d, hexs)
            self.assertTrue(-40 < d.fields["temperature_C"] < 60)
        d = D.AmbientWH31EDecoder().decode(bytes.fromhex("30c381d55c2acf0835442c"), 915.0)
        self.assertEqual(d.fields["temperature_C"], 6.9)
        self.assertEqual(d.fields["humidity_pct"], 92)
        self.assertEqual(d.fields["channel"], 1)

    def test_corrupted_packets_rejected(self):
        self.assertIsNone(D.LaCrosseITPlusDecoder().decode(bytes.fromhex("9284486aed"), 868.3))
        self.assertIsNone(D.FineOffsetWH24Decoder().decode(bytes.fromhex("24bf0ae2064f0802004a00010000008f07"), 868.3))


class TestRoundTrip(unittest.TestCase):
    def setUp(self):
        self.rng = random.Random(7)

    def cap(self, pulses, freq=433.92):
        return PulseCapture(pulses, freq, "OOK")

    def test_acurite_tower(self):
        res = D.decode_capture(self.cap(E.acurite_tower(0x1A2B & 0x3FFF, "B", 21.4, 47, rng=self.rng)))
        self.assertEqual(len(res), 1)
        f = res[0].fields
        self.assertEqual((f["channel"], f["temperature_C"], f["humidity_pct"]), ("B", 21.4, 47))

    def test_tx141th(self):
        res = D.decode_capture(self.cap(E.lacrosse_tx141th(0x5C, 1, -3.2, 66, rng=self.rng)))
        self.assertEqual([r.model for r in res], ["LaCrosse-TX141TH"])
        self.assertEqual(res[0].fields["temperature_C"], -3.2)

    def test_honeywell(self):
        for ch in (8, 2):
            res = D.decode_capture(self.cap(E.honeywell(0xA1B2C, ch, contact_open=True, rng=self.rng), 345.0))
            self.assertEqual(len(res), 1, ch)
            self.assertEqual(res[0].fields["id"], "a1b2c")
            self.assertEqual(res[0].fields["state"], "open")

    def test_honeywell_survives_lost_edge(self):
        pulses = E.honeywell(0x12345, 8, rng=self.rng)
        res = D.decode_capture(self.cap(pulses[1:], 345.0))   # mark/space swapped
        self.assertEqual(len(res), 1)

    def test_ev1527(self):
        res = D.decode_capture(self.cap(E.ev1527(0xA5C3E8, t_us=350, rng=self.rng)))
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].fields["code"], "A5C3E8")
        self.assertIn("code", res[0].sensitive_fields)

    def test_ev1527_needs_repeats(self):
        self.assertEqual(D.decode_capture(self.cap(E.ev1527(0xA5C3E8, repeats=1))), [])

    def test_wmbus_t1_and_c1(self):
        for data in (E.wmbus_t1("KAM", "12345678", 0x1B, 0x16), E.wmbus_c1a("KAM", "12345678", 0x1B, 0x16)):
            res = D.decode_packet(Packet(data, 868.95, "543d"))
            self.assertEqual(len(res), 1)
            f = res[0].fields
            self.assertEqual((f["manufacturer"], f["serial"], f["device_type"]),
                             ("Kamstrup", "12345678", "Cold water meter"))

    def test_packet_encoders(self):
        for data, model in ((E.lacrosse_itplus(33, 19.7, 55), "LaCrosse-IT+"),
                            (E.fineoffset_wh65(77, -5.5, 91), "FineOffset-WH24/WH65"),
                            (E.ambient_wh31e(0xC3, 3, 22.0, 40), "AmbientWeather-WH31E")):
            res = D.decode_packet(Packet(data, 915.0, "2dd4"))
            self.assertEqual([r.model for r in res], [model])

    def test_noise_is_not_a_device(self):
        rng = random.Random(1)
        for _ in range(200):
            noise = [rng.randint(100, 3000) for _ in range(rng.randint(40, 600))]
            self.assertEqual(D.decode_capture(self.cap(noise)), [])
            self.assertFalse(summarize(noise).structured)


class TestStockLog(unittest.TestCase):
    def test_parse_skips_corrected_block(self):
        raw = ",".join(str(x) for x in [150000] + E.ev1527(0x123456, repeats=3))
        log = ("-------------------------------------------------------\n\nCount=150\n" + raw + ",\n\n"
               "0101 [Pause: 9000 samples]\nSamples/Symbol: 320\n\nRawdata corrected:\nCount=99\n"
               "320,960,320,\n-------------------------------------------------------\n")
        caps = parse_stock_log(log)
        self.assertEqual(len(caps), 1)
        self.assertEqual(caps[0][0], 320)    # leading idle sample dropped; first bit 0 = short mark
        res = D.decode_capture(PulseCapture(caps[0], 433.92))
        self.assertEqual(res[0].fields["code"], "123456")


if __name__ == "__main__":
    unittest.main()
