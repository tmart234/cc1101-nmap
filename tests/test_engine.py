import unittest

from cc1101nmap.backends import Sink
from cc1101nmap.catalog import Catalog, derived_input, load_local_freqs
from cc1101nmap.engine import Engine, estimate_distance_m, proximity
from cc1101nmap.obs import SpectrumFrame
from cc1101nmap.sim import SimBackend


def run_sim(region, seconds, seed=4):
    cat = Catalog.load(region=region, extended=(region == "EU"))
    clock = {"t": 0.0}
    eng = Engine(cat, clock=lambda: clock["t"])
    sim = SimBackend(Sink(eng), cat, seed=seed)
    sim.t0 = 0.0
    for t in range(seconds):
        clock["t"] = float(t)
        sim.step(float(t))
        if t % 10 == 0:
            eng.tick()
    return eng


class TestDistance(unittest.TestCase):
    def test_monotonic_and_plausible(self):
        near = estimate_distance_m(-40, 37, 810)
        far = estimate_distance_m(-90, 37, 810)
        self.assertLess(near, 100)
        self.assertGreater(far, 1500)
        self.assertEqual(proximity(-40, 37, 810, 2.7)["bucket"], "nearby")
        self.assertEqual(proximity(-100, 37, 810, 2.7)["bucket"], "distant")


class TestSpectrum(unittest.TestCase):
    def setUp(self):
        self.cat = Catalog.load(region="US")
        self.t = 0.0
        self.eng = Engine(self.cat, clock=lambda: self.t)
        self.freqs = [806.0 + i * 0.1 for i in range(30)] + [851.0 + i * 0.1 for i in range(30)]

    def frame(self, hot=None):
        peak = [-98.0] * len(self.freqs)
        for f, level in (hot or {}).items():
            peak[min(range(len(self.freqs)), key=lambda i: abs(self.freqs[i] - f))] = level
        return SpectrumFrame(self.freqs, peak, [p - 3 for p in peak], [102.0] * len(self.freqs), 1, self.t)

    def test_burst_on_mobile_band_alerts_with_distance(self):
        for _ in range(5):
            self.t += 1
            self.eng.ingest_spectrum(self.frame())
        self.t += 1
        self.eng.ingest_spectrum(self.frame({806.5: -45}))
        alerts = [e for e in self.eng.events if e["level"] == "alert"]
        self.assertEqual(len(alerts), 1)
        self.assertIn("NPSPAC", alerts[0]["message"])
        item = next(i for i in self.eng.snapshot()["near"] if i["entry_id"] == "ps-800-npspac-mobile")
        self.assertTrue(item["active"])
        self.assertIn(item["proximity"]["bucket"], ("very_close", "nearby"))

    def test_weak_or_absent_signal_is_quiet(self):
        for _ in range(20):
            self.t += 1
            self.eng.ingest_spectrum(self.frame({806.5: -92}))
        self.assertEqual([e for e in self.eng.events if e["kind"] in ("alert", "rf_activity")], [])

    def test_tower_is_infrastructure_not_nearby(self):
        for _ in range(40):
            self.t += 1
            self.eng.ingest_spectrum(self.frame({851.5: -60}))
        snap = self.eng.snapshot()
        self.assertTrue(any(i["entry_id"] == "ps-800-base" for i in snap["infrastructure"]))
        self.assertFalse(any(i["entry_id"] == "ps-800-base" for i in snap["near"]))
        self.assertEqual([e for e in self.eng.events if e["level"] == "alert"], [])


class TestSimulatedNeighbourhood(unittest.TestCase):
    def test_us(self):
        eng = run_sim("US", 900)
        snap = eng.snapshot()
        models = {i["fields"].get("model") for i in snap["near"] if i["kind"] == "device"}
        for m in ("Acurite-Tower", "LaCrosse-TX141TH", "FineOffset-WH24/WH65", "Honeywell/Ademco security sensor"):
            self.assertIn(m, models)
        self.assertTrue(any(e["level"] == "alert" for e in eng.events))
        self.assertFalse(any(e["kind"] == "device_gone" for e in eng.events))
        ev = next(i for i in snap["near"] if i["entry_id"] == "fixed-code-remote")
        self.assertEqual(ev["fields"]["code"], "(redacted)")

    def test_eu(self):
        eng = run_sim("EU", 900)
        near = eng.snapshot()["near"]
        self.assertTrue(any(i["fields"].get("manufacturer") == "Kamstrup" for i in near))
        self.assertTrue(any(i["entry_id"] == "tetra-eu-ul" for i in near))


class TestLocalFreqs(unittest.TestCase):
    def test_derived_inputs(self):
        self.assertEqual(derived_input(851.0125), 806.0125)
        self.assertEqual(derived_input(772.5), 802.5)
        self.assertEqual(derived_input(460.125), 465.125)
        self.assertIsNone(derived_input(462.5625, repeater=False))     # FRS is simplex
        self.assertIsNone(derived_input(155.0))

    def test_csv(self):
        import os, tempfile
        path = os.path.join(tempfile.mkdtemp(), "local.csv")
        with open(path, "w") as fh:
            fh.write("freq_mhz,label,category\n853.4125,Springfield PD Dispatch,Law Dispatch\n"
                     "462.5625,Neighbourhood watch FRS,\n")
        entries = load_local_freqs(path)
        ids = {e.id: e for e in entries}
        self.assertEqual(ids["local-0-in"].service, "police")
        self.assertAlmostEqual(ids["local-0-in"].ranges_mhz[0][0], 808.40625, places=4)
        self.assertTrue(ids["local-0-in"].alert)
        self.assertEqual(ids["local-0"].role, "base")
        cat = Catalog.load(region="US", local_freqs=path)
        self.assertEqual(cat.best(808.4125).id, "local-0-in")   # local list beats generic band


class TestSensitiveAndBudget(unittest.TestCase):
    def test_sweep_plan_fits_under_600_for_all_configs(self):
        for region in ("US", "EU"):
            for extended in (False, True):
                for allow_sensitive in (False, True):
                    cat = Catalog.load(region=region, extended=extended, allow_sensitive=allow_sensitive)
                    full = cat.sweep_plan(2000)
                    capped = cat.sweep_plan(600)
                    self.assertEqual(len(capped), len(full), (region, extended, allow_sensitive))
                    self.assertLessEqual(sum(s.points for s in capped), 600)

    def test_sensitive_bands_and_profiles_are_gated_and_swept(self):
        for region, expected_energy, expected_rx in (
            ("US", {"medradio", "cospas-sarsat", "ems-med-base-us", "ems-med-mobile-us"},
             {"ook-916-minimed", "fsk-433-omnipod"}),
            ("EU", {"medradio", "cospas-sarsat", "social-alarm-eu", "eu-safety-alarms"},
             {"ook-868-minimed", "fsk-433-omnipod"}),
        ):
            cat_off = Catalog.load(region=region, extended=True, allow_sensitive=False)
            self.assertEqual([e for e in cat_off.entries if e.sensitive], [])
            self.assertEqual([p for p in cat_off.rx_profiles if p.get("sensitive")], [])

            cat_on = Catalog.load(region=region, extended=True, allow_sensitive=True)
            rx_ids = {p["id"] for p in cat_on.rx_profiles if p.get("sensitive")}
            self.assertEqual(rx_ids, expected_rx)
            freqs = [f for s in cat_on.sweep_plan(600) for f in s.freqs()]
            covered = {cat_on.best(f, ("energy",)).id for f in freqs if cat_on.best(f, ("energy",))}
            self.assertTrue(expected_energy.issubset(covered), (region, expected_energy - covered))

    def test_sensitive_decoded_devices_hidden_and_fields_redacted_by_default(self):
        from cc1101nmap import encoders as E
        from cc1101nmap.obs import Packet, PulseCapture

        cat_off = Catalog.load(region="US", allow_sensitive=False)
        eng_off = Engine(cat_off, allow_sensitive=False, clock=lambda: 100.0)
        # Medical packets must be dropped completely unless allow_sensitive=True
        eng_off.ingest_packet(Packet(E.minimed(0xA7, "597055", b"\x04\x00", pad_len=60), 916.5, "ff00", 100.0, -70))
        eng_off.ingest_packet(Packet(E.omnipod("1f014829", "POD", 14), 433.91, "54c3", 100.0, -72))
        self.assertEqual(eng_off.snapshot()["near"], [])
        self.assertEqual(list(eng_off.events), [])

        # MegaCode and Schrader TPMS decode by default, with replayable/tracking fields redacted
        eng_off.ingest_capture(PulseCapture(E.megacode(3, 17316, 1), 318.0, "OOK", 100.0, -70))
        eng_off.ingest_capture(PulseCapture(E.schrader_tpms(0x6703A38, 225.0, 23), 315.0, "OOK", 100.0, -75))
        near = {i["entry_id"]: i for i in eng_off.snapshot()["near"]}
        self.assertEqual(near["gate-318"]["fields"]["code"], "(redacted)")
        self.assertEqual(near["gate-318"]["fields"]["serial"], "(redacted)")
        self.assertEqual(near["gate-318"]["fields"]["facility"], "(redacted)")
        self.assertEqual(near["tpms-schrader"]["fields"]["id"], "(redacted)")
        for ev in eng_off.events:
            self.assertNotIn("9A1D21", ev["message"])
            self.assertNotIn("6703A38", ev["message"])

        # With allow_sensitive=True, medical devices appear and fields are visible
        cat_on = Catalog.load(region="US", allow_sensitive=True)
        eng_on = Engine(cat_on, allow_sensitive=True, clock=lambda: 100.0)
        eng_on.ingest_packet(Packet(E.minimed(0xA7, "597055", b"\x04\x00", pad_len=60), 916.5, "ff00", 100.0, -70))
        eng_on.ingest_packet(Packet(E.omnipod("1f014829", "POD", 14), 433.91, "54c3", 100.0, -72))
        eng_on.ingest_capture(PulseCapture(E.schrader_tpms(0x6703A38, 225.0, 23), 315.0, "OOK", 100.0, -75))
        near_on = {i["entry_id"]: i for i in eng_on.snapshot()["near"]}
        self.assertEqual(near_on["minimed-pump"]["fields"]["serial"], "597055")
        self.assertEqual(near_on["omnipod-pump"]["fields"]["pod_address"], "1f014829")
        self.assertEqual(near_on["tpms-schrader"]["fields"]["id"], "6703A38")


if __name__ == "__main__":
    unittest.main()
