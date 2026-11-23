"""Backends against fake devices, and the dashboard API.

FakeStock mimics the routes of the stock Evil Crow RF V2 firmware
(firmware/firmware/firmware.ino upstream); FakeNmap mimics the companion
firmware API in firmware/cc1101_nmap. Together they pin the wire formats.
"""
import json
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from cc1101nmap import encoders as E
from cc1101nmap.backends import NmapFirmware, Sink, StockEvilCrow
from cc1101nmap.catalog import Catalog
from cc1101nmap.engine import Engine
from cc1101nmap.web import WebServer

SEP = "-------------------------------------------------------\n"


def stock_log_block(pulses):
    raw = ",".join(str(p) for p in [150000] + pulses) + ","
    return (SEP + "\nCount=%d\n%s\n\n0101\nSamples/Symbol: 320\n\nRawdata corrected:\nCount=3\n320,960,320,\n\n"
            % (len(pulses) + 1, raw) + SEP)


class FakeDevice:
    def __init__(self, routes):
        dev = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _reply(self, method):
                url = urlparse(self.path)
                n = int(self.headers.get("Content-Length") or 0)
                form = {k: v[0] for k, v in parse_qs(self.rfile.read(n).decode()).items()} if n else {}
                q = {k: v[0] for k, v in parse_qs(url.query).items()}
                dev.calls.append((method, url.path, form or q))
                fn = routes.get((method, url.path))
                if not fn:
                    self.send_response(404)
                    self.end_headers()
                    return
                body, ctype = fn(form or q)
                data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._reply("GET")

            def do_POST(self):
                self._reply("POST")

        self.calls = []
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.host = "127.0.0.1:%d" % self.httpd.server_address[1]

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def wait_for(cond, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


class TestStockBackend(unittest.TestCase):
    def test_reads_and_decodes_stock_logs(self):
        log = {"text": ""}

        def setrx(form):
            log["text"] += stock_log_block(E.ev1527(0x9A3F12, 330))
            return {"status": "success"}, "application/json"
        dev = FakeDevice({
            ("GET", "/connectioncheck"): lambda q: ({"status": "ok"}, "application/json"),
            ("GET", "/stats"): lambda q: ({"uptime": 5, "sdcard_present": True}, "application/json"),
            ("POST", "/stoprx"): lambda f: ({"status": "success"}, "application/json"),
            ("POST", "/setrx"): setrx,
            ("GET", "/logs"): lambda q: (log["text"], "text/plain"),
            ("POST", "/delete"): lambda f: (log.update(text="") or {"status": "deleted"}, "application/json"),
        })
        cat = Catalog.load(region="US")
        eng = Engine(cat)
        be = StockEvilCrow(Sink(eng), cat, dev.host, poll_s=0.1)
        be.start()
        try:
            self.assertTrue(wait_for(lambda: any(t.entry and t.entry.id == "fixed-code-remote"
                                                 for t in eng.tracks.values())))
            setrx = next(c for c in dev.calls if c[1] == "/setrx")[2]
            self.assertEqual((setrx["module"], setrx["mod"], setrx["frequency"]), ("1", "2", "433.920"))
            self.assertIn("configmodule", setrx)
            self.assertLess(dev.calls.index(next(c for c in dev.calls if c[1] == "/stoprx")),
                            dev.calls.index(next(c for c in dev.calls if c[1] == "/setrx")))
        finally:
            be.stop()
            dev.close()


class TestNmapBackend(unittest.TestCase):
    def test_plan_spectrum_and_packets(self):
        state = {"plan": [], "seq": 0}

        def plan(form):
            pts = []
            for seg in form["segments"].split(","):
                a, b, step, bw = (float(x) for x in seg.split(":"))
                n = int(round((b - a) / step)) + 1 if step else 1
                pts += [(a + i * step, bw) for i in range(n)]
            state["plan"] = pts
            return {"ok": True, "points": len(pts)}, "application/json"

        def spectrum(q):
            peak = [-99] * len(state["plan"])
            for i, (f, _) in enumerate(state["plan"]):
                if abs(f - 806512.5) < 60:
                    peak[i] = -44
            return {"ok": True, "sweeps": 3, "sweep_ms": 410, "freq_hz": [int(f * 1000) for f, _ in state["plan"]],
                    "peak": peak, "avg": [p - 3 for p in peak], "rxbw_khz": [bw for _, bw in state["plan"]]}, \
                "application/json"

        def events(q):
            state["seq"] += 1
            pkt = {"seq": state["seq"], "ms": 1000, "freq_khz": 915000, "sync": "2dd4", "rssi": -63, "lqi": 30,
                   "hex": E.fineoffset_wh65(9, 18.5, 40).hex()}
            return {"seq": state["seq"], "now_ms": 1500, "captures": [], "packets": [pkt]}, "application/json"
        dev = FakeDevice({
            ("GET", "/nmap/info"): lambda q: ({"fw": "cc1101-nmap", "version": "0.2.0", "max_points": 1024,
                                               "seq": 0}, "application/json"),
            ("POST", "/nmap/plan"): plan,
            ("POST", "/nmap/rx"): lambda f: ({"ok": True}, "application/json"),
            ("GET", "/nmap/spectrum"): spectrum,
            ("GET", "/nmap/events"): events,
        })
        cat = Catalog.load(region="US")
        eng = Engine(cat)
        be = NmapFirmware(Sink(eng), cat, dev.host, poll_s=0.1, dashboard_port=8080)
        be.start()
        try:
            self.assertTrue(wait_for(lambda: "rf:ps-800-npspac-mobile" in eng.tracks and
                                     "fineoffset-wh65:9" in eng.tracks))
            self.assertTrue(any(e["level"] == "alert" for e in eng.events))
            rx = next(c for c in dev.calls if c[1] == "/nmap/rx")[2]
            self.assertEqual(rx["module"], "2")
            info = next(c for c in dev.calls if c[1] == "/nmap/info")[2]
            self.assertEqual(info.get("dash"), "8080")
        finally:
            be.stop()
            dev.close()


class TestWeb(unittest.TestCase):
    def test_endpoints(self):
        cat = Catalog.load(region="US")
        eng = Engine(cat)
        eng.set_status(connected=True, backend="sim", simulated=True)
        ws = WebServer(eng, cat, "127.0.0.1", 0)
        ws.start()
        base = f"http://127.0.0.1:{ws.port}"
        try:
            html = urllib.request.urlopen(base + "/").read().decode()
            self.assertIn("What's near", html)
            self.assertNotIn("https://", html.split("<script>")[0])     # no external resources
            state = json.loads(urllib.request.urlopen(base + "/api/state").read())
            self.assertTrue(state["status"]["simulated"])
            catj = json.loads(urllib.request.urlopen(base + "/api/catalog").read())
            self.assertGreater(len(catj["sweep_plan"]), 5)
            with urllib.request.urlopen(base + "/api/stream", timeout=5) as r:
                line = r.readline().decode()
            self.assertTrue(line.startswith("data: "))
        finally:
            ws.stop()


if __name__ == "__main__":
    unittest.main()
