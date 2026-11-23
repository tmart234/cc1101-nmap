"""Built-in web dashboard and JSON API (stdlib only, works fully offline).

  GET /                 dashboard
  GET /api/state        full snapshot (devices, RF activity, events, spectrum)
  GET /api/events?since=N
  GET /api/catalog      what this scanner knows about + current sweep plan
  GET /api/stream       Server-Sent Events: a snapshot each time something changes
  GET /healthz
"""
from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlparse

from .catalog import Catalog
from .engine import Engine

log = logging.getLogger(__name__)

DASHBOARD = os.path.join(os.path.dirname(__file__), "dashboard.html")


class _Handler(BaseHTTPRequestHandler):
    server_version = "cc1101-nmap"
    engine: Engine
    catalog: Catalog
    extra: dict

    def log_message(self, fmt, *args):  # route through logging, quietly
        log.debug("%s - %s", self.address_string(), fmt % args)

    def _send(self, code: int, body: bytes, ctype: str, cache: str = "no-store"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200):
        self._send(code, json.dumps(obj, separators=(",", ":")).encode(), "application/json")

    def do_GET(self):  # noqa: N802 (stdlib naming)
        url = urlparse(self.path)
        q = parse_qs(url.query)
        try:
            if url.path in ("/", "/index.html"):
                with open(DASHBOARD, "rb") as fh:
                    self._send(200, fh.read(), "text/html; charset=utf-8")
            elif url.path == "/api/state":
                self._json(self.engine.snapshot(include_spectrum=q.get("spectrum", ["1"])[0] != "0"))
            elif url.path == "/api/events":
                since = int(q.get("since", ["0"])[0])
                with self.engine.lock:
                    self._json([e for e in self.engine.events if e["seq"] > since])
            elif url.path == "/api/catalog":
                plan = [vars(s) | {"points": s.points} for s in self.catalog.sweep_plan(self.extra.get("max_points", 600))]
                self._json(self.catalog.to_json() | {"sweep_plan": plan, "rx_profiles": self.catalog.rx_profiles})
            elif url.path == "/api/stream":
                self._stream()
            elif url.path == "/healthz":
                self._json({"ok": True, "version": self.engine.version})
            else:
                self._send(404, b"not found", "text/plain")
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _stream(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        seen = -1
        last_sent = 0.0
        while not self.extra["stopping"].is_set():
            with self.engine.changed:
                if self.engine.version == seen:
                    self.engine.changed.wait(timeout=15)
            if self.engine.version == seen:
                self.wfile.write(b": keep-alive\n\n")
                self.wfile.flush()
                continue
            wait = 1.0 - (time.time() - last_sent)       # at most one update per second
            if wait > 0:
                time.sleep(wait)
            snap = self.engine.snapshot()
            seen, last_sent = snap["version"], time.time()
            self.wfile.write(b"data: " + json.dumps(snap, separators=(",", ":")).encode() + b"\n\n")
            self.wfile.flush()


class WebServer:
    def __init__(self, engine: Engine, catalog: Catalog, host: str = "0.0.0.0", port: int = 8080,
                 max_points: int = 600):
        self.stopping = threading.Event()
        handler = type("Handler", (_Handler,), {"engine": engine, "catalog": catalog,
                                                "extra": {"stopping": self.stopping, "max_points": max_points}})
        self.httpd = ThreadingHTTPServer((host, port), handler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True, name="web")

    @property
    def port(self) -> int:
        return self.httpd.server_address[1]

    def start(self):
        self.thread.start()
        host = self.httpd.server_address[0]
        log.info("Dashboard: http://%s:%d/", local_ip() if host in ("0.0.0.0", "") else host, self.port)

    def stop(self):
        self.stopping.set()
        self.httpd.shutdown()
        self.httpd.server_close()


def local_ip() -> str:
    """Best guess at this machine's LAN address (no packets are sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "localhost"
    finally:
        s.close()


def serve(engine: Engine, catalog: Catalog, host: str, port: int, max_points: int = 600) -> Optional[WebServer]:
    try:
        ws = WebServer(engine, catalog, host, port, max_points)
    except OSError as e:
        log.error("Web dashboard disabled: cannot bind %s:%d (%s)", host, port, e)
        return None
    ws.start()
    return ws
