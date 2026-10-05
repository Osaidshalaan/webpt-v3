#!/usr/bin/env python3
"""WebPT v4 — smoke tests for new modules."""
from __future__ import annotations
import asyncio
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import aiohttp

from banner import banner_static
from webpt_v4 import (
    AuthConfig, Authenticator, raw_http_request, parse_raw_response,
    family_stats, render_html_report, diff_two_reports,
    build_smuggling_probes, build_host_probes, build_range_probes,
    build_post_probes,
)
from webpt_v2 import (
    HttpEngine, LayerFingerprinter, Report, Architecture,
)


class LoginHandler(BaseHTTPRequestHandler):
    server_version = "LoginFixture/1.0"

    def log_message(self, *a):
        pass

    def _send(self, status, body, extra=None):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/login"):
            body = (b'<html><body>'
                    b'<form action="/login" method="post">'
                    b'<input type="hidden" name="csrf_token" value="tok123">'
                    b'<input name="username"><input name="password" type="password">'
                    b'</form></body></html>')
            return self._send(200, body)
        if self.path.startswith("/admin"):
            cookie = self.headers.get("Cookie", "")
            if "session=" in cookie:
                return self._send(200, b"<html>admin ok</html>")
            return self._send(403, b"<html>forbidden</html>")
        return self._send(200, b"<html>index</html>")

    def do_POST(self):
        cl = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(cl).decode("utf-8", errors="ignore")
        if "username=alice" in body and "password=secret" in body and "csrf_token=tok123" in body:
            return self._send(302, b"", {"Set-Cookie": "session=ok; Path=/",
                                          "Location": "/admin"})
        return self._send(401, b"<html>bad creds</html>")


def start_fixture(port=0):
    srv = ThreadingHTTPServer(("127.0.0.1", port), LoginHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "127.0.0.1", srv.server_address[1]


def test_banner_static():
    b = banner_static()
    ok = "OSAID" in b and "v4.0" in b
    print(f"    banner_static contains OSAID + v4.0: {ok}")
    return ok


def test_raw_http_request():
    print("[TEST] raw_http_request against local fixture")
    srv, host, port = start_fixture()
    try:
        req = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        raw = raw_http_request(host, port, False, req, timeout=3.0)
        snap = parse_raw_response(raw)
        ok = snap is not None and snap.status == 200 and b"index" in snap.body_raw
        print(f"    status={snap.status if snap else '?'} len={len(raw)}")
        return ok
    finally:
        srv.shutdown()


async def test_authenticator():
    print("[TEST] authenticator CSRF + cookie flow")
    srv, host, port = start_fixture()
    try:
        base = f"http://{host}:{port}"
        async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as s:
            http = HttpEngine(s, 4)
            cfg = AuthConfig(
                login_url=f"{base}/login",
                username="alice", password="secret",
            )
            ok, notes = await Authenticator(http).login(cfg)
            print(f"    login_ok={ok} notes={notes}")
            # check that /admin is reachable after login
            snap = await http.fetch(f"{base}/admin")
            admin_ok = snap is not None and snap.status == 200
            print(f"    admin status={snap.status if snap else '?'}")
            return ok and admin_ok
    finally:
        srv.shutdown()


def test_probe_builders():
    print("[TEST] probe builders produce non-empty lists")
    s = build_smuggling_probes("example.com")
    h = build_host_probes("example.com")
    r = build_range_probes()
    p = build_post_probes()
    ok = all(len(x) > 0 for x in (s, h, r, p))
    print(f"    smuggling={len(s)} host={len(h)} range={len(r)} post={len(p)}")
    return ok


def test_family_stats():
    print("[TEST] family_stats aggregation")
    from webpt_v2 import DiffExplanation, LayerSnapshot, Layer, Boundary, Signal
    empty = LayerSnapshot(Layer.UNKNOWN, {}, 200, "x", 0, "", [], "")
    d1 = DiffExplanation(baseline=empty, variant=empty, status_delta=(200, 200),
                         header_delta={}, body_delta=0,
                         relationship="Variant 'xff-localhost' tests ...",
                         boundary=Boundary.WAF_ORIGIN,
                         violation_evidence=[], normal_explanations_ruled_out=[],
                         confidence=0.1, signals=[])
    d2 = DiffExplanation(baseline=empty, variant=empty, status_delta=(200, 200),
                         header_delta={}, body_delta=0,
                         relationship="Variant 'range-first100' tests ...",
                         boundary=Boundary.ORIGIN_APP,
                         violation_evidence=[], normal_explanations_ruled_out=[],
                         confidence=0.1, signals=[])
    probes = [
        {"label": "xff-localhost", "cat": "fwd_ip"},
        {"label": "range-first100", "cat": "range"},
    ]
    stats = family_stats([d1, d2], probes)
    ok = "fwd_ip" in stats and "range" in stats
    print(f"    families={list(stats.keys())}")
    return ok


def test_html_report():
    print("[TEST] HTML report renders")
    empty = Architecture()
    report = Report(target="https://x", started="t0", finished="t1",
                    architecture=empty, layers={}, assumptions=[],
                    contradictions=[], origin_candidates=[], diffs=[],
                    findings=[], summary="test")
    html_text = render_html_report(report, [])
    ok = html_text.startswith("<!doctype html>") and "</html>" in html_text
    print(f"    html len={len(html_text)}")
    return ok


def test_diff_reports(tmpdir):
    print("[TEST] diff_two_reports")
    old = {"target": "x", "finished": "t1",
           "findings": [{"severity": "high", "title": "A", "boundary_crossed": "b"}]}
    new = {"target": "x", "finished": "t2",
           "findings": [{"severity": "high", "title": "B", "boundary_crossed": "b"}]}
    o = Path(tmpdir) / "old.json"
    n = Path(tmpdir) / "new.json"
    o.write_text(json.dumps(old))
    n.write_text(json.dumps(new))
    out = diff_two_reports(str(o), str(n))
    ok = "ADDED" in out and "RESOLVED" in out
    print(f"    diff len={len(out)}")
    return ok


async def run_all():
    import tempfile
    results = {}
    print("[*] WebPT v4 smoke tests")
    results["banner_static"] = test_banner_static()
    results["raw_http_request"] = test_raw_http_request()
    results["authenticator"] = await test_authenticator()
    results["probe_builders"] = test_probe_builders()
    results["family_stats"] = test_family_stats()
    results["html_report"] = test_html_report()
    with tempfile.TemporaryDirectory() as td:
        results["diff_reports"] = test_diff_reports(td)

    print("\n[RESULTS]")
    passed = sum(1 for v in results.values() if v)
    for name, ok in results.items():
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print(f"\n  {passed}/{len(results)} passed")
    return passed == len(results)


if __name__ == "__main__":
    ok = asyncio.run(run_all())
    sys.exit(0 if ok else 1)
