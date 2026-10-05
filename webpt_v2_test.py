#!/usr/bin/env python3
"""WebPT v3 — test harness. No argparse."""

from __future__ import annotations
import asyncio
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import aiohttp

from webpt_v2 import (
    WebPT, ReportGenerator, Layer, Boundary,
    HttpEngine, LayerFingerprinter, ExplainedDiffer,
    AssumptionEngine, FindingBuilder, OriginCandidateEngine,
    Validator, classify_architecture,
)


class FixtureHandler(BaseHTTPRequestHandler):
    server_version = "FixtureOrigin/1.0"

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        self._dispatch("GET")

    def do_OPTIONS(self):
        self._dispatch("OPTIONS")

    def _send(self, status, body, extra=None):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "nginx/1.25.3")
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _dispatch(self, method):
        h = {k.lower(): v for k, v in self.headers.items()}
        path = self.path

        if path.endswith("/.") or path.endswith("/;"):
            return self._send(200, b"<html><title>Normalization variant</title>variant-different-content</html>",
                              {"X-Normalization-Mismatch": "1"})

        if "%2e%2e" in path.lower() or "etc/passwd" in path.lower():
            return self._send(403, b"<html><title>Forbidden</title>blocked-different-content</html>")

        if path.rstrip("/") == "/admin":
            if "x-original-url" in h or "x-rewrite-url" in h:
                return self._send(200, b"<html><title>Admin console</title>admin-surface-different</html>",
                                  {"X-Admin-Surface": "1", "Server": "gunicorn/21.2"})
            return self._send(403, b"<html><title>Forbidden</title>blocked-different-content</html>")

        if h.get("x-forwarded-for") == "127.0.0.1":
            return self._send(200, b"<html><title>Internal view</title>internal-different-body</html>",
                              {"X-Internal-View": "1", "Server": "gunicorn/21.2"})

        if "x-custom-ip-authorization" in h:
            return self._send(200, b"<html><title>Auth view</title>auth-different</html>")

        if path.rstrip("/") == "/leak":
            return self._send(200, b"<html><title>Leak</title>leak</html>",
                              {"X-Backend-Server": "10.20.30.40"})

        return self._send(200, b"<html><title>Fixture Origin</title>ok</html>")


class StaticHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def _respond(self):
        body = b"<html><title>Static</title>ok</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "nginx")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        self._respond()
    def do_OPTIONS(self):
        self._respond()


class FlakyHandler(BaseHTTPRequestHandler):
    _counter = 0
    def log_message(self, *a):
        pass
    def do_GET(self):
        FlakyHandler._counter += 1
        body = f"<html><title>Flaky</title>req{FlakyHandler._counter}</html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "nginx")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_fixture(handler=FixtureHandler, port=0):
    srv = ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "127.0.0.1", srv.server_address[1]


async def test_main_snapshot(base_url):
    print("[TEST] main snapshot populates")
    async with aiohttp.ClientSession() as s:
        http = HttpEngine(s, 4)
        snap = await LayerFingerprinter(http).snapshot(base_url)
        ok = snap.status == 200 and snap.body_hash != "" and "nginx" in snap.technologies
        print(f"    status={snap.status} hash={snap.body_hash} len={snap.body_len} tech={snap.technologies}")
        return ok


async def test_architecture_no_front_end(base_url):
    print("[TEST] architecture classifier says no front-end on plain fixture")
    async with aiohttp.ClientSession() as s:
        http = HttpEngine(s, 4)
        snap = await LayerFingerprinter(http).snapshot(base_url)
        arch = classify_architecture(snap)
        print(f"    front_end={arch.front_end} edge={arch.edge_tech} origin={arch.origin_tech}")
        return arch.front_end is False and arch.origin_tech == "nginx"


async def test_assumptions(base_url):
    print("[TEST] assumptions populate")
    async with aiohttp.ClientSession() as s:
        http = HttpEngine(s, 4)
        snap = await LayerFingerprinter(http).snapshot(base_url)
        arch = classify_architecture(snap)
        assumptions = AssumptionEngine().extract(snap, [], arch)
        required = [
            "Only traffic arriving via the expected front-end is legitimate",
            "Host header reflects the public domain",
            "Authorization decisions are made after routing and path normalization",
        ]
        got = [a.statement for a in assumptions]
        ok = all(r in got for r in required)
        print(f"    assumptions={got}")
        return ok


async def test_differential_xor(base_url):
    print("[TEST] x-original-url fires with signals + validation")
    async with aiohttp.ClientSession() as s:
        http = HttpEngine(s, 4)
        main = await http.fetch(base_url)
        differ = ExplainedDiffer(http, validator=Validator(http), enable_validation=True)
        diffs = await differ.run(base_url, main)
        xor = next((d for d in diffs if "x-original-url" in d.relationship), None)
        if xor is None:
            print("    variant missing")
            return False
        print(f"    status {xor.status_delta} interesting={xor.interesting} conf={xor.confidence:.2f}")
        print(f"    signals={[s.kind for s in xor.signals]}")
        print(f"    validation_reproduced={xor.validation_reproduced}")
        return xor.interesting and len([s for s in xor.signals if s.severity_weight > 0]) >= 2


async def test_differential_xff(base_url):
    print("[TEST] xff-localhost fires with signals")
    async with aiohttp.ClientSession() as s:
        http = HttpEngine(s, 4)
        main = await http.fetch(base_url)
        differ = ExplainedDiffer(http, validator=Validator(http), enable_validation=True)
        diffs = await differ.run(base_url, main)
        xff = next((d for d in diffs if "xff-localhost" in d.relationship), None)
        if xff is None:
            return False
        print(f"    signals={[s.kind for s in xff.signals]} interesting={xff.interesting}")
        return len([s for s in xff.signals if s.severity_weight > 0]) >= 2


async def test_findings_have_curl(base_url):
    print("[TEST] findings carry curl proof strings")
    async with aiohttp.ClientSession() as s:
        http = HttpEngine(s, 4)
        main = await http.fetch(base_url)
        differ = ExplainedDiffer(http, validator=Validator(http), enable_validation=True)
        diffs = await differ.run(base_url, main)
        fb = FindingBuilder()
        findings = [f for i, d in enumerate(diffs, 1) if (f := fb.from_diff(d, i))]
        print(f"    findings={len(findings)}")
        for f in findings:
            print(f"      [{f.severity}] {f.id} {f.title}")
        return len(findings) >= 1 and all(f.baseline_curl and f.variant_curl for f in findings)


async def test_no_false_positive_on_static():
    print("[TEST] static fixture yields zero findings")
    srv, host, port = start_fixture(StaticHandler, 0)
    try:
        base_url = f"http://{host}:{port}"
        async with aiohttp.ClientSession() as s:
            http = HttpEngine(s, 4)
            main = await http.fetch(base_url)
            differ = ExplainedDiffer(http, validator=Validator(http), enable_validation=True)
            diffs = await differ.run(base_url, main)
            fb = FindingBuilder()
            findings = [f for i, d in enumerate(diffs, 1) if (f := fb.from_diff(d, i))]
            print(f"    findings={len(findings)} (expected 0)")
            return len(findings) == 0
    finally:
        srv.shutdown()


async def test_validation_rejects_flaky():
    print("[TEST] validator rejects flaky upstream")
    srv, host, port = start_fixture(FlakyHandler, 0)
    try:
        base_url = f"http://{host}:{port}"
        async with aiohttp.ClientSession() as s:
            http = HttpEngine(s, 4)
            main = await http.fetch(base_url)
            differ = ExplainedDiffer(http, validator=Validator(http), enable_validation=True)
            diffs = await differ.run(base_url, main)
            fired = [d for d in diffs if d.interesting]
            print(f"    interesting_after_validation={len(fired)} (expected 0)")
            return len(fired) == 0
    finally:
        srv.shutdown()


async def test_unreachable_target():
    print("[TEST] unreachable target aborts with reason")
    report = await WebPT("http://127.0.0.1:1", concurrency=2, enable_validation=False).run()
    main = report.layers.get("main")
    ok = main is not None and main.status == 0 and main.notes and main.notes[0].startswith("connect:")
    print(f"    status={main.status if main else '?'} notes={main.notes[:2] if main else []}")
    return ok


async def test_full_run(base_url):
    print("[TEST] full orchestrator run")
    report = await WebPT(base_url, concurrency=4, enable_validation=True).run()
    text = ReportGenerator().text(report)
    ok = (
        report.layers.get("main") is not None
        and report.layers["main"].status == 200
        and len(report.assumptions) >= 3
        and report.architecture is not None
    )
    print(f"    summary: {report.summary}")
    print(f"    report chars: {len(text)}")
    return ok


async def run_all():
    srv, host, port = start_fixture(FixtureHandler, 0)
    base_url = f"http://{host}:{port}"
    print(f"[*] Fixture origin at {base_url}")
    time.sleep(0.1)
    results = {}
    try:
        results["main_snapshot"] = await test_main_snapshot(base_url)
        results["architecture_no_front_end"] = await test_architecture_no_front_end(base_url)
        results["assumptions"] = await test_assumptions(base_url)
        results["differential_xor"] = await test_differential_xor(base_url)
        results["differential_xff"] = await test_differential_xff(base_url)
        results["findings_have_curl"] = await test_findings_have_curl(base_url)
        results["no_false_positive"] = await test_no_false_positive_on_static()
        results["validation_rejects_flaky"] = await test_validation_rejects_flaky()
        results["unreachable"] = await test_unreachable_target()
        results["full_run"] = await test_full_run(base_url)
    finally:
        srv.shutdown()
    print("\n[RESULTS]")
    passed = sum(1 for v in results.values() if v)
    for name, ok in results.items():
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print(f"\n  {passed}/{len(results)} passed")
    return passed == len(results)


if __name__ == "__main__":
    ok = asyncio.run(run_all())
    sys.exit(0 if ok else 1)
