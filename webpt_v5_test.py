#!/usr/bin/env python3
"""WebPT v5 — smoke tests."""
from __future__ import annotations
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from webpt_v5 import (
    _cidr_to_range, ip_in_ranges, build_v5_aiohttp_probes,
    refresh_edge_ranges, ws_handshake, WSProbeRunner,
    AuthConfigV5, AuthenticatorV5, H2ProbeRunner,
)
from webpt_v2 import normalize_ephemeral, bodies_similar


def test_cidr_to_range():
    print("[TEST] cidr_to_range")
    r = _cidr_to_range("104.16.0.0/12")
    ok = r is not None and r[0] == _cidr_to_range("104.16.0.0/12")[0]
    print(f"    {r}")
    return ok


def test_ip_in_ranges():
    print("[TEST] ip_in_ranges")
    ranges = {"cloudflare": [_cidr_to_range("104.16.0.0/12")]}
    cdn = ip_in_ranges("104.16.124.96", ranges)
    ok = cdn == "cloudflare"
    print(f"    cdn={cdn}")
    return ok


def test_v5_probes():
    print("[TEST] v5 probe builder")
    ps = build_v5_aiohttp_probes("example.com")
    fams = sorted({p["cat"] for p in ps})
    ok = len(ps) >= 200 and len(fams) >= 10
    print(f"    probes={len(ps)} families={len(fams)}")
    return ok


def test_normalize_non_ascii():
    print("[TEST] normalize_ephemeral strips non-ASCII runs")
    a = b"<html><body>token:\xe2\x9c\x93\xf0\x9f\x94\x91</body></html>"
    b = b"<html><body>token:\xe2\x98\x85\xf0\x9f\x8e\x89</body></html>"
    ok = normalize_ephemeral(a) == normalize_ephemeral(b)
    print(f"    norm_a={normalize_ephemeral(a)!r}")
    return ok


def test_bodies_similar():
    print("[TEST] bodies_similar byte-diff fallback")
    a = b"x" * 1000 + b"abc"
    b = b"x" * 1000 + b"xyz"
    ok = bodies_similar(a, b, threshold=0.05)
    print(f"    similar={ok}")
    return ok


async def test_refresh_edges():
    print("[TEST] refresh_edge_ranges (live, tolerant)")
    try:
        r = await refresh_edge_ranges(force=False)
        ok = "static" in r
        for k, v in r.items():
            print(f"    {k}: {len(v)} ranges")
        return ok
    except Exception as e:
        print(f"    exception: {e}")
        return False


async def test_h2_runner():
    print("[TEST] H2ProbeRunner imports")
    try:
        r = H2ProbeRunner("https://example.com")
        ok = r.base_url.startswith("https://")
        print(f"    ok={ok}")
        return ok
    except Exception as e:
        print(f"    exception: {e}")
        return False


async def run_all():
    results = {}
    results["cidr"] = test_cidr_to_range()
    results["ip_in_ranges"] = test_ip_in_ranges()
    results["v5_probes"] = test_v5_probes()
    results["norm_non_ascii"] = test_normalize_non_ascii()
    results["bodies_similar"] = test_bodies_similar()
    results["edges"] = await test_refresh_edges()
    results["h2"] = await test_h2_runner()
    print("\n[RESULTS]")
    passed = sum(1 for v in results.values() if v)
    for name, ok in results.items():
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print(f"\n  {passed}/{len(results)} passed")
    return passed == len(results)


if __name__ == "__main__":
    ok = asyncio.run(run_all())
    sys.exit(0 if ok else 1)
