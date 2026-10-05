#!/usr/bin/env python3
"""WebPT v5 — auth v5, HTTP/2, WebSocket, dynamic edge ranges, 300+ probes."""
from __future__ import annotations
import argparse
import asyncio
import base64
import hashlib
import json
import os
import re
import socket
import ssl
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import aiohttp

from banner import animate_banner
from webpt_v2 import (
    Boundary, Layer, LayerSnapshot, Signal, DiffExplanation, Report,
    HttpEngine, LayerFingerprinter, OriginCandidateEngine, AssumptionEngine,
    Validator, FindingBuilder, ReportGenerator, Architecture,
    classify_architecture, extract_signals, score_hypotheses,
    normalize, sha16, normalize_ephemeral, bodies_similar, is_edge_ip,
    EDGE_RANGES,
)
from webpt_v4 import (
    ExplainedDifferV4, AuthConfig, Authenticator,
    build_range_probes, build_post_probes,
    build_smuggling_probes, build_host_probes,
    family_stats, render_html_report, diff_two_reports,
)

# ---------------------------------------------------------------- deps guard
_HTTPX_OK = True
try:
    import httpx
except ImportError:
    _HTTPX_OK = False

_WS_OK = True
try:
    import websockets
except ImportError:
    _WS_OK = False

_TOTP_OK = True
try:
    import pyotp
except ImportError:
    _TOTP_OK = False


# ---------------------------------------------------------------- edge ranges v5

_EDGE_CACHE_DIR = Path.home() / ".cache" / "webpt"
_EDGE_CACHE = _EDGE_CACHE_DIR / "edge_ranges.json"
_EDGE_TTL = 86400


def _cidr_to_range(cidr: str) -> Optional[Tuple[int, int]]:
    cidr = cidr.strip()
    if "/" not in cidr:
        return None
    ip, bits = cidr.split("/", 1)
    try:
        bits = int(bits)
    except ValueError:
        return None
    try:
        parts = [int(p) for p in ip.split(".")]
    except ValueError:
        return None
    if len(parts) != 4 or bits < 0 or bits > 32:
        return None
    base = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF if bits else 0
    start = base & mask
    end = start | (0xFFFFFFFF ^ mask)
    return (start, end)


async def _fetch_json(url: str, timeout: float = 10.0) -> Any:
    if not _HTTPX_OK:
        return None
    try:
        async with httpx.AsyncClient(timeout=timeout) as c:
            r = await c.get(url)
            if r.status_code != 200:
                return None
            return r.json()
    except Exception:
        return None


async def _fetch_text(url: str, timeout: float = 10.0) -> Optional[str]:
    if not _HTTPX_OK:
        return None
    try:
        async with httpx.AsyncClient(timeout=timeout) as c:
            r = await c.get(url)
            if r.status_code != 200:
                return None
            return r.text
    except Exception:
        return None


async def refresh_edge_ranges(force: bool = False) -> Dict[str, List[Tuple[int, int]]]:
    """Fetch published CDN IP ranges. Cache to ~/.cache/webpt/edge_ranges.json."""
    _EDGE_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if not force and _EDGE_CACHE.exists():
        try:
            blob = json.loads(_EDGE_CACHE.read_text())
            if time.time() - blob.get("ts", 0) < _EDGE_TTL:
                return {k: [tuple(x) for x in v] for k, v in blob["data"].items()}
        except Exception:
            pass

    out: Dict[str, List[Tuple[int, int]]] = {}

    # Cloudflare
    txt = await _fetch_text("https://www.cloudflare.com/ips-v4")
    if txt:
        cf = [r for r in (_cidr_to_range(l) for l in txt.splitlines()) if r]
        if cf:
            out["cloudflare"] = cf

    # Fastly
    js = await _fetch_json("https://api.fastly.com/public-ip-list")
    if js and "addresses" in js:
        fs = [r for r in (_cidr_to_range(x) for x in js["addresses"]) if r]
        if fs:
            out["fastly"] = fs

    # CloudFront
    js = await _fetch_json("https://ip-ranges.amazonaws.com/ip-ranges.json")
    if js and "prefixes" in js:
        cf_all = [p["ip_prefix"] for p in js["prefixes"]
                  if p.get("service") == "CLOUDFRONT"]
        cfr = [r for r in (_cidr_to_range(x) for x in cf_all) if r]
        if cfr:
            out["cloudfront"] = cfr

    # Akamai — no public endpoint, keep static from webpt_v2
    static: List[Tuple[int, int]] = []
    for s, e in EDGE_RANGES:
        def to_int(x):
            p = [int(o) for o in x.split(".")]
            return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]
        static.append((to_int(s), to_int(e)))
    out["static"] = static

    try:
        _EDGE_CACHE.write_text(json.dumps({
            "ts": time.time(),
            "data": {k: [list(x) for x in v] for k, v in out.items()},
        }))
    except Exception:
        pass
    return out


def ip_in_ranges(ip: str, ranges: Dict[str, List[Tuple[int, int]]]) -> Optional[str]:
    try:
        parts = [int(p) for p in ip.split(".")]
        if len(parts) != 4:
            return None
        v = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    except (ValueError, AttributeError):
        return None
    for name, ranges_list in ranges.items():
        for s, e in ranges_list:
            if s <= v <= e:
                return name
    return None


# ---------------------------------------------------------------- probe families v5

def _p(cat, label, boundary, assumption, **kw):
    d = {"cat": cat, "label": label, "boundary": boundary,
         "tests_assumption": assumption}
    d.update(kw)
    return d


def build_v5_aiohttp_probes(target_host: str) -> List[Dict[str, Any]]:
    probes: List[Dict[str, Any]] = []

    # --- path_variants
    for i, sfx in enumerate([
        "/%2e", "/%2E", "/%2f", "/%2F", "/%5c", "/%5C",
        "/%252e", "/%252f", "/%c0%2e", "/%c0%ae",
        "/./", "/..", "/../", "/./././", "/.../",
        "/%2e/", "/.%2f", "/%2e./", "/.%2e.",
        "/%ef%bc%8f", "/%uff0e", "/%uff0f",
        "/%c0%af", "/%e0%80%af", "/%f0%80%80%af",
        "///", "///", "////", "/\\", "\\/",
        "/\\admin", "/admin\\", "/admin/.", "/admin/..",
        "/admin;/", "/admin%3b", "/admin%00", "/admin%0a",
        "/admin%0d", "/admin%09", "/admin ",
    ]):
        probes.append(_p("path_variants", f"pv{i:02d}", Boundary.WAF_ORIGIN,
                         f"Path variant {sfx!r} normalized identically",
                         path_suffix=sfx))

    # --- method_matrix
    for m in ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS",
              "TRACE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY",
              "MOVE", "LOCK", "UNLOCK", "REPORT", "SEARCH", "PURGE",
              "get", "Get", "gEt"]:
        probes.append(_p("method_matrix", f"mm-{m}", Boundary.ORIGIN_APP,
                         f"Method {m} handled identically", method=m))

    # --- headers_special
    for i, (h, v) in enumerate([
        ("X-HTTP-Method-Override", "GET"),
        ("X-HTTP-Method-Override", "HEAD"),
        ("X-HTTP-Method", "PUT"),
        ("X-Method-Override", "PATCH"),
        ("X-Original-Method", "DELETE"),
        ("X-Forwarded-Method", "PUT"),
        ("X-Override-Method", "PUT"),
        ("X-Rewrite-Method", "DELETE"),
        ("X-Method", "DELETE"),
        ("Override", "PUT"),
        ("X-HTTP-Method-Override", "PROPFIND"),
    ]):
        probes.append(_p("method_override", f"mo{i:02d}-{h.lower()}", Boundary.ORIGIN_APP,
                         f"Override header {h}: {v} ignored", headers={h: v}))

    # --- accept_variants
    for i, a in enumerate([
        "application/json", "application/xml", "text/xml",
        "application/yaml", "application/x-yaml", "text/yaml",
        "application/msgpack", "application/cbor",
        "application/octet-stream", "text/csv", "text/tab-separated-values",
        "application/x-www-form-urlencoded", "multipart/form-data",
        "application/graphql", "text/event-stream",
        "*/*;q=0.1,application/json;q=1",
    ]):
        probes.append(_p("accept_variants", f"av{i:02d}", Boundary.ORIGIN_APP,
                         f"Accept {a} does not expose different data",
                         headers={"Accept": a, "X-Requested-With": "XMLHttpRequest"}))

    # --- charset_variants
    for i, ct in enumerate([
        "text/html; charset=utf-7",
        "text/html; charset=utf-16",
        "text/html; charset=utf-32",
        "text/html; charset=gbk",
        "text/html; charset=big5",
        "text/html; charset=shift_jis",
        "text/html; charset=iso-2022-jp",
        "text/html; charset=cp1252",
        "text/html; charset=macintosh",
        "text/html; charset=x-user-defined",
    ]):
        probes.append(_p("charset", f"cs{i:02d}", Boundary.ORIGIN_APP,
                         f"Charset {ct} handled identically",
                         headers={"Accept-Charset": ct.split("=", 1)[1]}))

    # --- lang_variants
    for i, lang in enumerate([
        "en-US", "en", "zh-CN", "ru-RU", "ar-SA", "fa-IR",
        "he-IL", "tr-TR", "de-DE", "fr-FR",
    ]):
        probes.append(_p("lang", f"lg{i:02d}", Boundary.ORIGIN_APP,
                         f"Accept-Language {lang} does not expose different data",
                         headers={"Accept-Language": lang}))

    # --- ua_variants
    for i, ua in enumerate([
        "curl/8.0", "python-requests/2.31", "Go-http-client/1.1",
        "PostmanRuntime/7.32", "wget/1.21", "Mozilla/5.0",
        "Googlebot/2.1", "bingbot/2.0", "Baiduspider/2.0",
        "facebookexternalhit/1.1", "Twitterbot/1.0", "Slackbot-LinkExpanding 1.0",
        "HeadlessChrome/120", "PhantomJS/2.1", "Internal-Scanner/1.0",
    ]):
        probes.append(_p("ua", f"ua{i:02d}", Boundary.INTERNET_WAF,
                         f"UA {ua!r} not treated differently",
                         headers={"User-Agent": ua}))

    # --- referer_variants
    for i, ref in enumerate([
        "https://" + target_host, "https://" + target_host + "/admin",
        "https://localhost", "https://127.0.0.1", "https://internal.local",
        "null", "", "http://" + target_host,  # downgrade
        "//" + target_host, "https://" + target_host + ":8443",
    ]):
        probes.append(_p("referer", f"rf{i:02d}", Boundary.INTERNET_WAF,
                         f"Referer {ref!r} not trusted", headers={"Referer": ref}))

    # --- origin_header
    for i, o in enumerate([
        "null", "https://" + target_host, "https://localhost",
        "http://" + target_host, "", "*",
    ]):
        probes.append(_p("cors_origin", f"co{i:02d}", Boundary.ORIGIN_APP,
                         f"Origin {o!r} not reflected", headers={"Origin": o}))

    # --- auth_header
    for i, (scheme, val) in enumerate([
        ("Basic", base64.b64encode(b"admin:admin").decode()),
        ("Basic", base64.b64encode(b"root:root").decode()),
        ("Bearer", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."),
        ("Bearer", "null"),
        ("Bearer", "admin"),
        ("Digest", "username=admin"),
        ("Negotiate", "AAAA"),
        ("NTLM", "AAAA"),
        ("AWS4-HMAC-SHA256", "Credential=admin"),
        ("Token", "admin"),
    ]):
        probes.append(_p("auth_header", f"ah{i:02d}", Boundary.ORIGIN_APP,
                         f"Auth scheme {scheme} {val[:20]!r} not honored",
                         headers={"Authorization": f"{scheme} {val}"}))

    # --- forwarded_variants
    for i, h in enumerate([
        "X-Forwarded-For", "X-Real-IP", "X-Client-IP", "X-Originating-IP",
        "X-Remote-IP", "X-Remote-Addr", "True-Client-IP", "CF-Connecting-IP",
        "Fastly-Client-IP", "X-Cluster-Client-IP", "X-ProxyUser-IP",
        "Forwarded",
    ]):
        if h == "Forwarded":
            v = "for=127.0.0.1;proto=http;by=localhost"
        else:
            v = "127.0.0.1"
        probes.append(_p("fwd_ip", f"fw{i:02d}-{h.lower()}", Boundary.WAF_ORIGIN,
                         f"{h} not trusted from external", headers={h: v}))

    # --- x_internal
    for i, h in enumerate([
        "X-Internal", "X-Internal-Request", "X-Debug", "X-Debug-Mode",
        "X-Dev-Mode", "X-Developer", "X-Test", "X-Staging",
        "X-Admin", "X-Admin-Mode", "X-Authenticated-User",
        "X-Remote-User", "X-User", "X-User-Id", "X-User-Role",
        "X-Impersonate", "X-Sudo", "X-Bypass-WAF", "X-No-WAF",
    ]):
        v = "1" if "mode" in h.lower() or h.lower() in (
            "x-internal", "x-debug", "x-test", "x-staging", "x-bypass-waf",
            "x-no-waf", "x-sudo") else "admin"
        probes.append(_p("x_internal", f"xi{i:02d}-{h.lower()}", Boundary.WAF_ORIGIN,
                         f"{h} not honored from external", headers={h: v}))

    # --- query_variants
    for i, q in enumerate([
        "?debug=1", "?debug=true", "?test=1", "?admin=1", "?internal=1",
        "?dev=1", "?staging=1", "?preview=1", "?_debug=1", "?__debug=1",
        "?_method=DELETE", "?_method=PUT", "?__method=DELETE",
        "?format=json", "?output=json", "?type=json",
    ]):
        probes.append(_p("query", f"qv{i:02d}", Boundary.ORIGIN_APP,
                         f"Query {q} does not change authorization",
                         path_suffix=q))

    # --- cache_poisoning
    for i, q in enumerate([
        "?_=123", "?cb=abc", "?%00=1", "?utm_source=admin",
        "?ref=https://evil.example", "?callback=admin",
        "?jsonp=alert", "?redirect=https://evil.example",
        "?next=https://evil.example", "?url=https://evil.example",
        "?return_to=/admin", "?returnUrl=/admin",
        "?continue=/admin", "?r=/admin", "?goto=/admin",
    ]):
        probes.append(_p("cache_poison", f"cp{i:02d}", Boundary.WAF_ORIGIN,
                         f"Parameter {q} not reflected into cache key",
                         path_suffix=q))

    return probes


# ---------------------------------------------------------------- HTTP/2

class H2ProbeRunner:
    def __init__(self, base_url: str, timeout: float = 15.0):
        if not _HTTPX_OK:
            raise RuntimeError("httpx not installed")
        self.base_url = base_url
        self.timeout = timeout

    async def run(self, probes: List[Dict[str, Any]],
                  baseline: LayerSnapshot) -> List[DiffExplanation]:
        results: List[DiffExplanation] = []
        async with httpx.AsyncClient(http2=True, verify=False,
                                     timeout=self.timeout,
                                     follow_redirects=False) as client:
            for v in probes:
                url = self.base_url.rstrip("/") + v.get("path_suffix", "")
                method = v.get("method", "GET")
                hdrs = dict(v.get("headers") or {})
                body = v.get("body")
                try:
                    r = await client.request(method, url, headers=hdrs, content=body)
                except Exception:
                    continue
                raw = r.content or b""
                norm = normalize_ephemeral(raw)
                snap = LayerSnapshot(
                    layer=Layer.UNKNOWN,
                    headers={k.lower(): val for k, val in r.headers.items()},
                    status=r.status_code,
                    body_hash=sha16(raw), body_len=len(raw),
                    title="", technologies=[], raw_headers="",
                    notes=[f"http_version={r.http_version}",
                           f"elapsed_ms={int(r.elapsed.total_seconds()*1000)}"],
                    body_raw=raw,
                    elapsed_ms=int(r.elapsed.total_seconds()*1000),
                    body_hash_norm=sha16(norm),
                )
                signals = extract_signals(baseline, snap, hdrs)
                # proto_downgrade: h2 client but server answered HTTP/1.1
                if r.http_version == "HTTP/1.1":
                    signals.append(Signal(
                        kind="proto_downgrade",
                        rules_out="nothing - server downgraded h2 to h1.1",
                        detail="h2 client, h1.1 response",
                        severity_weight=0.3,
                    ))
                hyps = score_hypotheses(signals, variant_headers=hdrs,
                                        baseline=baseline, variant=snap,
                                        variant_path_is_new=bool(v.get("path_suffix")))
                positive = [s for s in signals if s.severity_weight > 0]
                corroborating = [s for s in positive if s.kind in (
                    "sensitive_header_delta", "status_class_shift",
                    "status_reversal", "auth_challenge_changed",
                    "proto_downgrade")]
                top = hyps[0] if hyps else None
                interesting = (top is not None
                               and top.kind == "boundary_violation"
                               and len(positive) >= 2
                               and len(corroborating) >= 1)
                d = DiffExplanation(
                    baseline=baseline, variant=snap,
                    status_delta=(baseline.status, snap.status),
                    header_delta={},
                    body_delta=snap.body_len - baseline.body_len,
                    relationship=(f"Variant '{v['label']}' [{v.get('cat','h2')}] tests assumption: "
                                  f"{v['tests_assumption']}. h2 response status={snap.status}."),
                    boundary=v["boundary"],
                    violation_evidence=[s.detail for s in positive],
                    normal_explanations_ruled_out=[s.rules_out for s in positive],
                    confidence=min(0.92, max(0.15, sum(s.severity_weight for s in positive))),
                    interesting=interesting,
                    signals=signals, hypotheses=hyps,
                    baseline_url=self.base_url, variant_url=url,
                    variant_method=method, variant_headers=hdrs,
                )
                results.append(d)
        return results


# ---------------------------------------------------------------- WebSocket

def ws_handshake(host: str, port: int, use_tls: bool, path: str,
                 headers: Dict[str, str], timeout: float = 6.0) -> Tuple[int, Dict[str, str]]:
    key = base64.b64encode(os.urandom(16)).decode()
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    req = ("\r\n".join(lines) + "\r\n\r\n").encode()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(req)
        sock.settimeout(timeout)
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 8192:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        sock.close()
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1", errors="replace")
        first = head.split("\r\n", 1)[0]
        m = re.match(r"HTTP/[\d.]+ (\d+)", first)
        status = int(m.group(1)) if m else 0
        hdrs: Dict[str, str] = {}
        for line in head.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                hdrs[k.strip().lower()] = v.strip()
        return status, hdrs
    except Exception:
        return 0, {}


class WSProbeRunner:
    def __init__(self, host: str, port: int, use_tls: bool, base_path: str = "/"):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.base_path = base_path

    async def run(self, baseline: LayerSnapshot) -> List[DiffExplanation]:
        loop = asyncio.get_event_loop()
        variants = [
            {"label": "ws-standard", "path": self.base_path, "headers": {}},
            {"label": "ws-origin-evil", "path": self.base_path,
             "headers": {"Origin": "https://evil.example"}},
            {"label": "ws-origin-null", "path": self.base_path,
             "headers": {"Origin": "null"}},
            {"label": "ws-no-version", "path": self.base_path,
             "headers": {"Sec-WebSocket-Version": ""}},
            {"label": "ws-bad-version", "path": self.base_path,
             "headers": {"Sec-WebSocket-Version": "8"}},
            {"label": "ws-subprotocol", "path": self.base_path,
             "headers": {"Sec-WebSocket-Protocol": "graphql-ws"}},
            {"label": "ws-extensions", "path": self.base_path,
             "headers": {"Sec-WebSocket-Extensions": "permessage-deflate"}},
            {"label": "ws-auth-null", "path": self.base_path,
             "headers": {"Authorization": "Bearer null"}},
            {"label": "ws-cookie-admin", "path": self.base_path,
             "headers": {"Cookie": "role=admin"}},
        ]
        results: List[DiffExplanation] = []
        for v in variants:
            status, hdrs = await loop.run_in_executor(
                None, ws_handshake, self.host, self.port,
                self.use_tls, v["path"], v["headers"])
            accepted = status == 101
            signals: List[Signal] = []
            if accepted:
                signals.append(Signal(
                    kind="ws_upgrade_accepted",
                    rules_out="nothing - websocket upgrade accepted",
                    detail=f"101 for {v['label']}",
                    severity_weight=0.2,
                ))
            if accepted and v["label"] in ("ws-origin-evil", "ws-origin-null"):
                signals.append(Signal(
                    kind="ws_origin_not_enforced",
                    rules_out="stable origin policy on ws upgrade",
                    detail=f"upgrade accepted with Origin={v['headers']['Origin']!r}",
                    severity_weight=0.5,
                ))
            if accepted and v["label"] == "ws-auth-null":
                signals.append(Signal(
                    kind="ws_auth_ignored",
                    rules_out="stable auth on ws upgrade",
                    detail="upgrade accepted with garbage bearer",
                    severity_weight=0.5,
                ))
            snap = LayerSnapshot(
                layer=Layer.UNKNOWN, headers=hdrs, status=status,
                body_hash="", body_len=0, title="", technologies=[],
                raw_headers="", notes=[f"ws_probe={v['label']}"],
            )
            positive = [s for s in signals if s.severity_weight > 0]
            interesting = len(positive) >= 2
            d = DiffExplanation(
                baseline=baseline, variant=snap,
                status_delta=(baseline.status, status),
                header_delta={}, body_delta=0,
                relationship=(f"Variant '{v['label']}' [ws] tests: upgrade behavior. "
                              f"status={status}."),
                boundary=Boundary.ORIGIN_APP,
                violation_evidence=[s.detail for s in positive],
                normal_explanations_ruled_out=[s.rules_out for s in positive],
                confidence=min(0.92, max(0.15, sum(s.severity_weight for s in positive))),
                interesting=interesting, signals=signals, hypotheses=[],
                baseline_url=self.base_path, variant_url=v["path"],
                variant_method="WS-UPGRADE",
            )
            results.append(d)
        return results


# ---------------------------------------------------------------- auth v5

@dataclass
class AuthConfigV5(AuthConfig):
    format: str = "form"           # form | json
    totp_secret: str = ""
    totp_field: str = "totp"
    verify_url: str = ""
    verify_contains: str = ""
    verify_excludes: str = ""
    basic_auth: str = ""           # "user:pass"
    bearer: str = ""
    inject_cookie: str = ""


class AuthenticatorV5:
    def __init__(self, http: HttpEngine):
        self.http = http

    async def login(self, cfg: AuthConfigV5) -> Tuple[bool, List[str]]:
        notes: List[str] = []
        if cfg.basic_auth:
            tok = base64.b64encode(cfg.basic_auth.encode()).decode()
            self.http.session.headers["Authorization"] = f"Basic {tok}"
            notes.append("basic_auth_set")
        if cfg.bearer:
            self.http.session.headers["Authorization"] = f"Bearer {cfg.bearer}"
            notes.append("bearer_set")
        if cfg.inject_cookie:
            for part in cfg.inject_cookie.split(";"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    self.http.session.cookie_jar.update_cookies({k.strip(): v.strip()})
            notes.append("cookie_injected")

        if not cfg.login_url:
            return True, notes or ["no_login_configured"]

        base_ok, base_notes = await Authenticator(self.http).login(
            AuthConfig(
                login_url=cfg.login_url,
                username=cfg.username, password=cfg.password,
                username_field=cfg.username_field,
                password_field=cfg.password_field,
                csrf_field=cfg.csrf_field, csrf_meta=cfg.csrf_meta,
                extra_fields=cfg.extra_fields,
                success_marker=cfg.success_marker,
            ))
        notes.extend(base_notes)

        if cfg.totp_secret and _TOTP_OK:
            try:
                code = pyotp.TOTP(cfg.totp_secret).now()
                body_data = {
                    cfg.username_field: cfg.username,
                    cfg.password_field: cfg.password,
                    cfg.totp_field: code,
                }
                body = "&".join(f"{k}={v}" for k, v in body_data.items()).encode()
                await self.http.fetch(cfg.login_url, method="POST",
                                      headers={"Content-Type":
                                               "application/x-www-form-urlencoded"},
                                      body=body, allow_redirects=True)
                notes.append("totp_submitted")
            except Exception:
                notes.append("totp_failed")

        if cfg.verify_url:
            vsnap = await self.http.fetch(cfg.verify_url, allow_redirects=False)
            if vsnap and vsnap.status == 200:
                text = vsnap.body_raw.decode("utf-8", errors="ignore")
                if cfg.verify_contains and cfg.verify_contains not in text:
                    notes.append("verify_missing_marker")
                    return False, notes
                if cfg.verify_excludes and cfg.verify_excludes in text:
                    notes.append("verify_has_exclusion_marker")
                    return False, notes
                notes.append("verify_ok")
                return True, notes
            else:
                notes.append(f"verify_status={vsnap.status if vsnap else 0}")
                return False, notes

        return base_ok, notes


# ---------------------------------------------------------------- CLI

def _bind_probes_to_target(probes: List[Dict[str, Any]]) -> None:
    """No-op placeholder for probes that need target-bound data."""
    return None


async def v5_main(args) -> int:
    if not args.no_banner:
        animate_banner(enable=True, delay=0.02 if args.fast_banner else 0.04)

    if args.diff:
        print(diff_two_reports(args.diff[0], args.diff[1]))
        return 0

    if args.refresh_edges:
        print("[*] Refreshing edge ranges")
        r = await refresh_edge_ranges(force=True)
        for k, v in r.items():
            print(f"    {k}: {len(v)} ranges")
        return 0

    target = normalize(args.target)
    parsed = urlparse(target)
    host = parsed.netloc.split(":")[0]
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_tls = parsed.scheme == "https"

    timeout = aiohttp.ClientTimeout(total=30, connect=7, sock_read=15)
    connector = aiohttp.TCPConnector(limit=args.c, ssl=False,
                                     enable_cleanup_closed=True)
    jar = aiohttp.CookieJar(unsafe=True)

    async with aiohttp.ClientSession(
            timeout=timeout, connector=connector, cookie_jar=jar) as session:
        http = HttpEngine(session, args.c)

        auth_ok = False
        if (args.auth_login or args.auth_basic or args.auth_bearer
                or args.auth_cookie or args.auth_verify):
            acfg = AuthConfigV5(
                login_url=args.auth_login or "",
                username=args.auth_user or "",
                password=args.auth_pass or "",
                username_field=args.auth_user_field,
                password_field=args.auth_pass_field,
                csrf_field=args.auth_csrf_field,
                csrf_meta=args.auth_csrf_meta,
                success_marker=args.auth_success_marker,
                format=args.auth_format,
                totp_secret=args.auth_totp or "",
                totp_field=args.auth_totp_field,
                verify_url=args.auth_verify or "",
                verify_contains=args.auth_verify_contains or "",
                verify_excludes=args.auth_verify_excludes or "",
                basic_auth=args.auth_basic or "",
                bearer=args.auth_bearer or "",
                inject_cookie=args.auth_cookie or "",
            )
            auth_ok, notes = await AuthenticatorV5(http).login(acfg)
            print(f"[*] Auth: {'OK' if auth_ok else 'FAILED'}")
            for n in notes:
                print(f"    {n}")

        print("[*] Fingerprinting main surface")
        finger = LayerFingerprinter(http)
        main_snap = await finger.snapshot(target)
        if main_snap.status == 0:
            print(f"[!] ABORT: unreachable. notes={main_snap.notes}")
            return 2

        arch = classify_architecture(main_snap)
        print(f"[*] Architecture: front_end={arch.front_end} "
              f"edge={arch.edge_tech} origin={arch.origin_tech}")

        print("[*] Loading edge ranges")
        ranges = await refresh_edge_ranges(force=False)
        if main_snap.headers:
            pass  # ranges used by origin engine below via monkey-patch

        print("[*] Origin candidate discovery")
        origin_eng = OriginCandidateEngine(http)
        candidates = await origin_eng.discover(host, main_snap,
                                               port=port, scheme=parsed.scheme)
        for c in candidates:
            if c.classification not in ("public-endpoint", "edge-ip"):
                continue
            cdn = ip_in_ranges(c.ip_or_host, ranges)
            if cdn and c.classification != "edge-ip":
                c.classification = "edge-ip"
                c.confirmed = False

        print("[*] Assumption extraction")
        assume_eng = AssumptionEngine()
        assumptions = assume_eng.extract(main_snap, candidates, arch)

        print("[*] Differential probes (aiohttp)")
        validator = Validator(http) if not args.no_validate else None
        v4_differ = ExplainedDifferV4(http, validator=validator,
                                       enable_validation=not args.no_validate,
                                       target_host=host, target_port=port,
                                       use_tls=use_tls)
        v5_probes = build_v5_aiohttp_probes(host)
        v4_differ.aiohttp_probes = v4_differ.aiohttp_probes + v5_probes
        diffs = await v4_differ.run(target, main_snap)

        proto = args.proto
        if proto in ("h2", "both") and _HTTPX_OK:
            print(f"[*] Differential probes (HTTP/2, {len(v5_probes)} variants)")
            try:
                h2r = H2ProbeRunner(target)
                h2_diffs = await h2r.run(v5_probes, main_snap)
                diffs.extend(h2_diffs)
            except Exception as e:
                print(f"    h2 runner failed: {e}")

        if args.ws:
            print("[*] WebSocket upgrade probes")
            ws_path = args.ws_path or "/"
            wsr = WSProbeRunner(host, port, use_tls, ws_path)
            ws_diffs = await wsr.run(main_snap)
            diffs.extend(ws_diffs)

        print("[*] Contradiction analysis")
        contras = assume_eng.find_contradictions(assumptions, diffs,
                                                 candidates, main_snap, arch)

        finder = FindingBuilder()
        findings = []
        for i, c in enumerate(contras, 1):
            findings.append(finder.from_contradiction(c, i))
        for i, d in enumerate(diffs, 1):
            f = finder.from_diff(d, i)
            if f:
                findings.append(f)
        for i, oc in enumerate(candidates, 1):
            f = finder.from_origin(oc, i, has_front_end=arch.front_end)
            if f:
                findings.append(f)

        seen = set()
        unique = []
        for f in findings:
            sig = f.title + "|" + f.boundary_crossed.value
            if sig not in seen:
                seen.add(sig)
                unique.append(f)

        now = datetime.now(timezone.utc).isoformat()
        report = Report(
            target=target, started=now, finished=now,
            architecture=arch, layers={"main": main_snap},
            assumptions=assumptions, contradictions=contras,
            origin_candidates=candidates, diffs=diffs, findings=unique,
        )

        all_probes = v4_differ.aiohttp_probes + v4_differ.raw_probes
        stats = family_stats(diffs, all_probes)
        high = sum(1 for f in unique if f.severity in ("high", "critical"))
        med = sum(1 for f in unique if f.severity == "medium")
        report.summary = (
            f"Front-end: {'yes' if arch.front_end else 'no'} | "
            f"Probes: {len(diffs)} | "
            f"Assumptions: {len(assumptions)} | "
            f"Contradictions: {len(contras)} | "
            f"Findings: {len(unique)} (high={high}, medium={med}) | "
            f"Auth: {'yes' if auth_ok else 'no'} | "
            f"Proto: {proto}"
        )

        gen = ReportGenerator()
        text = gen.text(report)
        Path(args.o).write_text(text)
        Path(args.j).write_text(gen.json(report))

        if args.html:
            Path(args.html).write_text(render_html_report(report, all_probes))
            print(f"[+] {args.html}")

        if args.families:
            print()
            print(f"{'family':<20}{'total':>7}{'sig':>6}{'int':>6}{'valid':>7}")
            print("-" * 46)
            for fam in sorted(stats):
                s = stats[fam]
                print(f"{fam:<20}{s['total']:>7}{s['signals']:>6}"
                      f"{s['interesting']:>6}{s['validated']:>7}")

        if args.json_only:
            print(json.dumps({
                "target": report.target, "summary": report.summary,
                "findings": len(report.findings), "high": high,
                "auth": auth_ok, "proto": proto,
            }, indent=2))
        else:
            print(text)

        print(f"\n[+] {args.o}")
        print(f"[+] {args.j}")
        return 1 if high else 0


def main():
    ap = argparse.ArgumentParser(prog="webpt_v5",
                                 description="WebPT v5 — full-scope boundary mapper")
    ap.add_argument("target", nargs="?", default="")
    ap.add_argument("-o", default="webpt_v5_report.txt")
    ap.add_argument("-j", default="webpt_v5_report.json")
    ap.add_argument("--html", default="")
    ap.add_argument("-c", type=int, default=12)
    ap.add_argument("--no-validate", action="store_true")
    ap.add_argument("--json-only", action="store_true")
    ap.add_argument("--families", action="store_true")
    ap.add_argument("--no-banner", action="store_true")
    ap.add_argument("--fast-banner", action="store_true")
    ap.add_argument("--diff", nargs=2, metavar=("OLD", "NEW"), default=None)
    ap.add_argument("--refresh-edges", action="store_true")
    ap.add_argument("--proto", choices=["h1", "h2", "both"], default="h1")
    ap.add_argument("--ws", action="store_true",
                    help="run websocket upgrade probes")
    ap.add_argument("--ws-path", default="/")
    # auth
    ap.add_argument("--auth-login", default="")
    ap.add_argument("--auth-user", default="")
    ap.add_argument("--auth-pass", default="")
    ap.add_argument("--auth-user-field", default="username")
    ap.add_argument("--auth-pass-field", default="password")
    ap.add_argument("--auth-csrf-field", default=None)
    ap.add_argument("--auth-csrf-meta", default=None)
    ap.add_argument("--auth-success-marker", default=None)
    ap.add_argument("--auth-format", choices=["form", "json"], default="form")
    ap.add_argument("--auth-totp", default=None)
    ap.add_argument("--auth-totp-field", default="totp")
    ap.add_argument("--auth-basic", default=None,
                    help="user:pass for HTTP Basic")
    ap.add_argument("--auth-bearer", default=None)
    ap.add_argument("--auth-cookie", default=None,
                    help="name=value[; name=value...]")
    ap.add_argument("--auth-verify", default=None,
                    help="URL to GET after login; 200 required")
    ap.add_argument("--auth-verify-contains", default=None)
    ap.add_argument("--auth-verify-excludes", default=None)
    args = ap.parse_args()
    if args.diff or args.refresh_edges:
        sys.exit(asyncio.run(v5_main(args)))
    if not args.target:
        ap.print_usage(sys.stderr)
        sys.exit(2)
    sys.exit(asyncio.run(v5_main(args)))


if __name__ == "__main__":
    main()
