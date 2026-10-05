#!/usr/bin/env python3
"""
WebPT v4 — extends v3.1 with authenticated probing, POST body differentials,
chunked-smuggling primitives via raw sockets, host-header matrix, Range
differentials, HTML reporting, per-family statistics, and run diffing.
"""
from __future__ import annotations
import argparse
import asyncio
import html as htmlmod
import json
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

from banner import animate_banner, banner_static
import webpt_v2 as base
from webpt_v2 import (
    Layer, Boundary, Assumption, Contradiction, OriginCandidate, Finding,
    LayerSnapshot, Signal, Hypothesis, DiffExplanation, Report, Architecture,
    HttpEngine, LayerFingerprinter, OriginCandidateEngine, AssumptionEngine,
    Validator, FindingBuilder, ReportGenerator,
    classify_architecture, extract_signals, score_hypotheses,
    normalize, sha16,
)


# ================================================================ auth

@dataclass
class AuthConfig:
    login_url: str
    username: str
    password: str
    username_field: str = "username"
    password_field: str = "password"
    csrf_field: Optional[str] = None
    csrf_meta: Optional[str] = None
    extra_fields: Dict[str, str] = field(default_factory=dict)
    success_marker: Optional[str] = None


class Authenticator:
    def __init__(self, http: HttpEngine):
        self.http = http

    async def login(self, cfg: AuthConfig) -> Tuple[bool, List[str]]:
        notes: List[str] = []
        snap = await self.http.fetch(cfg.login_url, allow_redirects=True)
        if not snap or snap.status == 0:
            return False, ["login_page_unreachable"]
        body_text = snap.body_raw.decode("utf-8", errors="ignore")

        csrf_field = cfg.csrf_field
        csrf_value: Optional[str] = None

        if cfg.csrf_meta:
            m = re.search(
                rf'<meta[^>]+name=["\']{re.escape(cfg.csrf_meta)}["\'][^>]+content=["\']([^"\']+)',
                body_text, re.I)
            if m:
                csrf_value = m.group(1)
                csrf_field = csrf_field or cfg.csrf_meta
                notes.append(f"csrf_from_meta:{csrf_field}")

        if not csrf_value:
            for m in re.finditer(
                r'<input[^>]+name=["\']([^"\']*csrf[^"\']*)["\'][^>]*value=["\']([^"\']+)["\']',
                body_text, re.I):
                csrf_field = m.group(1)
                csrf_value = m.group(2)
                notes.append(f"csrf_from_input:{csrf_field}")
                break

        data: Dict[str, str] = {
            cfg.username_field: cfg.username,
            cfg.password_field: cfg.password,
        }
        if csrf_field and csrf_value:
            data[csrf_field] = csrf_value
        data.update(cfg.extra_fields)

        body = "&".join(f"{k}={v}" for k, v in data.items()).encode()
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        login_snap = await self.http.fetch(
            cfg.login_url, method="POST", headers=headers,
            body=body, allow_redirects=True)
        if not login_snap or login_snap.status == 0:
            return False, notes + ["login_post_failed"]

        text2 = login_snap.body_raw.decode("utf-8", errors="ignore")
        if cfg.success_marker:
            ok = cfg.success_marker in text2
        else:
            ok = (login_snap.body_hash != snap.body_hash
                  or login_snap.status != snap.status)
        if not ok:
            notes.append("success_marker_not_seen")

        jar_keys = [c.key for c in self.http.session.cookie_jar]
        if not jar_keys:
            return False, notes + ["no_cookies_after_login"]
        notes.append("cookies:" + ",".join(jar_keys))
        return ok, notes


# ================================================================ raw HTTP

def raw_http_request(host: str, port: int, use_tls: bool,
                     request_bytes: bytes, timeout: float = 8.0,
                     read_limit: int = 512_000) -> bytes:
    """Send raw bytes over TCP/TLS, return response bytes."""
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(request_bytes)
        sock.settimeout(timeout)
        chunks: List[bytes] = []
        total = 0
        while True:
            try:
                data = sock.recv(65536)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
            total += len(data)
            if total > read_limit:
                break
        return b"".join(chunks)
    finally:
        try:
            sock.close()
        except Exception:
            pass


def parse_raw_response(raw: bytes) -> Optional[LayerSnapshot]:
    if not raw:
        return None
    if b"\r\n\r\n" in raw:
        head, body = raw.split(b"\r\n\r\n", 1)
    elif b"\n\n" in raw:
        head, body = raw.split(b"\n\n", 1)
    else:
        return None
    head_lines = head.decode("latin-1", errors="replace").split("\n")
    if not head_lines:
        return None
    m = re.match(r"HTTP/[\d.]+ (\d+)", head_lines[0].strip())
    status = int(m.group(1)) if m else 0
    hdrs: Dict[str, str] = {}
    for line in head_lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    body = body[:1_000_000]
    return LayerSnapshot(
        layer=Layer.UNKNOWN, headers=hdrs, status=status,
        body_hash=sha16(body), body_len=len(body),
        title="", technologies=[],
        raw_headers=head.decode("latin-1", errors="replace"),
        notes=[], body_raw=body, elapsed_ms=0,
        body_hash_norm=sha16(body),
    )


# ================================================================ probe families

def build_smuggling_probes(target_host: str) -> List[Dict[str, Any]]:
    probes: List[Dict[str, Any]] = []

    cl_te_body = b"0\r\n\r\nG"
    probes.append({
        "cat": "smuggling_raw", "label": "raw-cl-te",
        "boundary": Boundary.WAF_ORIGIN,
        "tests_assumption": "Front-end and origin agree on framing (CL vs TE)",
        "raw_request": (
            f"POST / HTTP/1.1\r\nHost: {target_host}\r\n"
            f"Content-Length: {len(cl_te_body)}\r\n"
            f"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        ).encode() + cl_te_body,
    })

    te_cl_body = (
        b"5c\r\n"
        b"GET /admin HTTP/1.1\r\nHost: " + target_host.encode() + b"\r\n\r\n"
        b"0\r\n\r\n"
    )
    probes.append({
        "cat": "smuggling_raw", "label": "raw-te-cl",
        "boundary": Boundary.WAF_ORIGIN,
        "tests_assumption": "Front-end and origin agree on framing (TE vs CL)",
        "raw_request": (
            f"POST / HTTP/1.1\r\nHost: {target_host}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        ).encode() + te_cl_body,
    })

    probes.append({
        "cat": "smuggling_raw", "label": "raw-te-obfuscated",
        "boundary": Boundary.WAF_ORIGIN,
        "tests_assumption": "Obfuscated Transfer-Encoding rejected",
        "raw_request": (
            f"POST / HTTP/1.1\r\nHost: {target_host}\r\n"
            f"Transfer-Encoding: xchunked\r\nConnection: close\r\n\r\n0\r\n\r\n"
        ).encode(),
    })

    probes.append({
        "cat": "smuggling_raw", "label": "raw-te-space-colon",
        "boundary": Boundary.WAF_ORIGIN,
        "tests_assumption": "TE with whitespace before colon rejected",
        "raw_request": (
            f"POST / HTTP/1.1\r\nHost: {target_host}\r\n"
            f"Transfer-Encoding : chunked\r\nConnection: close\r\n\r\n0\r\n\r\n"
        ).encode(),
    })

    probes.append({
        "cat": "smuggling_raw", "label": "raw-double-te",
        "boundary": Boundary.WAF_ORIGIN,
        "tests_assumption": "Duplicate Transfer-Encoding rejected",
        "raw_request": (
            f"POST / HTTP/1.1\r\nHost: {target_host}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Transfer-Encoding: identity\r\nConnection: close\r\n\r\n0\r\n\r\n"
        ).encode(),
    })

    return probes


def build_host_probes(target_host: str) -> List[Dict[str, Any]]:
    hosts = [
        ("host-localhost", "localhost"),
        ("host-127", "127.0.0.1"),
        ("host-internal", "internal.local"),
        ("host-port-inject", f"{target_host}:22"),
        ("host-empty", ""),
        ("host-trailing-dot", f"{target_host}."),
        ("host-case-upper", target_host.upper()),
        ("host-userinfo", f"x@{target_host}"),
    ]
    probes: List[Dict[str, Any]] = []
    for label, h in hosts:
        req = (
            f"GET / HTTP/1.1\r\nHost: {h}\r\n"
            f"Connection: close\r\nUser-Agent: WebPT/4.0\r\n\r\n"
        ).encode()
        probes.append({
            "cat": "host_matrix", "label": label,
            "boundary": Boundary.INTERNET_WAF,
            "tests_assumption": f"Host header {h!r} not honored differently",
            "raw_request": req,
        })
    return probes


def build_range_probes() -> List[Dict[str, Any]]:
    return [
        {"cat": "range", "headers": {"Range": "bytes=0-99"},
         "label": "range-first100", "boundary": Boundary.ORIGIN_APP,
         "tests_assumption": "Partial content not exposed without policy"},
        {"cat": "range", "headers": {"Range": "bytes=-1"},
         "label": "range-lastbyte", "boundary": Boundary.ORIGIN_APP,
         "tests_assumption": "Trailing range not exposed"},
        {"cat": "range", "headers": {"Range": "bytes=0-0,-1"},
         "label": "range-multi", "boundary": Boundary.ORIGIN_APP,
         "tests_assumption": "Multi-range not exposed"},
        {"cat": "range", "headers": {"Range": "bytes=99999999-"},
         "label": "range-unsat", "boundary": Boundary.ORIGIN_APP,
         "tests_assumption": "Unsatisfiable range handled identically"},
        {"cat": "range", "headers": {"Range": "bytes=0-99999999"},
         "label": "range-huge", "boundary": Boundary.ORIGIN_APP,
         "tests_assumption": "Oversized range clamped identically"},
    ]


def build_post_probes() -> List[Dict[str, Any]]:
    return [
        {"cat": "post_body", "method": "POST",
         "headers": {"Content-Type": "application/json"},
         "body": b'{"admin":true}', "label": "post-json-admin",
         "boundary": Boundary.ORIGIN_APP,
         "tests_assumption": "JSON body does not bypass authorization"},
        {"cat": "post_body", "method": "POST",
         "headers": {"Content-Type": "application/x-www-form-urlencoded"},
         "body": b'admin=true', "label": "post-form-admin",
         "boundary": Boundary.ORIGIN_APP,
         "tests_assumption": "Form body does not bypass authorization"},
        {"cat": "post_body", "method": "POST",
         "headers": {"Content-Type": "text/plain"},
         "body": b'{"admin":true}', "label": "post-plain-json",
         "boundary": Boundary.ORIGIN_APP,
         "tests_assumption": "Text-plain JSON body rejected identically"},
        {"cat": "post_body", "method": "POST",
         "headers": {"Content-Type": "application/xml"},
         "body": b'<?xml version="1.0"?><root><admin>true</admin></root>',
         "label": "post-xml-admin", "boundary": Boundary.ORIGIN_APP,
         "tests_assumption": "XML body does not bypass authorization"},
        {"cat": "post_body", "method": "POST",
         "headers": {"Content-Type": "application/x-www-form-urlencoded"},
         "body": b'role=user&role=admin', "label": "post-dup-param",
         "boundary": Boundary.ORIGIN_APP,
         "tests_assumption": "Duplicate form parameters resolved identically"},
        {"cat": "post_body", "method": "POST",
         "headers": {"Content-Type": "application/x-www-form-urlencoded"},
         "body": b'role=user%00&role=admin', "label": "post-null-param",
         "boundary": Boundary.ORIGIN_APP,
         "tests_assumption": "Null-byte in form parameter rejected"},
        {"cat": "post_body", "method": "POST",
         "headers": {"Content-Type": "application/json; charset=utf-16"},
         "body": '{"admin":true}'.encode("utf-16"),
         "label": "post-json-utf16", "boundary": Boundary.ORIGIN_APP,
         "tests_assumption": "UTF-16 JSON body rejected identically"},
    ]


# ================================================================ v4 differ

class ExplainedDifferV4:
    def __init__(self, http: HttpEngine, validator: Optional[Validator] = None,
                 enable_validation: bool = True,
                 target_host: str = "", target_port: int = 0,
                 use_tls: bool = True):
        self.http = http
        self.validator = validator
        self.enable_validation = enable_validation
        self.target_host = target_host
        self.target_port = target_port
        self.use_tls = use_tls
        self.aiohttp_probes: List[Dict[str, Any]] = (
            list(base.PROBE_LIBRARY)
            + build_range_probes()
            + build_post_probes()
        )
        self.raw_probes: List[Dict[str, Any]] = (
            build_smuggling_probes(target_host)
            + build_host_probes(target_host)
        )

    async def _run_raw(self, v: Dict[str, Any]) -> Optional[LayerSnapshot]:
        loop = asyncio.get_event_loop()
        t0 = time.monotonic()
        try:
            raw = await loop.run_in_executor(
                None, raw_http_request,
                self.target_host, self.target_port, self.use_tls,
                v["raw_request"], 8.0)
        except Exception:
            raw = b""
        elapsed = int((time.monotonic() - t0) * 1000)
        snap = parse_raw_response(raw)
        if snap is not None:
            snap.elapsed_ms = elapsed
        return snap

    def _build_diff(self, v: Dict[str, Any], main: LayerSnapshot,
                    snap: LayerSnapshot, base_url: str) -> DiffExplanation:
        header_delta: Dict[str, Tuple[str, str]] = {}
        for k in set(main.headers) | set(snap.headers):
            b, a = main.headers.get(k, ""), snap.headers.get(k, "")
            if b != a:
                header_delta[k] = (b, a)
        signals = extract_signals(main, snap, v.get("headers") or {})
        hyps = score_hypotheses(
            signals, variant_headers=v.get("headers") or {},
            baseline=main, variant=snap, variant_path_is_new=True)
        top = hyps[0] if hyps else None
        positive = [s for s in signals if s.severity_weight > 0]
        corroborating = [s for s in positive
                         if s.kind in ("sensitive_header_delta",
                                       "cache_layer_disagreement",
                                       "status_class_shift")]
        agreeing = len(positive) >= 2 and len(corroborating) >= 1
        is_violation = top is not None and top.kind == "boundary_violation"
        conf = min(0.92, max(0.15, sum(s.severity_weight for s in positive)))
        relationship = (
            f"Variant '{v['label']}' [{v.get('cat','general')}] tests assumption: "
            f"{v['tests_assumption']}. Baseline layer~{main.layer.value}, variant status={snap.status}."
        )
        return DiffExplanation(
            baseline=main, variant=snap,
            status_delta=(main.status, snap.status),
            header_delta=header_delta,
            body_delta=snap.body_len - main.body_len,
            relationship=relationship,
            boundary=v["boundary"],
            violation_evidence=[s.detail for s in positive],
            normal_explanations_ruled_out=[s.rules_out for s in positive],
            confidence=conf,
            interesting=is_violation and agreeing,
            signals=signals, hypotheses=hyps,
            baseline_url=base_url, variant_url=base_url,
            variant_method=v.get("method", "GET"),
            variant_headers=v.get("headers") or {},
        )

    async def run(self, base_url: str,
                  main: LayerSnapshot) -> List[DiffExplanation]:
        sem = asyncio.Semaphore(8)

        async def one_aio(v):
            async with sem:
                url = base_url.rstrip("/") + v.get("path_suffix", "")
                method = v.get("method", "GET")
                v_headers = v.get("headers") or {}
                v_body = v.get("body")
                try:
                    snap = await self.http.fetch(
                        url, method=method, headers=v_headers,
                        allow_redirects=False, body=v_body)
                except Exception:
                    return None
                if not snap or snap.status == 0:
                    return None
                d = self._build_diff(v, main, snap, base_url)
                return (v, d, snap)

        raw_aio = await asyncio.gather(*(one_aio(v) for v in self.aiohttp_probes))

        results: List[DiffExplanation] = []
        interesting_pairs: List[Tuple[Dict, DiffExplanation, LayerSnapshot]] = []

        for item in raw_aio:
            if item is None:
                continue
            v, d, snap = item
            results.append(d)
            if d.interesting:
                interesting_pairs.append((v, d, snap))

        for v in self.raw_probes:
            snap = await self._run_raw(v)
            if snap is None or snap.status == 0:
                continue
            d = self._build_diff(v, main, snap, base_url)
            results.append(d)
            if d.interesting:
                interesting_pairs.append((v, d, snap))

        if self.enable_validation:
            for v, d, snap in interesting_pairs:
                if "raw_request" in v:
                    snap2 = await self._run_raw(v)
                    if snap2 is None:
                        d.validation_reproduced = False
                        d.validation_notes = ["raw_reprobe_failed"]
                    else:
                        same = (snap2.status == snap.status
                                and snap2.body_hash == snap.body_hash)
                        d.validation_reproduced = same
                        d.validation_notes = ([] if same else
                                              [f"raw_variant_not_reproduced: {snap.body_hash} != {snap2.body_hash}"])
                        if not same:
                            d.interesting = False
                            d.normal_explanations_ruled_out.append(
                                "validation failed - raw delta not reproducible")
                elif self.validator is not None:
                    ok, notes = await self.validator.validate(base_url, v, main, snap)
                    d.validation_reproduced = ok
                    d.validation_notes = notes
                    if not ok:
                        d.interesting = False
                        d.normal_explanations_ruled_out.append(
                            "validation failed - delta not reproducible")
        return results


# ================================================================ family stats

def family_stats(diffs: List[DiffExplanation],
                 probes: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    label_to_family = {p["label"]: p.get("cat", "unknown") for p in probes}
    stats: Dict[str, Dict[str, int]] = {}
    for d in diffs:
        m = re.search(r"Variant '([^']+)'", d.relationship or "")
        label = m.group(1) if m else "?"
        fam = label_to_family.get(label, "unknown")
        s = stats.setdefault(fam, {"total": 0, "signals": 0,
                                   "interesting": 0, "validated": 0})
        s["total"] += 1
        if d.signals:
            s["signals"] += 1
        if d.interesting:
            s["interesting"] += 1
        if d.validation_reproduced:
            s["validated"] += 1
    return stats


# ================================================================ HTML report

HTML_CSS = """
body{background:#0d1117;color:#c9d1d9;font-family:ui-monospace,SFMono-Regular,monospace;
margin:0;padding:24px;line-height:1.5}
h1,h2,h3{color:#58a6ff;border-bottom:1px solid #30363d;padding-bottom:6px}
pre,code{background:#161b22;padding:2px 6px;border-radius:4px;color:#a5d6ff}
pre{padding:12px;overflow-x:auto}
table{border-collapse:collapse;width:100%;margin:12px 0}
th,td{border:1px solid #30363d;padding:6px 10px;text-align:left;vertical-align:top}
th{background:#161b22;color:#58a6ff}
.sev-high{color:#f85149;font-weight:bold}
.sev-critical{color:#ff7b72;font-weight:bold}
.sev-medium{color:#d29922;font-weight:bold}
.sev-low,.sev-info{color:#8b949e}
.signal{color:#7ee787}
.banner{white-space:pre;color:#58a6ff;font-size:11px;line-height:1}
.meta{color:#8b949e;font-size:13px}
.finding{border-left:3px solid #f85149;padding-left:12px;margin:12px 0}
"""


def _esc(s: Any) -> str:
    return htmlmod.escape(str(s), quote=True)


def render_html_report(report: Report,
                       probes: List[Dict[str, Any]]) -> str:
    stats = family_stats(report.diffs, probes)
    out: List[str] = []
    out.append("<!doctype html><html><head><meta charset='utf-8'>")
    out.append(f"<title>WebPT v4 — {_esc(report.target)}</title>")
    out.append(f"<style>{HTML_CSS}</style></head><body>")
    out.append(f"<div class='banner'>{_esc(banner_static())}</div>")
    out.append("<h1>WebPT v4 Report</h1><table>")
    out.append(f"<tr><th>Target</th><td>{_esc(report.target)}</td></tr>")
    out.append(f"<tr><th>Started</th><td>{_esc(report.started)}</td></tr>")
    out.append(f"<tr><th>Finished</th><td>{_esc(report.finished)}</td></tr>")
    if report.architecture:
        a = report.architecture
        out.append(f"<tr><th>Front-end</th><td>{a.front_end}</td></tr>")
        out.append(f"<tr><th>Edge</th><td>{_esc(a.edge_tech or '-')}</td></tr>")
        out.append(f"<tr><th>Origin</th><td>{_esc(a.origin_tech or '-')}</td></tr>")
    out.append("</table>")

    out.append(f"<h2>Findings ({len(report.findings)})</h2>")
    if not report.findings:
        out.append("<p><em>none</em></p>")
    for f in report.findings:
        cls = f"sev-{f.severity}"
        out.append(f"<div class='finding'><h3 class='{cls}'>"
                   f"[{_esc(f.severity.upper())}] {_esc(f.id)} — {_esc(f.title)}</h3>")
        out.append(f"<p class='meta'>boundary: {_esc(f.boundary_crossed.value)}"
                   f" | confidence: {f.confidence:.2f}</p>")
        if f.preconditions:
            out.append("<p><strong>Preconditions</strong></p><ul>")
            for x in f.preconditions:
                out.append(f"<li>{_esc(x)}</li>")
            out.append("</ul>")
        if f.validation:
            out.append("<p><strong>Validation</strong></p><ul>")
            for x in f.validation:
                out.append(f"<li>{_esc(x)}</li>")
            out.append("</ul>")
        if f.baseline_curl:
            out.append(f"<p><strong>Reproduce baseline</strong></p><pre>{_esc(f.baseline_curl)}</pre>")
        if f.variant_curl:
            out.append(f"<p><strong>Reproduce variant</strong></p><pre>{_esc(f.variant_curl)}</pre>")
        if f.remediation:
            out.append(f"<p><strong>Remediation</strong>: {_esc(f.remediation)}</p>")
        out.append("</div>")

    out.append("<h2>Per-family statistics</h2>")
    out.append("<table><tr><th>Family</th><th>Total</th><th>Signals</th>"
               "<th>Interesting</th><th>Validated</th></tr>")
    for fam in sorted(stats):
        s = stats[fam]
        out.append(f"<tr><td>{_esc(fam)}</td><td>{s['total']}</td>"
                   f"<td>{s['signals']}</td><td>{s['interesting']}</td>"
                   f"<td>{s['validated']}</td></tr>")
    out.append("</table>")

    out.append("<h2>Probes</h2>")
    out.append("<table><tr><th>Probe</th><th>Family</th><th>Status</th>"
               "<th>Signals</th><th>Top hypothesis</th></tr>")
    for d in report.diffs:
        m = re.search(r"Variant '([^']+)'", d.relationship or "")
        label = m.group(1) if m else "?"
        fam = next((p.get("cat", "?") for p in probes if p["label"] == label), "?")
        sigs = ", ".join(s.kind for s in d.signals)
        top = d.hypotheses[0].name if d.hypotheses else "-"
        out.append(f"<tr><td>{_esc(label)}</td><td>{_esc(fam)}</td>"
                   f"<td>{d.status_delta[0]}→{d.status_delta[1]}</td>"
                   f"<td class='signal'>{_esc(sigs)}</td>"
                   f"<td>{_esc(top)}</td></tr>")
    out.append("</table>")

    out.append("<h2>Unconfirmed diffs</h2>")
    unconfirmed = [d for d in report.diffs if d.signals and not d.interesting]
    if not unconfirmed:
        out.append("<p><em>none</em></p>")
    else:
        out.append("<table><tr><th>Probe</th><th>Signals</th>"
                   "<th>Top hypothesis</th></tr>")
        for d in unconfirmed:
            m = re.search(r"Variant '([^']+)'", d.relationship or "")
            label = m.group(1) if m else "?"
            sigs = ", ".join(s.kind for s in d.signals)
            top = d.hypotheses[0].name if d.hypotheses else "-"
            out.append(f"<tr><td>{_esc(label)}</td><td>{_esc(sigs)}</td>"
                       f"<td>{_esc(top)}</td></tr>")
        out.append("</table>")

    out.append(f"<p class='meta'>{_esc(report.summary)}</p>")
    out.append("</body></html>")
    return "".join(out)


# ================================================================ run diff

def _finding_sig(f: Dict[str, Any]) -> str:
    return f"{f.get('boundary_crossed','')}|{f.get('title','')}"


def diff_two_reports(old_path: str, new_path: str) -> str:
    with open(old_path) as fh:
        old = json.load(fh)
    with open(new_path) as fh:
        new = json.load(fh)
    old_finds = {_finding_sig(f): f for f in old.get("findings", [])}
    new_finds = {_finding_sig(f): f for f in new.get("findings", [])}
    added = [new_finds[k] for k in new_finds if k not in old_finds]
    resolved = [old_finds[k] for k in old_finds if k not in new_finds]
    retained = [new_finds[k] for k in new_finds if k in old_finds]

    lines: List[str] = []
    lines.append("=" * 78)
    lines.append("WebPT v4 — run diff")
    lines.append(f"OLD: {old.get('target')} @ {old.get('finished')}")
    lines.append(f"NEW: {new.get('target')} @ {new.get('finished')}")
    lines.append("=" * 78)
    lines.append(f"\nADDED ({len(added)}):")
    for f in added:
        lines.append(f"  [{f['severity']}] {f['title']}")
        lines.append(f"      boundary: {f['boundary_crossed']}")
    lines.append(f"\nRESOLVED ({len(resolved)}):")
    for f in resolved:
        lines.append(f"  [{f['severity']}] {f['title']}")
        lines.append(f"      boundary: {f['boundary_crossed']}")
    lines.append(f"\nRETAINED ({len(retained)}):")
    for f in retained:
        lines.append(f"  [{f['severity']}] {f['title']}")
    lines.append("\n" + "=" * 78)
    return "\n".join(lines)


# ================================================================ CLI

async def v4_main(args) -> int:
    if not args.no_banner:
        animate_banner(enable=True, delay=0.02 if args.fast_banner else 0.04)

    if args.diff:
        print(diff_two_reports(args.diff[0], args.diff[1]))
        return 0

    target = normalize(args.target)
    parsed = urlparse(target)
    host = parsed.netloc.split(":")[0]
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_tls = parsed.scheme == "https"

    timeout = aiohttp.ClientTimeout(total=30, connect=7, sock_read=15)
    connector = aiohttp.TCPConnector(limit=args.c, ssl=False, enable_cleanup_closed=True)
    jar = aiohttp.CookieJar(unsafe=True)

    async with aiohttp.ClientSession(
            timeout=timeout, connector=connector, cookie_jar=jar) as session:
        http = HttpEngine(session, args.c)

        auth_ok = False
        if args.auth_login:
            cfg = AuthConfig(
                login_url=args.auth_login,
                username=args.auth_user or "",
                password=args.auth_pass or "",
                username_field=args.auth_user_field,
                password_field=args.auth_pass_field,
                csrf_field=args.auth_csrf_field,
                csrf_meta=args.auth_csrf_meta,
                success_marker=args.auth_success_marker,
            )
            auth_ok, notes = await Authenticator(http).login(cfg)
            print(f"[*] Auth login: {'OK' if auth_ok else 'FAILED'}")
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

        print("[*] Origin candidate discovery")
        origin_eng = OriginCandidateEngine(http)
        candidates = await origin_eng.discover(host, main_snap,
                                               port=port, scheme=parsed.scheme)

        print("[*] Assumption extraction")
        assume_eng = AssumptionEngine()
        assumptions = assume_eng.extract(main_snap, candidates, arch)

        print("[*] Differential probes")
        validator = Validator(http) if not args.no_validate else None
        differ = ExplainedDifferV4(
            http, validator=validator,
            enable_validation=not args.no_validate,
            target_host=host, target_port=port, use_tls=use_tls)
        diffs = await differ.run(target, main_snap)

        print("[*] Contradiction analysis")
        contras = assume_eng.find_contradictions(assumptions, diffs,
                                                 candidates, main_snap, arch)

        finder = FindingBuilder()
        findings: List[Finding] = []
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
        unique: List[Finding] = []
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

        all_probes = differ.aiohttp_probes + differ.raw_probes
        stats = family_stats(diffs, all_probes)
        high = sum(1 for f in unique if f.severity in ("high", "critical"))
        med = sum(1 for f in unique if f.severity == "medium")
        report.summary = (
            f"Front-end: {'yes' if arch.front_end else 'no'} | "
            f"Probes: {len(diffs)} | "
            f"Assumptions: {len(assumptions)} | "
            f"Contradictions: {len(contras)} | "
            f"Findings: {len(unique)} (high={high}, medium={med}) | "
            f"Auth: {'yes' if auth_ok else 'no'}"
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
            print(f"{'family':<18}{'total':>7}{'sig':>6}{'int':>6}{'valid':>7}")
            print("-" * 44)
            for fam in sorted(stats):
                s = stats[fam]
                print(f"{fam:<18}{s['total']:>7}{s['signals']:>6}"
                      f"{s['interesting']:>6}{s['validated']:>7}")

        if args.json_only:
            print(json.dumps({
                "target": report.target,
                "summary": report.summary,
                "findings": len(report.findings),
                "high": high,
            }, indent=2))
        else:
            print(text)

        print(f"\n[+] {args.o}")
        print(f"[+] {args.j}")

        return 1 if high else 0


def main():
    ap = argparse.ArgumentParser(
        prog="webpt_v4",
        description="WebPT v4 — extended boundary mapper")
    ap.add_argument("target", nargs="?", default="")
    ap.add_argument("-o", default="webpt_v4_report.txt")
    ap.add_argument("-j", default="webpt_v4_report.json")
    ap.add_argument("--html", default="")
    ap.add_argument("-c", type=int, default=12)
    ap.add_argument("--no-validate", action="store_true")
    ap.add_argument("--json-only", action="store_true")
    ap.add_argument("--families", action="store_true")
    ap.add_argument("--no-banner", action="store_true")
    ap.add_argument("--fast-banner", action="store_true")
    ap.add_argument("--diff", nargs=2, metavar=("OLD", "NEW"), default=None)
    ap.add_argument("--auth-login", default="")
    ap.add_argument("--auth-user", default="")
    ap.add_argument("--auth-pass", default="")
    ap.add_argument("--auth-user-field", default="username")
    ap.add_argument("--auth-pass-field", default="password")
    ap.add_argument("--auth-csrf-field", default=None)
    ap.add_argument("--auth-csrf-meta", default=None)
    ap.add_argument("--auth-success-marker", default=None)
    args = ap.parse_args()
    if args.diff:
        sys.exit(asyncio.run(v4_main(args)))
    if not args.target:
        ap.print_usage(sys.stderr)
        sys.exit(2)
    sys.exit(asyncio.run(v4_main(args)))


if __name__ == "__main__":
    main()
