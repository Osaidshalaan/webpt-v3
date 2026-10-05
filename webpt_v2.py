#!/usr/bin/env python3
"""
WebPT v3 — Assumption Engine + Boundary Violation Mapper

v3 changes over v2:
  - Architecture classification is a single function (front_end yes/no).
  - Signal taxonomy: each signal reports what it saw and what it rules out.
  - Hypothesis scoring: benign vs boundary_violation. interesting requires 2+ signals.
  - Validation pass: interesting diffs must reproduce on a clean connection.
  - Findings carry curl proof strings.
  - Three-bucket report: findings / unconfirmed / ruled-out.
"""

from __future__ import annotations
import asyncio
import hashlib
import json
import re
import ssl
import socket
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import aiohttp
import dns.resolver
from aiohttp import ClientSession, ClientTimeout, TCPConnector
from bs4 import BeautifulSoup


# ---------------------------------------------------------------------------
# Enums & Core Models
# ---------------------------------------------------------------------------

class Layer(str, Enum):
    INTERNET = "internet"
    WAF = "waf"
    PROXY = "proxy"
    ORIGIN = "origin"
    APP = "app"
    UNKNOWN = "unknown"


class Boundary(str, Enum):
    INTERNET_WAF = "internet→waf"
    WAF_PROXY = "waf→proxy"
    PROXY_ORIGIN = "proxy→origin"
    ORIGIN_APP = "origin→app"
    INTERNET_ORIGIN = "internet→origin"
    WAF_ORIGIN = "waf→origin"
    CUSTOM = "custom"


@dataclass
class Architecture:
    front_end: bool = False
    edge_tech: Optional[str] = None
    proxy_tech: Optional[str] = None
    origin_tech: Optional[str] = None
    app_tech: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)


@dataclass
class Assumption:
    layer: Layer
    statement: str
    source: str
    confidence: float = 0.5


@dataclass
class Contradiction:
    assumption_a: Assumption
    assumption_b: Assumption
    observed_behavior: str
    explanation: str
    boundary: Boundary
    evidence: List[str] = field(default_factory=list)
    confidence: float = 0.0


@dataclass
class OriginCandidate:
    ip_or_host: str
    source: str
    confidence: float = 0.0
    dns_relationship: str = ""
    http_fingerprint: Dict[str, Any] = field(default_factory=dict)
    tls_fingerprint: Dict[str, Any] = field(default_factory=dict)
    app_similarity: float = 0.0
    relationship_evidence: List[str] = field(default_factory=list)
    confirmed: bool = False
    classification: str = "unknown"


@dataclass
class Finding:
    id: str
    title: str
    discovery_evidence: List[str]
    boundary_crossed: Boundary
    preconditions: List[str]
    validation: List[str]
    impact_evidence: List[str]
    confidence: float
    remediation: str
    severity: str = "info"
    related_contradictions: List[str] = field(default_factory=list)
    baseline_curl: str = ""
    variant_curl: str = ""
    baseline_excerpt: str = ""
    variant_excerpt: str = ""


@dataclass
class LayerSnapshot:
    layer: Layer
    headers: Dict[str, str]
    status: int
    body_hash: str
    body_len: int
    title: str
    technologies: List[str]
    raw_headers: str
    notes: List[str] = field(default_factory=list)
    body_raw: bytes = b""
    elapsed_ms: int = 0
    body_hash_norm: str = ""


@dataclass
class Signal:
    kind: str
    rules_out: str
    detail: str
    severity_weight: float
    requires_corroboration: bool = True


@dataclass
class Hypothesis:
    name: str
    kind: str
    explains: List[str]
    score: float = 0.0


@dataclass
class DiffExplanation:
    baseline: LayerSnapshot
    variant: LayerSnapshot
    status_delta: Tuple[int, int]
    header_delta: Dict[str, Tuple[str, str]]
    body_delta: int
    relationship: str
    boundary: Boundary
    violation_evidence: List[str]
    normal_explanations_ruled_out: List[str]
    confidence: float
    interesting: bool = False
    signals: List[Signal] = field(default_factory=list)
    hypotheses: List[Hypothesis] = field(default_factory=list)
    baseline_url: str = ""
    variant_url: str = ""
    variant_method: str = "GET"
    variant_headers: Dict[str, str] = field(default_factory=dict)
    validation_reproduced: Optional[bool] = None
    validation_notes: List[str] = field(default_factory=list)


@dataclass
class Report:
    target: str
    started: str
    finished: str
    architecture: Optional[Architecture] = None
    layers: Dict[str, LayerSnapshot] = field(default_factory=dict)
    assumptions: List[Assumption] = field(default_factory=list)
    contradictions: List[Contradiction] = field(default_factory=list)
    origin_candidates: List[OriginCandidate] = field(default_factory=list)
    diffs: List[DiffExplanation] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    summary: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def normalize(url: str) -> str:
    if "://" not in url:
        netloc = url.split("/", 1)[0]
        if ":" in netloc:
            port = netloc.rsplit(":", 1)[1]
            scheme = "http" if port in ("80", "8080", "8000", "3000") else "https"
        else:
            scheme = "https"
        url = f"{scheme}://{url}"
    p = urlparse(url)
    path = p.path or "/"
    return f"{p.scheme}://{p.netloc.lower()}{path}"


def sha16(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def normalize_ephemeral(body: bytes) -> bytes:
    if not body or len(body) > 2_000_000:
        return body
    try:
        text = body.decode("utf-8", errors="strict")
    except (UnicodeDecodeError, ValueError):
        return body
    text = re.sub(r"[A-Za-z0-9+/=_-]{40,}", "<TOK>", text)
    text = re.sub(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?", "<TSISO>", text)
    text = re.sub(r"[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT", "<TSRFC>", text)
    text = re.sub(r"(?<!\d)1[6-9]\d{11}(?!\d)", "<TSMS>", text)
    text = re.sub(r"(?<!\d)1[6-9]\d{8}(?!\d)", "<TSS>", text)
    return text.encode("utf-8")


def title_of(html: bytes) -> str:
    try:
        return BeautifulSoup(html, "html.parser").title.get_text(strip=True)[:120]
    except Exception:
        return ""


TECH = {
    "cloudflare": [r"cloudflare", r"cf-ray", r"__cf"],
    "akamai": [r"akamai", r"x-akamai", r"akamai-origin"],
    "fastly": [r"fastly", r"x-served-by"],
    "cloudfront": [r"cloudfront", r"x-amz-cf"],
    "imperva": [r"imperva", r"incapsula"],
    "sucuri": [r"sucuri", r"x-sucuri"],
    "nginx": [r"nginx"],
    "apache": [r"apache"],
    "iis": [r"microsoft-iis", r"x-aspnet"],
    "varnish": [r"varnish", r"x-varnish"],
    "haproxy": [r"haproxy"],
    "wordpress": [r"wp-content", r"wordpress"],
    "laravel": [r"laravel_session"],
    "django": [r"csrftoken", r"django"],
    "express": [r"x-powered-by:.*express"],
    "spring": [r"x-application-context", r"jsessionid"],
}


def detect_tech(headers: Dict[str, str], body: bytes) -> List[str]:
    blob = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
    blob += " " + body[:6000].decode("utf-8", errors="ignore").lower()
    return [name for name, pats in TECH.items() if any(re.search(p, blob, re.I) for p in pats)]


EDGE_TECH = {"cloudflare", "akamai", "fastly", "cloudfront", "imperva", "sucuri"}
EDGE_HEADERS = ("cf-ray", "cf-cache-status", "x-akamai", "x-served-by",
                "x-amz-cf-id", "x-cache", "x-cache-hits", "x-sucuri-id")
PROXY_TECH = {"varnish", "haproxy"}
PROXY_HEADERS = ("via", "x-varnish", "x-forwarded-for", "x-forwarded-host")

# Published CDN edge ranges. Any A record inside these belongs to the edge, not the origin.
EDGE_RANGES = (
    ("104.16.0.0", "104.31.255.255"),       # Cloudflare
    ("172.64.0.0", "172.71.255.255"),       # Cloudflare
    ("173.245.48.0", "173.245.63.255"),     # Cloudflare
    ("103.21.244.0", "103.21.247.255"),     # Cloudflare
    ("103.22.200.0", "103.22.203.255"),     # Cloudflare
    ("103.31.4.0", "103.31.7.255"),         # Cloudflare
    ("141.101.64.0", "141.101.127.255"),    # Cloudflare
    ("108.162.192.0", "108.162.255.255"),   # Cloudflare
    ("190.93.240.0", "190.93.255.255"),     # Cloudflare
    ("188.114.96.0", "188.114.111.255"),    # Cloudflare
    ("197.234.240.0", "197.234.243.255"),   # Cloudflare
    ("198.41.128.0", "198.41.255.255"),     # Cloudflare
    ("162.158.0.0", "162.159.255.255"),     # Cloudflare
    ("131.0.72.0", "131.0.75.255"),         # Cloudflare
    ("151.101.0.0", "151.101.255.255"),     # Fastly
    ("199.232.0.0", "199.232.255.255"),     # Fastly
    ("23.32.0.0", "23.63.255.255"),         # Akamai
    ("23.192.0.0", "23.223.255.255"),       # Akamai
    ("184.24.0.0", "184.31.255.255"),       # Akamai
    ("96.6.0.0", "96.7.255.255"),           # Akamai
    ("99.84.0.0", "99.86.255.255"),         # CloudFront
    ("143.204.0.0", "143.204.255.255"),     # CloudFront
    ("18.64.0.0", "18.65.255.255"),         # CloudFront
    ("52.84.0.0", "52.95.255.255"),         # CloudFront (partial)
)


def ip_to_int(ip: str) -> int:
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return -1
        return sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts))
    except Exception:
        return -1


def is_edge_ip(ip: str) -> bool:
    v = ip_to_int(ip)
    if v < 0:
        return False
    for start, end in EDGE_RANGES:
        if ip_to_int(start) <= v <= ip_to_int(end):
            return True
    return False


def classify_architecture(main: LayerSnapshot) -> Architecture:
    arch = Architecture()
    h = main.headers
    tech = set(main.technologies)

    for t in EDGE_TECH:
        if t in tech:
            arch.edge_tech = t
            arch.front_end = True
            arch.evidence.append(f"tech:{t}")
            break
    if not arch.front_end:
        for hk in EDGE_HEADERS:
            if hk in h:
                arch.edge_tech = hk
                arch.front_end = True
                arch.evidence.append(f"header:{hk}")
                break

    for t in PROXY_TECH:
        if t in tech:
            arch.proxy_tech = t
            arch.evidence.append(f"proxy:{t}")
            break
    if not arch.proxy_tech:
        for hk in PROXY_HEADERS:
            if hk in h:
                arch.proxy_tech = hk
                arch.evidence.append(f"proxy-header:{hk}")
                break

    server = h.get("server", "").lower()
    for t in ("nginx", "apache", "iis"):
        if t in server or t in tech:
            arch.origin_tech = t
            break

    for t in tech:
        if t in ("wordpress", "laravel", "django", "express", "spring"):
            arch.app_tech.append(t)

    return arch


# ---------------------------------------------------------------------------
# HTTP Core
# ---------------------------------------------------------------------------

class HttpEngine:
    def __init__(self, session: ClientSession, concurrency: int = 12):
        self.session = session
        self.sem = asyncio.Semaphore(concurrency)
        self.stats = {"ok": 0, "err": 0, "by_reason": {}}

    async def fetch(self, url: str, method: str = "GET",
                    headers: Optional[Dict] = None,
                    allow_redirects: bool = True,
                    body: Optional[bytes] = None) -> Optional[LayerSnapshot]:
        async with self.sem:
            t0 = time.monotonic()
            try:
                async with self.session.request(
                    method, url, headers=headers or {},
                    data=body, allow_redirects=allow_redirects, ssl=False
                ) as resp:
                    body_bytes = await resp.read()
                    hdrs = {k.lower(): v for k, v in resp.headers.items()}
                    self.stats["ok"] += 1
                    elapsed = int((time.monotonic()-t0)*1000)
                    norm = normalize_ephemeral(body_bytes)
                    return LayerSnapshot(
                        layer=Layer.UNKNOWN, headers=hdrs, status=resp.status,
                        body_hash=sha16(body_bytes), body_len=len(body_bytes),
                        title=title_of(body_bytes) if "html" in hdrs.get("content-type", "") else "",
                        technologies=detect_tech(hdrs, body_bytes),
                        raw_headers="\n".join(f"{k}: {v}" for k, v in resp.headers.items()),
                        notes=[f"elapsed_ms={elapsed}"],
                        body_raw=body_bytes,
                        elapsed_ms=elapsed,
                        body_hash_norm=sha16(norm),
                    )
            except asyncio.TimeoutError:
                reason = "timeout"
            except aiohttp.ClientConnectorCertificateError as e:
                reason = f"tls_cert:{e}"
            except aiohttp.ClientConnectorError as e:
                reason = f"connect:{e}"
            except aiohttp.ClientSSLError as e:
                reason = f"tls:{e}"
            except aiohttp.ClientError as e:
                reason = f"client:{type(e).__name__}:{e}"
            except Exception as e:
                reason = f"other:{type(e).__name__}:{e}"
            self.stats["err"] += 1
            key = reason.split(":")[0]
            self.stats["by_reason"][key] = self.stats["by_reason"].get(key, 0) + 1
            return LayerSnapshot(
                layer=Layer.UNKNOWN, headers={}, status=0,
                body_hash="", body_len=0, title="", technologies=[],
                raw_headers="",
                notes=[reason, f"url={url}",
                       f"elapsed_ms={int((time.monotonic()-t0)*1000)}"],
            )


# ---------------------------------------------------------------------------
# Layer Fingerprinting
# ---------------------------------------------------------------------------

class LayerFingerprinter:
    def __init__(self, http: HttpEngine):
        self.http = http

    async def snapshot(self, url: str) -> LayerSnapshot:
        snap = await self.http.fetch(url)
        if not snap:
            return LayerSnapshot(Layer.UNKNOWN, {}, 0, "", 0, "", [], "")
        h = snap.headers
        if any(k in h for k in ("cf-ray", "cf-cache-status")) or "cloudflare" in h.get("server", "").lower():
            snap.layer = Layer.WAF
        elif any(k in h for k in ("x-cache", "x-served-by", "via", "x-varnish", "age", "x-amz-cf-id")):
            snap.layer = Layer.PROXY
        elif "x-powered-by" in h or any(t in snap.technologies for t in ("nginx", "apache", "iis")):
            snap.layer = Layer.ORIGIN
        else:
            snap.layer = Layer.APP
        return snap


# ---------------------------------------------------------------------------
# Origin Candidate Engine
# ---------------------------------------------------------------------------

class OriginCandidateEngine:
    def __init__(self, http: HttpEngine):
        self.http = http

    async def discover(self, domain: str, main_snap: LayerSnapshot,
                       port: int = 443, scheme: str = "https",
                       max_candidates: int = 64,
                       probe_concurrency: int = 8) -> List[OriginCandidate]:
        candidates: Dict[str, OriginCandidate] = {}

        def add(ip_or_host: str, source: str, conf: float, evidence: str, dns_rel: str = ""):
            key = ip_or_host.lower()
            if key not in candidates:
                candidates[key] = OriginCandidate(
                    ip_or_host=ip_or_host, source=source, confidence=conf,
                    dns_relationship=dns_rel, relationship_evidence=[evidence]
                )
            else:
                c = candidates[key]
                c.confidence = min(1.0, c.confidence + conf * 0.4)
                c.relationship_evidence.append(evidence)
                if source not in c.source:
                    c.source += f",{source}"

        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 5.0

        try:
            for r in resolver.resolve(domain, "A"):
                add(str(r), "dns-a", 0.35, f"A record for {domain}", "direct-a")
        except Exception:
            pass

        for sub in ("origin", "direct", "backend", "api", "admin", "mail",
                    "ftp", "cpanel", "webmail", "ns1", "ns2", "cdn", "static"):
            try:
                for r in resolver.resolve(f"{sub}.{domain}", "A"):
                    add(str(r), "dns-sub", 0.45, f"A record for {sub}.{domain}", f"sub:{sub}")
            except Exception:
                pass

        is_tls = port in (443, 8443) or scheme == "https"
        if is_tls:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((domain, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        if cert:
                            sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
                            cn = None
                            for part in cert.get("subject", ()):
                                for k, v in part:
                                    if k == "commonName":
                                        cn = v
                            for name in set(sans + ([cn] if cn else [])):
                                if name and name != domain and not name.startswith("*"):
                                    add(name, "tls-san", 0.5, f"SAN/CN on cert: {name}", "tls-san")
            except Exception:
                pass

        for hname in ("x-origin", "x-backend-server", "x-real-ip",
                      "x-cache-lookup", "x-upstream", "x-server"):
            if hname in main_snap.headers:
                val = main_snap.headers[hname]
                # only accept values that look like a hostname or IP
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", val) or re.match(r"^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$", val.lower()):
                    add(val, "http-header", 0.55, f"Header {hname}: {val}", "header-leak")

        ordered = sorted(candidates.values(), key=lambda c: -c.confidence)[:max_candidates]
        probe_sem = asyncio.Semaphore(probe_concurrency)

        async def probe(c: OriginCandidate):
            async with probe_sem:
                target = c.ip_or_host
                try:
                    headers = {"Host": domain} if re.match(r"^\d+\.\d+\.\d+\.\d+$", target) else {}
                    snap = await self.http.fetch(f"{scheme}://{target}/", headers=headers)
                    if snap and snap.status:
                        c.http_fingerprint = {
                            "status": snap.status,
                            "server": snap.headers.get("server", ""),
                            "body_hash": snap.body_hash,
                            "tech": snap.technologies,
                            "edge_headers_present": any(k in snap.headers for k in EDGE_HEADERS),
                        }
                        same_hash = snap.body_hash == main_snap.body_hash
                        same_server = snap.headers.get("server") == main_snap.headers.get("server")
                        tech_overlap = len(set(snap.technologies) & set(main_snap.technologies))
                        main_has_edge = any(k in main_snap.headers for k in EDGE_HEADERS)
                        cand_has_edge = c.http_fingerprint["edge_headers_present"]
                        sim = 0.0
                        if same_hash:
                            sim += 0.4
                        if same_server:
                            sim += 0.2
                        sim += min(0.2, tech_overlap * 0.1)
                        if main_has_edge and not cand_has_edge:
                            sim += 0.2
                        c.app_similarity = sim
                        c.confidence = min(1.0, c.confidence + sim * 0.4)
                        c.relationship_evidence.append(
                            f"HTTP sim={sim:.2f} status={snap.status} hash_match={same_hash}"
                        )
                except Exception:
                    pass

                if is_tls:
                    try:
                        host = c.ip_or_host if not re.match(r"^\d+\.\d+\.\d+\.\d+$", c.ip_or_host) else domain
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        with socket.create_connection((c.ip_or_host, port), timeout=4) as sock:
                            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                                cert = ssock.getpeercert(binary_form=True)
                                if cert:
                                    c.tls_fingerprint = {"sha256": hashlib.sha256(cert).hexdigest()[:16]}
                                    c.confidence = min(1.0, c.confidence + 0.1)
                    except Exception:
                        pass

                main_has_edge = any(k in main_snap.headers for k in EDGE_HEADERS)
                cand_has_edge = bool(c.http_fingerprint.get("edge_headers_present"))
                cand_in_edge_range = is_edge_ip(c.ip_or_host)

                if cand_in_edge_range:
                    c.classification = "edge-ip"
                elif not main_has_edge:
                    c.classification = "public-endpoint"
                elif cand_has_edge:
                    # candidate presents edge headers itself — it is another edge node
                    c.classification = "edge-ip"
                elif c.dns_relationship == "direct-a":
                    c.classification = "candidate-origin"
                elif c.source.startswith("dns-sub"):
                    c.classification = "candidate-origin"
                elif c.source.startswith("tls-san"):
                    c.classification = "candidate-origin"
                elif c.source.startswith("http-header"):
                    c.classification = "leak-suspected"
                else:
                    c.classification = "unknown"

                if (c.confidence >= 0.75
                        and c.app_similarity >= 0.4
                        and c.classification not in ("public-endpoint", "edge-ip")):
                    c.confirmed = True

        await asyncio.gather(*(probe(c) for c in ordered))
        ordered.sort(key=lambda x: x.confidence, reverse=True)
        return ordered


# ---------------------------------------------------------------------------
# Signal taxonomy
# ---------------------------------------------------------------------------

def _sig_status_reversal(base: LayerSnapshot, var: LayerSnapshot,
                         vh: Optional[Dict] = None) -> Optional[Signal]:
    if base.status == var.status:
        return None
    return Signal(
        kind="status_reversal",
        rules_out="pure routing variance",
        detail=f"{base.status} -> {var.status}",
        severity_weight=0.6,
    )


def _sig_body_delta(base: LayerSnapshot, var: LayerSnapshot,
                    vh: Optional[Dict] = None) -> Optional[Signal]:
    if base.body_hash == var.body_hash:
        return None
    if "set-cookie" in var.headers and "set-cookie" not in base.headers:
        return Signal(
            kind="body_delta_under_cookie",
            rules_out="nothing — cookie variance plausible",
            detail="body changed and Set-Cookie appeared",
            severity_weight=0.0,
        )
    return Signal(
        kind="body_delta",
        rules_out="session-driven content variance",
        detail=f"{base.body_hash} -> {var.body_hash}, len {base.body_len} -> {var.body_len}",
        severity_weight=0.4,
    )


def _sig_sensitive_header_delta(base: LayerSnapshot, var: LayerSnapshot,
                                vh: Optional[Dict] = None) -> Optional[Signal]:
    sensitive = ("server", "x-powered-by", "x-origin", "x-backend-server",
                 "x-real-ip", "via")
    changed = [k for k in sensitive if base.headers.get(k) != var.headers.get(k)]
    if not changed:
        return None
    return Signal(
        kind="sensitive_header_delta",
        rules_out="stable upstream identity",
        detail=f"changed: {changed}",
        severity_weight=0.5,
    )


def _sig_cache_layer_disagreement(base: LayerSnapshot, var: LayerSnapshot,
                                  vh: Optional[Dict] = None) -> Optional[Signal]:
    keys = ("x-cache", "age", "x-served-by", "x-varnish", "cf-cache-status")
    b = {k: base.headers.get(k, "") for k in keys if k in base.headers}
    v = {k: var.headers.get(k, "") for k in keys if k in var.headers}
    if b == v:
        return None
    return Signal(
        kind="cache_layer_disagreement",
        rules_out="stable edge behavior",
        detail=f"cache headers moved: base={b} var={v}",
        severity_weight=0.3,
    )


def _sig_compression_variance(base: LayerSnapshot, var: LayerSnapshot,
                              vh: Optional[Dict] = None) -> Optional[Signal]:
    if base.body_hash == var.body_hash:
        return None
    if base.headers.get("content-encoding") != var.headers.get("content-encoding"):
        return Signal(
            kind="compression_variance",
            rules_out="application-layer content change",
            detail=f"encoding {base.headers.get('content-encoding')} -> {var.headers.get('content-encoding')}",
            severity_weight=-0.2,
            requires_corroboration=False,
        )
    return None


def _sig_time_delta(base, var, vh=None):
    if not base.elapsed_ms or not var.elapsed_ms:
        return None
    if base.elapsed_ms < 200:
        return None
    if var.elapsed_ms > base.elapsed_ms * 4 and (var.elapsed_ms - base.elapsed_ms) > 500:
        return Signal(kind="time_delta", rules_out="stable upstream performance",
                      detail=f"{base.elapsed_ms}ms -> {var.elapsed_ms}ms", severity_weight=0.3)
    return None


def _sig_ephemeral_only(base, var, vh=None):
    if base.body_hash == var.body_hash:
        return None
    if base.body_hash_norm and var.body_hash_norm and base.body_hash_norm == var.body_hash_norm:
        return Signal(kind="ephemeral_only",
                      rules_out="nothing - bodies match after stripping per-request tokens",
                      detail="raw bodies differ, normalized bodies match",
                      severity_weight=-0.4, requires_corroboration=False)
    return None


def _sig_status_class_shift(base, var, vh=None):
    if base.status == var.status:
        return None
    bc, vc = base.status // 100, var.status // 100
    if bc == vc:
        return None
    return Signal(kind="status_class_shift", rules_out="no class boundary crossed",
                  detail=f"{base.status} -> {var.status} ({bc}xx -> {vc}xx)", severity_weight=0.5)


def _sig_auth_challenge_changed(base, var, vh=None):
    if "www-authenticate" not in base.headers and "www-authenticate" not in var.headers:
        return None
    if base.headers.get("www-authenticate") == var.headers.get("www-authenticate"):
        return None
    return Signal(kind="auth_challenge_changed", rules_out="stable auth boundary",
                  detail="WWW-Authenticate changed", severity_weight=0.4)


def _sig_redirect_target_delta(base, var, vh=None):
    bl = base.headers.get("location", "")
    vl = var.headers.get("location", "")
    if bl == vl or (not bl and not vl):
        return None
    return Signal(kind="redirect_target_delta", rules_out="stable redirect policy",
                  detail=f"location {bl!r} -> {vl!r}", severity_weight=0.3)


def _sig_content_type_confusion(base, var, vh=None):
    bc = base.headers.get("content-type", "").split(";")[0].strip()
    vc = var.headers.get("content-type", "").split(";")[0].strip()
    if not bc or not vc or bc == vc:
        return None
    if base.body_hash != var.body_hash:
        return None
    return Signal(kind="content_type_confusion", rules_out="consistent representation",
                  detail=f"same body, content-type {bc} -> {vc}", severity_weight=0.4)


SIGNAL_FUNCS = (
    _sig_status_reversal,
    _sig_status_class_shift,
    _sig_body_delta,
    _sig_sensitive_header_delta,
    _sig_cache_layer_disagreement,
    _sig_compression_variance,
    _sig_time_delta,
    _sig_ephemeral_only,
    _sig_auth_challenge_changed,
    _sig_redirect_target_delta,
    _sig_content_type_confusion,
)


def extract_signals(base: LayerSnapshot, var: LayerSnapshot,
                    variant_headers: Optional[Dict] = None) -> List[Signal]:
    out = []
    for fn in SIGNAL_FUNCS:
        try:
            s = fn(base, var, variant_headers)
            if s:
                out.append(s)
        except Exception:
            continue
    return out


def _looks_like_generic_error_page(snap: LayerSnapshot) -> bool:
    if snap.status not in (404, 410):
        return False
    t = (snap.title or "").lower()
    if any(s in t for s in ("not found", "404", "nicht gefunden", "fehler")):
        return True
    # any 404 with a small body and no app-specific markers
    if snap.body_len < 4096 and not any(
        m in (snap.title or "").lower() for m in ("admin", "dashboard", "login", "console")
    ):
        return True
    return False


def score_hypotheses(signals: List[Signal],
                     variant_headers: Optional[Dict] = None,
                     baseline: Optional[LayerSnapshot] = None,
                     variant: Optional[LayerSnapshot] = None,
                     variant_path_is_new: bool = False) -> List[Hypothesis]:
    kinds = {s.kind for s in signals}
    vh = {k.lower(): v for k, v in (variant_headers or {}).items()}
    bh = baseline.headers if baseline else {}
    varh = variant.headers if variant else {}

    has_accept_mutation = "accept" in vh
    has_cookie_variance = (
        ("set-cookie" in varh and "set-cookie" not in bh)
        or "cookie" in vh
    )
    has_cache_variance = any(
        k in varh and varh.get(k) != bh.get(k)
        for k in ("x-cache", "age", "x-served-by", "x-varnish", "cf-cache-status")
    )
    has_compression_variance = (
        bh.get("content-encoding") != varh.get("content-encoding")
    )
    has_404_generic = (
        variant is not None
        and variant_path_is_new
        and _looks_like_generic_error_page(variant)
    )
    has_rejected_negotiation = (
        has_accept_mutation
        and variant is not None
        and 400 <= variant.status < 500
        and baseline is not None
        and variant.headers.get("content-type", "").split(";")[0]
            != baseline.headers.get("content-type", "").split(";")[0]
    )
    # Detect "different method requested" — expected to yield different status/body.
    # We cannot see the variant method here, so rely on presence of an Allow header
    # and variant status in the 2xx-3xx range with empty body.
    has_method_semantics = (
        variant is not None
        and "allow" in variant.headers
        and variant.status in (200, 204, 301, 302)
        and variant.body_len == 0
    )
    has_method_unsupported = (
        variant is not None
        and variant.status == 501
    )
    _vh_lower = {k.lower() for k in vh.keys()}
    has_host_mutation = "host" in _vh_lower
    has_te_mutation = "transfer-encoding" in _vh_lower
    has_cl_mutation = "content-length" in _vh_lower
    has_host_reject = (
        has_host_mutation and variant is not None
        and variant.status in (400, 403, 404, 421, 444, 500)
    )
    has_host_redirect = (
        has_host_mutation and variant is not None
        and variant.status in (301, 302, 307, 308)
    )
    has_framing_reject = (
        (has_te_mutation or has_cl_mutation) and variant is not None
        and variant.status in (400, 411, 413, 431, 501, 505)
    )

    hypotheses = [
        Hypothesis("session variance", "benign",
                   ["body_delta_under_cookie"],
                   0.9 if has_cookie_variance else 0.0),
        Hypothesis("cache hit/miss variance", "benign",
                   ["cache_layer_disagreement"],
                   0.9 if has_cache_variance else 0.0),
        Hypothesis("compression difference", "benign",
                   ["compression_variance"],
                   0.9 if has_compression_variance else 0.0),
        Hypothesis("content negotiation", "benign",
                   ["body_delta", "sensitive_header_delta"],
                   0.6 if has_accept_mutation else 0.0),
        Hypothesis("path does not exist on origin", "benign",
                   ["status_reversal", "body_delta", "compression_variance"],
                   0.95 if has_404_generic else 0.0),
        Hypothesis("app rejected content negotiation", "benign",
                   ["status_reversal", "body_delta_under_cookie", "compression_variance"],
                   0.95 if has_rejected_negotiation else 0.0),
        Hypothesis("method semantics differ", "benign",
                   ["status_reversal", "body_delta", "compression_variance"],
                   0.95 if has_method_semantics else 0.0),
        Hypothesis("server does not support method", "benign",
                   ["status_reversal", "status_class_shift", "body_delta"],
                   0.95 if has_method_unsupported else 0.0),
        Hypothesis("edge enforces host integrity", "benign",
                   ["status_reversal", "status_class_shift", "body_delta",
                    "cache_layer_disagreement"],
                   0.95 if has_host_reject else 0.0),
        Hypothesis("edge normalises host (redirect)", "benign",
                   ["status_reversal", "status_class_shift", "redirect_target_delta",
                    "body_delta"],
                   0.95 if has_host_redirect else 0.0),
        Hypothesis("edge rejects malformed framing", "benign",
                   ["status_reversal", "status_class_shift", "body_delta",
                    "cache_layer_disagreement"],
                   0.95 if has_framing_reject else 0.0),
        Hypothesis("challenge page rotation", "benign",
                   ["ephemeral_only", "body_delta"],
                   0.95 if any(s.kind == "ephemeral_only" for s in signals) else 0.0),
        Hypothesis("rate limiting or throttling", "benign",
                   ["time_delta", "status_reversal"],
                   0.85 if any(s.kind == "time_delta" for s in signals) else 0.0),
        Hypothesis("slow upstream, no policy change", "benign",
                   ["time_delta"],
                   0.6 if any(s.kind == "time_delta" for s in signals) else 0.0),
        Hypothesis("auth challenge refresh", "benign",
                   ["auth_challenge_changed"],
                   0.7 if any(s.kind == "auth_challenge_changed" for s in signals) else 0.0),
        Hypothesis("redirect policy variance", "benign",
                   ["redirect_target_delta"],
                   0.6 if any(s.kind == "redirect_target_delta" for s in signals) else 0.0),
        Hypothesis("content-type rewrite at edge", "benign",
                   ["content_type_confusion"],
                   0.5 if any(s.kind == "content_type_confusion" for s in signals) else 0.0),
        Hypothesis("cache key ignores header", "benign",
                   ["cache_layer_disagreement"],
                   0.5 if has_cache_variance else 0.0),
        Hypothesis("path encoded, decoded downstream", "boundary_violation",
                   ["status_reversal", "status_class_shift", "body_delta",
                    "sensitive_header_delta"], 0.0),
        Hypothesis("header not stripped at edge", "boundary_violation",
                   ["status_reversal", "sensitive_header_delta",
                    "cache_layer_disagreement"], 0.0),
        Hypothesis("case routing bypass", "boundary_violation",
                   ["status_reversal", "status_class_shift", "body_delta"], 0.0),
        Hypothesis("smuggling primitive accepted", "boundary_violation",
                   ["status_reversal", "time_delta", "sensitive_header_delta"], 0.0),
        Hypothesis("layer interpretation mismatch", "boundary_violation",
                   ["status_reversal", "status_class_shift", "body_delta",
                    "sensitive_header_delta", "cache_layer_disagreement"], 0.0),
        Hypothesis("different upstream answered", "boundary_violation",
                   ["status_reversal", "status_class_shift",
                    "sensitive_header_delta"], 0.0),
    ]
    for h in hypotheses:
        matched = [k for k in h.explains if k in kinds]
        if h.kind == "benign":
            if h.score > 0.0:
                coverage = len(matched) / max(1, len(kinds))
                h.score = h.score + coverage * 0.1
            continue
        h.score = len(matched) / max(1, len(kinds)) if kinds else 0.0
    return sorted(hypotheses, key=lambda x: -x.score)


# ---------------------------------------------------------------------------
# Assumption Engine
# ---------------------------------------------------------------------------

class AssumptionEngine:
    def extract(self, main: LayerSnapshot, candidates: List[OriginCandidate],
                arch: Architecture) -> List[Assumption]:
        assumptions = []

        if arch.front_end or main.layer == Layer.WAF:
            assumptions.append(Assumption(
                Layer.WAF,
                "All external traffic is terminated and inspected before reaching origin",
                "edge signatures present",
                0.8,
            ))
            assumptions.append(Assumption(
                Layer.WAF,
                "Path and header normalization occurs at the edge",
                "standard WAF behavior model",
                0.7,
            ))
            if arch.front_end:
                assumptions.append(Assumption(
                    Layer.WAF,
                    "Origin IP is not directly reachable from the internet",
                    "CDN fronting observed",
                    0.75,
                ))

        if arch.proxy_tech:
            assumptions.append(Assumption(
                Layer.PROXY,
                "Cache key is derived from normalized URL + selected headers",
                f"proxy tech: {arch.proxy_tech}",
                0.65,
            ))

        assumptions.append(Assumption(
            Layer.ORIGIN,
            "Only traffic arriving via the expected front-end is legitimate",
            "default origin trust model",
            0.6,
        ))
        assumptions.append(Assumption(
            Layer.ORIGIN,
            "Host header reflects the public domain",
            "virtual-host based routing common",
            0.7,
        ))
        assumptions.append(Assumption(
            Layer.APP,
            "Authorization decisions are made after routing and path normalization",
            "typical application stack ordering",
            0.55,
        ))

        for c in candidates:
            if c.confidence > 0.6 and arch.front_end and c.dns_relationship != "direct-a":
                assumptions.append(Assumption(
                    Layer.ORIGIN,
                    f"Origin candidate {c.ip_or_host} should not be reachable without front-end",
                    f"candidate source={c.source}",
                    c.confidence * 0.9,
                ))
            elif c.confidence > 0.6 and not arch.front_end and c.dns_relationship == "direct-a":
                assumptions.append(Assumption(
                    Layer.ORIGIN,
                    f"Candidate {c.ip_or_host} appears to be the public endpoint (no front-end observed)",
                    f"candidate source={c.source}",
                    0.7,
                ))

        return assumptions

    def find_contradictions(self, assumptions: List[Assumption],
                            diffs: List[DiffExplanation],
                            candidates: List[OriginCandidate],
                            main: LayerSnapshot,
                            arch: Architecture) -> List[Contradiction]:
        contras = []

        if arch.front_end:
            for c in candidates:
                if c.classification in ("public-endpoint", "edge-ip"):
                    continue
                if c.confirmed or (c.confidence >= 0.7 and c.app_similarity >= 0.35):
                    for a in assumptions:
                        if "not directly reachable" in a.statement.lower():
                            contras.append(Contradiction(
                                assumption_a=a,
                                assumption_b=Assumption(Layer.INTERNET, "Direct connection succeeded", "probe", 0.9),
                                observed_behavior=f"HTTP response from {c.ip_or_host} with public Host header",
                                explanation="Traffic reached a host the edge assumed shielded",
                                boundary=Boundary.INTERNET_ORIGIN,
                                evidence=c.relationship_evidence + [
                                    f"confidence={c.confidence:.2f}",
                                    f"sim={c.app_similarity:.2f}",
                                ],
                                confidence=min(0.95, c.confidence + 0.15),
                            ))

        for d in diffs:
            if not d.interesting:
                continue
            if d.boundary in (Boundary.WAF_ORIGIN, Boundary.INTERNET_ORIGIN, Boundary.PROXY_ORIGIN):
                contras.append(Contradiction(
                    assumption_a=Assumption(Layer.WAF,
                                            "Normalization and filtering are consistent across layers",
                                            "edge model", 0.7),
                    assumption_b=Assumption(Layer.ORIGIN,
                                            "Origin sees the same request semantics as the edge",
                                            "trust model", 0.7),
                    observed_behavior=d.relationship,
                    explanation=d.violation_evidence[0] if d.violation_evidence else "layer interpretation mismatch",
                    boundary=d.boundary,
                    evidence=d.violation_evidence + d.normal_explanations_ruled_out,
                    confidence=d.confidence,
                ))

        return contras


# ---------------------------------------------------------------------------
# Validation pass
# ---------------------------------------------------------------------------

class Validator:
    def __init__(self, http: HttpEngine):
        self.http = http

    async def validate(self, base_url: str, variant_cfg: Dict,
                       baseline: LayerSnapshot,
                       original_variant: LayerSnapshot) -> Tuple[bool, List[str]]:
        url = base_url.rstrip("/") + variant_cfg.get("path_suffix", "")
        method = variant_cfg.get("method", "GET")
        headers = dict(variant_cfg.get("headers") or {})
        headers["User-Agent"] = "WebPT-Validator/1.0"

        baseline2 = await self.http.fetch(base_url,
                                          headers={"User-Agent": "WebPT-Validator/1.0"})
        variant2 = await self.http.fetch(url, method=method, headers=headers)

        notes = []
        if not baseline2 or baseline2.status == 0:
            return False, ["baseline_reprobe_failed"] + (baseline2.notes if baseline2 else [])
        if not variant2 or variant2.status == 0:
            return False, ["variant_reprobe_failed"] + (variant2.notes if variant2 else [])

        if baseline2.body_hash_norm and baseline.body_hash_norm:
            b_ok = baseline2.body_hash_norm == baseline.body_hash_norm
        else:
            b_ok = baseline2.body_hash == baseline.body_hash
        if variant2.body_hash_norm and original_variant.body_hash_norm:
            v_ok = variant2.body_hash_norm == original_variant.body_hash_norm
        else:
            v_ok = variant2.body_hash == original_variant.body_hash
        if not b_ok:
            notes.append(f"baseline_not_reproduced: {baseline.body_hash} != {baseline2.body_hash}")
        if not v_ok:
            notes.append(f"variant_not_reproduced: {original_variant.body_hash} != {variant2.body_hash}")
        if baseline2.status != baseline.status:
            notes.append(f"baseline_status_drift: {baseline.status} != {baseline2.status}")
        if variant2.status != original_variant.status:
            notes.append(f"variant_status_drift: {original_variant.status} != {variant2.status}")

        return (len(notes) == 0), notes


# ---------------------------------------------------------------------------
# Probe library - 50 probes across 12 families.
# ---------------------------------------------------------------------------

PROBE_LIBRARY: List[Dict[str, Any]] = [
    {"cat":"fwd_ip","headers":{"X-Forwarded-For":"127.0.0.1"},"label":"xff-localhost","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Edge and origin share the same view of client IP"},
    {"cat":"fwd_ip","headers":{"X-Forwarded-For":"192.168.1.1"},"label":"xff-private","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Origin trusts forwarded-for private range"},
    {"cat":"fwd_ip","headers":{"X-Real-IP":"127.0.0.1"},"label":"x-real-ip","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Origin trusts X-Real-IP from external client"},
    {"cat":"fwd_ip","headers":{"X-Client-IP":"127.0.0.1"},"label":"x-client-ip","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Origin trusts X-Client-IP from external client"},
    {"cat":"fwd_ip","headers":{"X-Originating-IP":"127.0.0.1"},"label":"x-originating-ip","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Origin trusts X-Originating-IP"},
    {"cat":"fwd_ip","headers":{"X-Remote-Addr":"127.0.0.1"},"label":"x-remote-addr","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Origin trusts X-Remote-Addr"},
    {"cat":"rewrite","headers":{"X-Original-URL":"/admin"},"path_suffix":"/admin","label":"x-original-url","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Path interpreted identically by WAF and origin"},
    {"cat":"rewrite","headers":{"X-Rewrite-URL":"/admin"},"path_suffix":"/admin","label":"x-rewrite-url","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Rewrite headers stripped before origin"},
    {"cat":"rewrite","headers":{"X-Forwarded-Prefix":"/admin"},"path_suffix":"/admin","label":"x-forwarded-prefix","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Forwarded prefix not injected into routing"},
    {"cat":"rewrite","headers":{"X-Sendfile":"/etc/passwd"},"label":"x-sendfile","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"X-Sendfile not honored by external clients"},
    {"cat":"method_override","headers":{"X-HTTP-Method-Override":"PUT"},"label":"x-http-method-override","boundary":Boundary.ORIGIN_APP,"tests_assumption":"Method override headers ignored"},
    {"cat":"method_override","headers":{"X-HTTP-Method":"DELETE"},"label":"x-http-method","boundary":Boundary.ORIGIN_APP,"tests_assumption":"X-HTTP-Method ignored"},
    {"cat":"method_override","headers":{"X-Method-Override":"PUT"},"label":"x-method-override","boundary":Boundary.ORIGIN_APP,"tests_assumption":"X-Method-Override ignored"},
    {"cat":"method_override","path_suffix":"?_method=PUT","label":"query-method-override","boundary":Boundary.ORIGIN_APP,"tests_assumption":"Query method override ignored"},
    {"cat":"cache_key","headers":{"X-Host":"localhost"},"label":"x-host-mismatch","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Cache and origin agree on host"},
    {"cat":"cache_key","headers":{"X-Forwarded-Host":"localhost"},"label":"xfh-mismatch","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Cache and origin agree on forwarded host"},
    {"cat":"cache_key","headers":{"X-Forwarded-Scheme":"http"},"label":"xfs-http","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Cache and origin agree on scheme"},
    {"cat":"cache_key","headers":{"X-Original-Host":"localhost"},"label":"x-original-host","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"X-Original-Host not honored"},
    {"cat":"path_norm","path_suffix":"/.","label":"trailing-dot","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Path normalization identical"},
    {"cat":"path_norm","path_suffix":"/;","label":"semicolon","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Semicolon truncation handled same"},
    {"cat":"path_norm","path_suffix":"//","label":"double-slash","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Double slash collapsed identically"},
    {"cat":"path_norm","path_suffix":"///","label":"triple-slash","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Triple slash collapsed identically"},
    {"cat":"path_norm","path_suffix":"/%2e%2e/","label":"enc-dotdot","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Encoded traversal not decoded before WAF check"},
    {"cat":"path_norm","path_suffix":"/..%2f","label":"dotdot-slash-enc","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Half-encoded traversal blocked at same layer"},
    {"cat":"path_norm","path_suffix":"/%2e%2e%2f","label":"enc-dotdot-slash","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Fully-encoded traversal blocked"},
    {"cat":"path_norm","path_suffix":"/.%2e/","label":"mixed-dot-enc","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Mixed-encoded traversal blocked"},
    {"cat":"path_norm","path_suffix":"/%252e%252e/","label":"double-enc-dotdot","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Double-encoded traversal blocked"},
    {"cat":"path_norm","path_suffix":"/%c0%af","label":"overlong-slash","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Overlong UTF-8 slash rejected identically"},
    {"cat":"case","path_suffix":"/ADMIN","label":"admin-upper","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Routing case-sensitive at all layers"},
    {"cat":"case","path_suffix":"/Admin","label":"admin-title","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Routing case-sensitive at all layers"},
    {"cat":"case","headers":{"X-ORIGINAL-URL":"/admin"},"path_suffix":"/admin","label":"xor-case-upper","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Header name case does not affect rewrite"},
    {"cat":"ext","path_suffix":"/admin.json","label":"admin-json","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Extension not stripped before policy check"},
    {"cat":"ext","path_suffix":"/admin.html","label":"admin-html","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"HTML extension does not bypass filter"},
    {"cat":"ext","path_suffix":"/admin.php","label":"admin-php","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"PHP extension does not bypass filter"},
    {"cat":"ext","path_suffix":"/admin/","label":"admin-trailing","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Trailing slash handled identically"},
    {"cat":"encoding","path_suffix":"/%2f","label":"enc-slash","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Encoded slash rejected or decoded identically"},
    {"cat":"encoding","path_suffix":"/%5c","label":"enc-backslash","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Backslash normalized identically"},
    {"cat":"encoding","path_suffix":"/%00","label":"null-byte","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Null byte rejected at same layer"},
    {"cat":"encoding","path_suffix":"/%09","label":"tab-char","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Tab in path rejected identically"},
    {"cat":"cookie","headers":{"Cookie":"role=admin"},"label":"cookie-role-admin","boundary":Boundary.ORIGIN_APP,"tests_assumption":"Authorization not driven by unauth cookie"},
    {"cat":"cookie","headers":{"Cookie":"is_admin=true"},"label":"cookie-is-admin","boundary":Boundary.ORIGIN_APP,"tests_assumption":"Authorization not driven by unauth cookie"},
    {"cat":"cookie","headers":{"Cookie":"debug=true"},"label":"cookie-debug","boundary":Boundary.ORIGIN_APP,"tests_assumption":"Debug flags not exposed via cookie"},
    {"cat":"cookie","headers":{"X-Custom-IP-Authorization":"127.0.0.1"},"label":"custom-ip-auth","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Custom internal-auth headers not honored externally"},
    {"cat":"query","path_suffix":"?debug=1","label":"query-debug","boundary":Boundary.ORIGIN_APP,"tests_assumption":"Debug query flags do not change authorization"},
    {"cat":"query","path_suffix":"?test=1","label":"query-test","boundary":Boundary.ORIGIN_APP,"tests_assumption":"Test query flags do not change response"},
    {"cat":"query","path_suffix":"?admin=1","label":"query-admin","boundary":Boundary.ORIGIN_APP,"tests_assumption":"Admin query flags not trusted"},
    {"cat":"content_neg","headers":{"Accept":"application/json","X-Requested-With":"XMLHttpRequest"},"label":"force-json","boundary":Boundary.ORIGIN_APP,"tests_assumption":"Content negotiation does not expose different data"},
    {"cat":"content_neg","headers":{"Accept":"application/xml"},"label":"force-xml","boundary":Boundary.ORIGIN_APP,"tests_assumption":"XML negotiation does not expose different data"},
    {"cat":"method_semantics","method":"OPTIONS","label":"options","boundary":Boundary.ORIGIN_APP,"tests_assumption":"OPTIONS handled consistently"},
    {"cat":"method_semantics","method":"TRACE","label":"trace","boundary":Boundary.ORIGIN_APP,"tests_assumption":"TRACE disabled or handled identically"},
    {"cat":"smuggling","headers":{"Transfer-Encoding":"chunked","Content-Length":"0"},"method":"POST","body":b"","label":"te-cl","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"TE and CL not both honored"},
    {"cat":"smuggling","headers":{"Transfer-Encoding":"xchunked"},"method":"POST","body":b"","label":"te-obfuscated","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"Obfuscated TE rejected"},
    {"cat":"smuggling","headers":{"Transfer-Encoding":"identity"},"method":"POST","body":b"","label":"te-identity","boundary":Boundary.WAF_ORIGIN,"tests_assumption":"TE identity rejected or ignored"},
]


# ---------------------------------------------------------------------------
# Explained Differ
# ---------------------------------------------------------------------------

class ExplainedDiffer:
    def __init__(self, http: HttpEngine, validator: Optional[Validator] = None,
                 enable_validation: bool = True):
        self.http = http
        self.validator = validator
        self.enable_validation = enable_validation

    async def run(self, base_url: str, main: LayerSnapshot) -> List[DiffExplanation]:
        variants = PROBE_LIBRARY
        sem = asyncio.Semaphore(8)

        async def probe_one(v):
            async with sem:
                url = base_url.rstrip("/") + v.get("path_suffix", "")
                method = v.get("method", "GET")
                v_headers = v.get("headers") or {}
                v_body = v.get("body")
                snap = await self.http.fetch(url, method=method, headers=v_headers,
                                             allow_redirects=False, body=v_body)
                if not snap or snap.status == 0:
                    return None
                header_delta = {}
                for k in set(main.headers) | set(snap.headers):
                    b, a = main.headers.get(k, ""), snap.headers.get(k, "")
                    if b != a:
                        header_delta[k] = (b, a)
                signals = extract_signals(main, snap, v_headers)
                hyps = score_hypotheses(
                    signals, variant_headers=v_headers,
                    baseline=main, variant=snap,
                    variant_path_is_new=(url.split("?", 1)[0].rstrip("/") != base_url.split("?", 1)[0].rstrip("/")),
                )
                top = hyps[0] if hyps else None
                positive_signals = [s for s in signals if s.severity_weight > 0]
                _corroborating = [s for s in positive_signals
                                  if s.kind in ("sensitive_header_delta",
                                                "status_class_shift",
                                                "status_reversal",
                                                "auth_challenge_changed")]
                agreeing = len(positive_signals) >= 2 and len(_corroborating) >= 1
                is_violation = top is not None and top.kind == "boundary_violation"
                violation_evidence = [s.detail for s in positive_signals]
                ruled_out = [s.rules_out for s in positive_signals]
                interesting = is_violation and agreeing
                conf = sum(s.severity_weight for s in positive_signals)
                conf = min(0.92, max(0.15, conf))
                relationship = (
                    f"Variant '{v['label']}' [{v.get('cat','general')}] tests assumption: "
                    f"{v['tests_assumption']}. Baseline layer~{main.layer.value}, variant status={snap.status}."
                )
                d = DiffExplanation(
                    baseline=main, variant=snap,
                    status_delta=(main.status, snap.status),
                    header_delta=header_delta,
                    body_delta=snap.body_len - main.body_len,
                    relationship=relationship,
                    boundary=v["boundary"],
                    violation_evidence=violation_evidence,
                    normal_explanations_ruled_out=ruled_out,
                    confidence=conf,
                    interesting=interesting,
                    signals=signals,
                    hypotheses=hyps,
                    baseline_url=base_url,
                    variant_url=url,
                    variant_method=method,
                    variant_headers=v_headers,
                )
                return (v, d, snap)

        raw = await asyncio.gather(*(probe_one(v) for v in variants))
        results = []
        interesting_pairs = []
        for item in raw:
            if item is None:
                continue
            v, d, snap = item
            results.append(d)
            if d.interesting:
                interesting_pairs.append((v, d, snap))
        if self.enable_validation and self.validator is not None:
            for v, d, snap in interesting_pairs:
                ok, notes = await self.validator.validate(base_url, v, main, snap)
                d.validation_reproduced = ok
                d.validation_notes = notes
                if not ok:
                    d.interesting = False
                    d.normal_explanations_ruled_out.append(
                        "validation failed - delta not reproducible")
        return results



# ---------------------------------------------------------------------------
# Finding Builder
# ---------------------------------------------------------------------------

class FindingBuilder:
    def from_contradiction(self, c: Contradiction, idx: int) -> Finding:
        sev = "medium"
        if c.confidence >= 0.8:
            sev = "high"
        if c.boundary == Boundary.INTERNET_ORIGIN and c.confidence >= 0.75:
            sev = "high"
        return Finding(
            id=f"CONTRA-{idx:03d}",
            title=f"Boundary violation: {c.boundary.value}",
            discovery_evidence=c.evidence,
            boundary_crossed=c.boundary,
            preconditions=[c.assumption_a.statement, c.assumption_b.statement],
            validation=[c.observed_behavior, c.explanation],
            impact_evidence=c.evidence,
            confidence=c.confidence,
            remediation=self._remediate(c.boundary),
            severity=sev,
            related_contradictions=[c.explanation],
        )

    def from_diff(self, d: DiffExplanation, idx: int) -> Optional[Finding]:
        if not d.interesting or d.confidence < 0.35:
            return None
        m = re.search(r"Variant '([^']+)'", d.relationship or "")
        label = m.group(1) if m else f"variant-{idx:03d}"
        return Finding(
            id=f"DIFF-{idx:03d}",
            title=f"Layer interpretation mismatch on {d.boundary.value} [{label}]",
            discovery_evidence=d.violation_evidence,
            boundary_crossed=d.boundary,
            preconditions=[d.relationship],
            validation=d.normal_explanations_ruled_out + d.violation_evidence,
            impact_evidence=[
                f"status {d.status_delta[0]}→{d.status_delta[1]}",
                f"body delta {d.body_delta} bytes",
                f"header keys changed: {list(d.header_delta.keys())}",
            ],
            confidence=d.confidence,
            remediation=self._remediate(d.boundary),
            severity="high" if d.confidence >= 0.7 else "medium",
            baseline_curl=self._curl("GET", d.baseline_url, {}),
            variant_curl=self._curl(d.variant_method, d.variant_url, d.variant_headers),
            baseline_excerpt=f"status={d.baseline.status} hash={d.baseline.body_hash} len={d.baseline.body_len}",
            variant_excerpt=f"status={d.variant.status} hash={d.variant.body_hash} len={d.variant.body_len}",
        )

    def from_origin(self, c: OriginCandidate, idx: int,
                    has_front_end: bool = True) -> Optional[Finding]:
        if not (c.confirmed or c.confidence >= 0.7):
            return None
        if c.classification in ("public-endpoint", "edge-ip"):
            return None
        if not has_front_end:
            return None
        return Finding(
            id=f"ORIGIN-{idx:03d}",
            title=f"Origin candidate reachable: {c.ip_or_host}",
            discovery_evidence=c.relationship_evidence,
            boundary_crossed=Boundary.INTERNET_ORIGIN,
            preconditions=[
                "Architecture assumes origin is shielded by edge/WAF/CDN",
                f"Candidate source(s): {c.source}",
            ],
            validation=[
                f"confidence={c.confidence:.2f}",
                f"app_similarity={c.app_similarity:.2f}",
                f"classification={c.classification}",
                f"http_fp={c.http_fingerprint}",
                f"tls_fp={c.tls_fingerprint}",
            ],
            impact_evidence=[
                "Direct reachability bypasses edge controls (WAF, rate limits, bot management, geo blocks)"
            ],
            confidence=c.confidence,
            remediation="Restrict origin to accept traffic only from edge/proxy IP ranges; remove public DNS for origin hostnames; enforce network ACLs.",
            severity="high" if c.confirmed else "medium",
        )

    def _curl(self, method: str, url: str, headers: Dict[str, str]) -> str:
        parts = [f"curl -sS -D- -o- -X {method}"]
        for k, val in (headers or {}).items():
            parts.append(f"-H {k!r}:{val!r}".replace("'", "'\\''"))
        parts.append(f"'{url}'")
        return " ".join(parts)

    def _remediate(self, b: Boundary) -> str:
        return {
            Boundary.INTERNET_ORIGIN: "Block direct origin access; force all traffic through edge; network ACL + DNS hygiene.",
            Boundary.WAF_ORIGIN: "Ensure WAF and origin apply identical normalization; strip or sanitize hop-by-hop and rewrite headers.",
            Boundary.PROXY_ORIGIN: "Align cache key and header forwarding policy.",
            Boundary.ORIGIN_APP: "Make authorization and routing decisions on a single normalized view.",
            Boundary.INTERNET_WAF: "Review edge rules for consistency under header/path mutation.",
        }.get(b, "Review layer contract and normalize request view across the chain.")


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class WebPT:
    def __init__(self, target: str, concurrency: int = 12, enable_validation: bool = True):
        self.target = normalize(target)
        self.concurrency = concurrency
        self.enable_validation = enable_validation
        self.report = Report(
            target=self.target,
            started=datetime.now(timezone.utc).isoformat(),
            finished="",
        )

    async def run(self) -> Report:
        timeout = ClientTimeout(total=30, connect=7, sock_read=15)
        connector = TCPConnector(limit=self.concurrency, ssl=False, enable_cleanup_closed=True)
        async with ClientSession(timeout=timeout, connector=connector) as session:
            http = HttpEngine(session, self.concurrency)
            finger = LayerFingerprinter(http)
            origin_eng = OriginCandidateEngine(http)
            assume_eng = AssumptionEngine()
            validator = Validator(http) if self.enable_validation else None
            differ = ExplainedDiffer(http, validator=validator,
                                     enable_validation=self.enable_validation)
            finder = FindingBuilder()

            parsed = urlparse(self.target)
            domain = parsed.netloc.split(":")[0]
            scheme = parsed.scheme
            port = parsed.port or (443 if scheme == "https" else 80)

            print("[*] Fingerprinting main surface")
            main = await finger.snapshot(self.target)
            self.report.layers["main"] = main

            if main.status == 0:
                self.report.finished = datetime.now(timezone.utc).isoformat()
                self.report.summary = f"ABORT: unreachable. reason={main.notes[0] if main.notes else 'unknown'}"
                print(f"[!] {self.report.summary}")
                return self.report

            arch = classify_architecture(main)
            self.report.architecture = arch
            print(f"[*] Architecture: front_end={arch.front_end} edge={arch.edge_tech} origin={arch.origin_tech}")

            print("[*] Origin candidate discovery")
            candidates = await origin_eng.discover(domain, main, port=port, scheme=scheme)
            self.report.origin_candidates = candidates

            print("[*] Assumption extraction")
            assumptions = assume_eng.extract(main, candidates, arch)
            self.report.assumptions = assumptions

            print("[*] Differential probes")
            diffs = await differ.run(self.target, main)
            self.report.diffs = diffs

            print("[*] Contradiction analysis")
            contras = assume_eng.find_contradictions(assumptions, diffs, candidates, main, arch)
            self.report.contradictions = contras

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
                sig = (f.title
                       + "|" + f.boundary_crossed.value
                       + "|" + (f.discovery_evidence[0] if f.discovery_evidence else "")
                       + "|" + (f.validation[0] if f.validation else ""))
                if sig not in seen:
                    seen.add(sig)
                    unique.append(f)
            self.report.findings = unique

            self.report.finished = datetime.now(timezone.utc).isoformat()
            high = sum(1 for f in unique if f.severity in ("high", "critical"))
            med = sum(1 for f in unique if f.severity == "medium")
            self.report.summary = (
                f"Front-end: {'yes' if arch.front_end else 'no'} | "
                f"Assumptions: {len(assumptions)} | "
                f"Contradictions: {len(contras)} | "
                f"Origin candidates (conf≥0.5): {sum(1 for c in candidates if c.confidence >= 0.5)} | "
                f"Findings: {len(unique)} (high={high}, medium={med})"
            )
            return self.report


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

class ReportGenerator:
    def text(self, r: Report) -> str:
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings_sorted = sorted(r.findings,
                                 key=lambda f: (sev_order.get(f.severity, 9), -f.confidence))
        validated = [f for f in findings_sorted if f.id.startswith("DIFF") or f.id.startswith("CONTRA")]
        unconfirmed_diffs = [d for d in r.diffs if d.signals and not d.interesting]
        ruled_out_diffs = [d for d in r.diffs if not d.signals]

        lines = [
            "=" * 78,
            "WebPT v3 — Assumption Engine Report",
            f"Target   : {r.target}",
            f"Started  : {r.started}",
            f"Finished : {r.finished}",
            f"Reachable: {'yes' if r.layers.get('main') and r.layers['main'].status else 'no'}",
            f"Front-end: {'yes' if r.architecture and r.architecture.front_end else 'no'}",
            f"Layer    : {r.layers.get('main').layer.value if r.layers.get('main') else 'unknown'}",
            f"Findings : {sum(1 for f in r.findings if f.severity in ('high','critical'))} high, "
            f"{sum(1 for f in r.findings if f.severity == 'medium')} medium",
            "=" * 78,
            "",
            "## 1. Main Surface Snapshot",
        ]
        m = r.layers.get("main")
        if m:
            lines.append(f"  layer   : {m.layer.value}")
            lines.append(f"  status  : {m.status}")
            lines.append(f"  hash    : {m.body_hash}")
            lines.append(f"  len     : {m.body_len}")
            lines.append(f"  tech    : {m.technologies}")
            lines.append(f"  server  : {m.headers.get('server','')}")
            if m.notes:
                lines.append(f"  notes   : {m.notes[:2]}")

        if r.architecture:
            lines.append(f"  arch    : front_end={r.architecture.front_end} "
                         f"edge={r.architecture.edge_tech} "
                         f"proxy={r.architecture.proxy_tech} "
                         f"origin={r.architecture.origin_tech}")
            lines.append(f"  arch_ev : {r.architecture.evidence}")

        lines.append("\n## 2. Extracted Assumptions")
        for a in r.assumptions:
            lines.append(f"  [{a.layer.value}] ({a.confidence:.2f}) {a.statement}")
            lines.append(f"           source: {a.source}")

        lines.append("\n## 3. Origin Candidates")
        if not r.origin_candidates:
            lines.append("  (none)")
        for c in r.origin_candidates:
            flag = "CONFIRMED" if c.confirmed else f"conf={c.confidence:.2f}"
            lines.append(f"  [{flag}] {c.ip_or_host}  class={c.classification}")
            lines.append(f"      source     : {c.source}")
            lines.append(f"      dns        : {c.dns_relationship}")
            lines.append(f"      app_sim    : {c.app_similarity:.2f}")
            lines.append(f"      evidence   : {c.relationship_evidence[:3]}")

        lines.append("\n## 4. Probes Run")
        for d in r.diffs:
            tag = "INTERESTING" if d.interesting else ("SIGNAL" if d.signals else "quiet")
            lines.append(f"  [{tag}] {d.relationship.split('.')[0]}")
            lines.append(f"      status_delta: {d.status_delta}")
            if d.signals:
                for s in d.signals:
                    lines.append(f"      signal: {s.kind} (w={s.severity_weight:+.2f}) — {s.detail}")
                    lines.append(f"              rules_out: {s.rules_out}")
            if d.validation_reproduced is not None:
                lines.append(f"      validation_reproduced: {d.validation_reproduced}")
                if d.validation_notes:
                    lines.append(f"      validation_notes: {d.validation_notes}")

        lines.append("\n## 5. Findings (validated)")
        if not r.findings:
            lines.append("  (none)")
        for f in findings_sorted:
            lines.append(f"  [{f.severity.upper()}] {f.id} — {f.title}")
            lines.append(f"      boundary     : {f.boundary_crossed.value}")
            lines.append(f"      confidence   : {f.confidence:.2f}")
            lines.append(f"      preconditions: {f.preconditions}")
            lines.append(f"      validation   : {f.validation}")
            lines.append(f"      impact       : {f.impact_evidence}")
            if f.baseline_curl:
                lines.append(f"      reproduce_baseline: {f.baseline_curl}")
            if f.variant_curl:
                lines.append(f"      reproduce_variant : {f.variant_curl}")
            lines.append(f"      remediation  : {f.remediation}")

        lines.append("\n## 6. Unconfirmed Diffs (signals fired, not validated)")
        if not unconfirmed_diffs:
            lines.append("  (none)")
        for d in unconfirmed_diffs:
            lines.append(f"  boundary={d.boundary.value}  conf={d.confidence:.2f}")
            lines.append(f"      relationship : {d.relationship}")
            lines.append(f"      signals      : {[s.kind for s in d.signals]}")
            lines.append(f"      top_hypothesis: {d.hypotheses[0].name if d.hypotheses else 'n/a'}")

        lines.append("\n## 7. Ruled-Out Diffs (no signal fired)")
        lines.append(f"  count: {len(ruled_out_diffs)}")

        lines.append("\n## 8. Summary")
        lines.append(r.summary)
        lines.append("=" * 78)
        return "\n".join(lines)

    def json(self, r: Report) -> str:
        return json.dumps(asdict(r), indent=2, default=str)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

async def main():
    import argparse
    parser = argparse.ArgumentParser(prog="webpt_v3",
                                     description="WebPT v3 — Assumption Engine")
    parser.add_argument("target")
    parser.add_argument("-o", default="webpt_v3_report.txt")
    parser.add_argument("-j", default="webpt_v3_report.json")
    parser.add_argument("-c", type=int, default=12)
    parser.add_argument("--no-validate", action="store_true",
                        help="skip the reproduction pass")
    parser.add_argument("--json-only", action="store_true")
    args = parser.parse_args()

    engine = WebPT(args.target, concurrency=args.c,
                   enable_validation=not args.no_validate)
    report = await engine.run()
    gen = ReportGenerator()

    text = gen.text(report)
    Path(args.o).write_text(text)
    Path(args.j).write_text(gen.json(report))

    if args.json_only:
        print(json.dumps({
            "target": report.target,
            "reachable": bool(report.layers.get("main") and report.layers["main"].status),
            "front_end": bool(report.architecture and report.architecture.front_end),
            "findings": len(report.findings),
            "high": sum(1 for f in report.findings if f.severity in ("high", "critical")),
            "summary": report.summary,
        }, indent=2))
    else:
        print(text)

    print(f"\n[+] {args.o}")
    print(f"[+] {args.j}")

    if not (report.layers.get("main") and report.layers["main"].status):
        return 2
    if any(f.severity in ("high", "critical") for f in report.findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
