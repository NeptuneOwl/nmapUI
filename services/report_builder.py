"""
Builds the report data structure that the report.html template renders.
Includes a recursive `format_any_data`-style renderer for full host/CVE
details, exactly like the original DashboardGenerator.py.
"""

import html as _html
import re
from urllib.parse import urlparse

from . import storage


# ============================================================
# Recursive value renderer (mirrors original format_any_data)
# ============================================================

_URL_RE = re.compile(r"(https?://[^\s]+)")


def format_any_data(data) -> str:
    """Recursively render any Python structure as styled HTML."""
    if isinstance(data, dict):
        if not data:
            return '<span class="text-muted fst-italic">Empty</span>'
        inner = '<div class="detail-section">'
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                inner += (
                    '<div class="detail-block">'
                    f'<h6 class="detail-header">{_html.escape(str(key))}</h6>'
                    f'{format_any_data(value)}'
                    '</div>'
                )
            else:
                inner += (
                    '<div class="detail-row">'
                    f'<div class="detail-key">{_html.escape(str(key))}</div>'
                    f'<div class="detail-value">{format_any_data(value)}</div>'
                    '</div>'
                )
        return inner + '</div>'

    if isinstance(data, list):
        if not data:
            return '<span class="text-muted fst-italic">None</span>'
        items = ''.join(
            f'<div class="detail-list-item">{format_any_data(item)}</div>'
            for item in data
        )
        return f'<div class="detail-list">{items}</div>'

    if isinstance(data, bool):
        return f'<span>{str(data)}</span>'

    if data is None:
        return '<span class="text-muted fst-italic">null</span>'

    val = str(data)
    if val == "up":
        return '<span class="badge badge-success">UP</span>'
    if val == "open":
        return '<span class="badge badge-info">OPEN</span>'
    if val == "closed":
        return '<span class="badge badge-secondary">CLOSED</span>'
    if val == "filtered":
        return '<span class="badge badge-warning">FILTERED</span>'

    # Linkify URLs
    def _sub(m):
        url = m.group(1)
        return f'<a class="detail-link" href="{_html.escape(url)}" target="_blank" rel="noopener">{_html.escape(url)}</a>'
    safe = _html.escape(val)
    safe = _URL_RE.sub(_sub, safe)
    return f'<span>{safe}</span>'


# ============================================================
# CVE helpers
# ============================================================

def _pick_metric(cve):
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if arr:
            m = arr[0]
            data = m.get("cvssData") or {}
            return {
                "score":    data.get("baseScore"),
                "vector":   data.get("vectorString"),
                "severity": (data.get("baseSeverity") or m.get("baseSeverity") or "UNKNOWN").upper(),
                "version":  data.get("version", ""),
            }
    return {"score": None, "vector": None, "severity": "UNKNOWN", "version": ""}


def _english_description(cve):
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def _cwe_list(cve):
    out = []
    for w in cve.get("weaknesses") or []:
        for d in w.get("description") or []:
            v = d.get("value")
            if v and v not in out:
                out.append(v)
    return out


def _references(cve):
    refs, patches = [], []
    seen = set()
    for r in cve.get("references") or []:
        url = r.get("url")
        if not url or url in seen:
            continue
        seen.add(url)
        tags = [t.lower() for t in (r.get("tags") or [])]
        entry = {"url": url, "tags": r.get("tags") or []}
        refs.append(entry)
        if any("patch" in t or "vendor advisory" in t for t in tags):
            patches.append(entry)
    return refs, patches


def _normalize_cve(cve):
    metric = _pick_metric(cve)
    refs, patches = _references(cve)
    return {
        "id":          cve.get("id", "N/A"),
        "severity":    metric["severity"],
        "score":       metric["score"],
        "vector":      metric["vector"],
        "published":   (cve.get("published") or "")[:10],
        "description": _english_description(cve),
        "cwes":        _cwe_list(cve),
        "references":  refs,
        "patches":     patches,
        "url":         f"https://nvd.nist.gov/vuln/detail/{cve.get('id','')}",
        "matched_cpes": cve.get("_matched_cpes", []),
        "raw_html":    format_any_data(cve),   # full recursive dump
    }


# ============================================================
# Host helpers
# ============================================================

def _host_summary(ip, info):
    ports = []
    for label, svc in (info.get("scan") or {}).items():
        ports.append({
            "label":    label,
            "state":    svc.get("state"),
            "name":     svc.get("name"),
            "product":  svc.get("product"),
            "version":  svc.get("version"),
            "extrainfo": svc.get("extrainfo"),
            "cpe":      svc.get("cpe"),
        })
    return {
        "ip":        ip,
        "state":     info.get("status", {}).get("state", "unknown"),
        "hostnames": info.get("hostnames") or [],
        "addresses": info.get("addresses") or {},
        "vendor":    info.get("vendor") or {},
        "ports":     ports,
        "raw_html":  format_any_data(info),   # full recursive dump
    }


# ============================================================
# Public API
# ============================================================

def build(scan_id: str):
    meta = storage.load_json(scan_id, "meta.json")
    if not meta:
        return None

    scan = storage.load_json(scan_id, "scan.json") or {}
    cpes = storage.load_json(scan_id, "cpes.json") or {}
    raw_cves = storage.load_json(scan_id, "nvd_search_results.json") or []

    hosts = [_host_summary(ip, info) for ip, info in scan.items()]
    hosts.sort(key=lambda h: h["ip"])

    cves = sorted(
        (_normalize_cve(c) for c in raw_cves),
        key=lambda c: (
            0 if c["severity"] == "CRITICAL" else
            1 if c["severity"] == "HIGH" else
            2 if c["severity"] == "MEDIUM" else
            3 if c["severity"] == "LOW" else 4,
            -(c["score"] or 0),
        )
    )

    cpe_index = {}
    for ip, lst in cpes.items():
        for port_label, cpe in lst:
            cpe_index.setdefault(cpe, []).append({"host": ip, "port": port_label})

    for c in cves:
        affected = []
        for cpe in c["matched_cpes"]:
            affected.extend(cpe_index.get(cpe, []))
        c["affected"] = affected

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for c in cves:
        counts[c["severity"]] = counts.get(c["severity"], 0) + 1

    stats = {
        "total_hosts": len(hosts),
        "up_hosts":    sum(1 for h in hosts if h["state"] == "up"),
        "open_ports":  sum(1 for h in hosts for p in h["ports"] if p["state"] == "open"),
        "total_cves":  len(cves),
        "severities":  counts,
    }

    return {
        "id":     scan_id,
        "meta":   meta,
        "stats":  stats,
        "hosts":  hosts,
        "cves":   cves,
    }
