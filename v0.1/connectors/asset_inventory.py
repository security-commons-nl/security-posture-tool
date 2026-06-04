"""Asset-inventaris (1.3). Gecombineerde CSV met kolom `source` (ad|dhcp|fw_arp).

Pass als ≥90% van de unieke IPs voorkomt in ≥2 bronnen, én de totalen per bron
niet meer dan 20% uiteenlopen.
"""
from __future__ import annotations
from ._csv_helpers import read_rows, missing_cols, pct

REQUIRED = {"source", "ip"}
EXPECTED_SOURCES = {"ad", "dhcp", "fw_arp"}


def parse(raw_bytes: bytes) -> dict:
    headers, rows = read_rows(raw_bytes)
    miss = missing_cols(REQUIRED, headers)
    if miss:
        return {"verdict": "unparsed", "missing": miss}

    per_source: dict[str, set] = {s: set() for s in EXPECTED_SOURCES}
    ip_sources: dict[str, set] = {}
    for r in rows:
        src = (r.get("source") or "").strip().lower()
        ip = (r.get("ip") or "").strip()
        if not src or not ip:
            continue
        if src in per_source:
            per_source[src].add(ip)
        ip_sources.setdefault(ip, set()).add(src)

    counts = {s: len(ips) for s, ips in per_source.items()}
    total_unique = len(ip_sources)
    in_multi = sum(1 for s in ip_sources.values() if len(s) >= 2)
    multi_pct = pct(in_multi, total_unique)

    if any(c == 0 for c in counts.values()):
        verdict = "fail"
    else:
        spread_max = max(counts.values())
        spread_min = min(counts.values())
        spread_ok = (spread_max - spread_min) / spread_max <= 0.2 if spread_max else False
        verdict = "pass" if multi_pct >= 90 and spread_ok else "fail"

    return {"verdict": verdict,
            "total_unique_ips": total_unique,
            "counts_per_source": counts,
            "in_multi_source": in_multi,
            "multi_source_pct": multi_pct,
            "threshold_pct": 90}
