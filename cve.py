#!/usr/bin/env python3
"""
ARGOS — cve.py
CVE lookup via NVD API v2 with local SQLite cache.
Offline-safe: on network failure returns cached data or empty list.
"""

import re
import json
import sqlite3
import datetime
import requests
from config import DB_PATH

NVD_API    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_DAYS = 7       # days before re-fetching
NVD_TIMEOUT = 8      # seconds per request

# ── Software version patterns from nmap output ───────────────────────────────
_SW_PATTERNS = [
    r"(Apache(?:\s+httpd)?)\s+([\d][\d\.]+)",
    r"(nginx)\s+([\d][\d\.]+)",
    r"(OpenSSH)\s+([\d][\d\.]+)",
    r"(OpenSSL)\s+([\d][\d\.]+)",
    r"(PHP)\s+([\d][\d\.]+)",
    r"(MySQL)\s+([\d][\d\.]+)",
    r"(MariaDB)\s+([\d][\d\.]+)",
    r"(PostgreSQL)\s+([\d][\d\.]+)",
    r"(Microsoft\s+IIS)\s+([\d][\d\.]+)",
    r"(Tomcat)\s+([\d][\d\.]+)",
    r"(WordPress)\s+([\d][\d\.]+)",
    r"(Drupal)\s+([\d][\d\.]+)",
    r"(Joomla)\s+([\d][\d\.]+)",
    r"(vsftpd)\s+([\d][\d\.]+)",
    r"(ProFTPD)\s+([\d][\d\.]+)",
    r"(Samba)\s+([\d][\d\.]+)",
    r"(Exim)\s+([\d][\d\.]+)",
    r"(Postfix)\s+([\d][\d\.]+)",
    r"(Dovecot)\s+([\d][\d\.]+)",
    r"(Node\.js)\s+([\d][\d\.]+)",
    r"(Python)\s+([\d][\d\.]+)",
    r"(Ruby)\s+([\d][\d\.]+)",
    r"(Jenkins)\s+([\d][\d\.]+)",
    r"(GitLab)\s+([\d][\d\.]+)",
    r"(Elasticsearch)\s+([\d][\d\.]+)",
    r"(Redis)\s+([\d][\d\.]+)",
    r"(MongoDB)\s+([\d][\d\.]+)",
]


def _ensure_cache_table(conn: sqlite3.Connection):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cve_cache (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            software   TEXT NOT NULL,
            version    TEXT NOT NULL,
            cve_data   TEXT,
            fetched_at TEXT NOT NULL,
            UNIQUE(software, version)
        )
    """)
    conn.commit()


def extract_software_versions(text: str) -> list:
    """Return list of (software, version) pairs found in text."""
    found = {}
    for pat in _SW_PATTERNS:
        for m in re.finditer(pat, text, re.IGNORECASE):
            sw  = m.group(1).strip()
            ver = m.group(2).strip()
            key = sw.lower()
            if key not in found:
                found[key] = (sw, ver)
    return list(found.values())


def _fetch_nvd(software: str, version: str) -> list:
    """Query NVD API v2. Returns list of CVE dicts."""
    try:
        resp = requests.get(
            NVD_API,
            params={
                "keywordSearch":    f"{software} {version}",
                "resultsPerPage":   5,
            },
            timeout=NVD_TIMEOUT,
            headers={"Accept": "application/json"},
        )
        if resp.status_code != 200:
            return []
        vulns = resp.json().get("vulnerabilities", [])
        results = []
        for item in vulns:
            cve_id = item.get("cve", {}).get("id", "")
            descs  = item.get("cve", {}).get("descriptions", [])
            desc   = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            # CVSS score: prefer v3.1 → v3.0 → v2
            score = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metrics = item.get("cve", {}).get("metrics", {}).get(key, [])
                if metrics:
                    score = metrics[0].get("cvssData", {}).get("baseScore")
                    break
            results.append({
                "cve_id":  cve_id,
                "score":   score,
                "summary": desc[:300],
            })
        results.sort(key=lambda x: x["score"] or 0, reverse=True)
        return results[:5]
    except Exception:
        return []


def lookup_cves(software: str, version: str, force_refresh: bool = False) -> list:
    """Return CVEs for software/version. Uses SQLite cache; falls back to empty list."""
    try:
        conn = sqlite3.connect(DB_PATH)
        _ensure_cache_table(conn)

        if not force_refresh:
            row = conn.execute(
                "SELECT cve_data, fetched_at FROM cve_cache WHERE software=? AND version=?",
                (software.lower(), version),
            ).fetchone()
            if row:
                now_utc = datetime.datetime.now(datetime.timezone.utc)
                fetched = datetime.datetime.fromisoformat(row[1])
                if fetched.tzinfo is None:
                    fetched = fetched.replace(tzinfo=datetime.timezone.utc)
                age = (now_utc - fetched).days
                if age < CACHE_DAYS:
                    conn.close()
                    return json.loads(row[0])

        cves = _fetch_nvd(software, version)
        now  = datetime.datetime.now(datetime.timezone.utc).isoformat()
        conn.execute(
            """INSERT INTO cve_cache(software, version, cve_data, fetched_at)
               VALUES(?,?,?,?)
               ON CONFLICT(software, version) DO UPDATE
               SET cve_data=excluded.cve_data, fetched_at=excluded.fetched_at""",
            (software.lower(), version, json.dumps(cves), now),
        )
        conn.commit()
        conn.close()
        return cves
    except Exception:
        return []


def enrich_with_cves(nmap_text: str) -> str:
    """
    Parse nmap output for software versions, look up CVEs,
    return a formatted string to inject into the LLM prompt.
    Returns empty string if nothing found.
    """
    pairs = extract_software_versions(nmap_text)
    if not pairs:
        return ""

    lines = ["[CVE Enrichment — NVD lookup]"]
    for sw, ver in pairs:
        cves = lookup_cves(sw, ver)
        if cves:
            lines.append(f"  {sw} {ver}:")
            for c in cves:
                score = f"CVSS {c['score']:.1f}" if c["score"] is not None else "no score"
                lines.append(f"    {c['cve_id']} ({score}): {c['summary'][:120]}")
        else:
            lines.append(f"  {sw} {ver}: no CVEs in NVD")

    return "\n".join(lines)


def show_cve_cache_stats() -> str:
    """Return a one-line string with cache stats for the settings menu."""
    try:
        conn = sqlite3.connect(DB_PATH)
        _ensure_cache_table(conn)
        total = conn.execute("SELECT COUNT(*) FROM cve_cache").fetchone()[0]
        conn.close()
        return f"{total} software entries cached"
    except Exception:
        return "unavailable"
