#!/usr/bin/env python3
"""
ARGOS - search.py
Free web search via DuckDuckGo — no API key needed.
"""

import re
import requests
from bs4 import BeautifulSoup
from ddgs import DDGS


def web_search(query: str, max_results: int = 5) -> str:
    print(f"  [*] Searching: {query}")
    try:
        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=max_results))
        if not results:
            return "[!] No search results found."
        output = f"[WEB SEARCH RESULTS FOR: {query}]\n" + "─" * 50 + "\n"
        for i, r in enumerate(results, 1):
            output += f"\n[{i}] {r['title']}\n"
            output += f"    URL     : {r['href']}\n"
            output += f"    Snippet : {r['body']}\n"
        return output
    except Exception as e:
        return f"[!] Search failed: {e}"


def search_cve(cve_id: str) -> str:
    print(f"  [*] Looking up {cve_id}...")
    ddg_results = web_search(f"{cve_id} vulnerability exploit details", max_results=3)
    mitre_url   = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
    mitre_data  = fetch_page(mitre_url, max_chars=2000)
    return f"{ddg_results}\n\n[MITRE CVE LOOKUP: {cve_id}]\n{mitre_data}"


def search_fix(vuln_name: str) -> str:
    return web_search(f"how to fix {vuln_name} security mitigation patch", max_results=3)


def fetch_page(url: str, max_chars: int = 3000) -> str:
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/120.0"}
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")
        for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
            tag.decompose()
        text  = soup.get_text(separator="\n", strip=True)
        lines = [l for l in text.splitlines() if l.strip()]
        clean = "\n".join(lines)
        if len(clean) > max_chars:
            clean = clean[:max_chars] + f"\n... [truncated at {max_chars} chars]"
        return clean
    except requests.exceptions.ConnectionError:
        return "[!] Could not connect to URL."
    except requests.exceptions.Timeout:
        return "[!] Page fetch timed out."
    except requests.exceptions.HTTPError as e:
        return f"[!] HTTP error: {e}"
    except Exception as e:
        return f"[!] Fetch failed: {e}"


def search_exploits(software: str, version: str = "") -> str:
    """Find public exploits / PoCs for a software (+optional version) via the web."""
    q = f"{software} {version}".strip()
    print(f"  [*] Searching exploits for: {q}")
    web = web_search(f"{q} exploit poc github exploit-db", max_results=6)
    return f"[EXPLOIT SEARCH: {q}]\n{web}"


def search_exploits_for_cve(cve_id: str) -> str:
    """Find public exploits / PoCs for a specific CVE, plus the NVD detail page."""
    cve_id = cve_id.upper().strip()
    print(f"  [*] Searching exploits for: {cve_id}")
    web = web_search(f"{cve_id} exploit poc github", max_results=6)
    nvd = fetch_page(f"https://nvd.nist.gov/vuln/detail/{cve_id}", max_chars=1500)
    return f"[EXPLOITS FOR {cve_id}]\n{web}\n\n[NVD DETAIL]\n{nvd}"


def handle_search_dispatch(query: str) -> str:
    query = query.strip()
    cve_match = re.search(r'CVE-\d{4}-\d{4,7}', query, re.IGNORECASE)
    if cve_match:
        return search_cve(cve_match.group())
    if any(w in query.lower() for w in ["exploit", "poc", "payload", "rce", "lfi", "sqli"]):
        return web_search(query + " exploit poc github", max_results=5)
    if any(w in query.lower() for w in ["fix", "patch", "mitigate", "harden", "secure"]):
        return search_fix(query)
    return web_search(query, max_results=5)


if __name__ == "__main__":
    print("[ search.py test ]\n[1] General search  [2] CVE lookup  [3] Fetch URL")
    choice = input("Choice: ").strip()
    if choice == "1":
        print(web_search(input("Query: ").strip()))
    elif choice == "2":
        print(search_cve(input("CVE ID: ").strip()))
    elif choice == "3":
        print(fetch_page(input("URL: ").strip()))
