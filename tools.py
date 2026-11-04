#!/usr/bin/env python3
"""
ARGOS - tools.py  (cross-platform: Windows + Linux)
Recon tool runners. Pipelines use ThreadPoolExecutor for parallelism.
on_done(tool_name) callback enables live progress UI in argos.py.
"""

import platform
import subprocess
import socket
import re
import ssl
import datetime
import requests
import urllib3
import settings
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

IS_WINDOWS = platform.system() == "Windows"


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# BASE SUBPROCESS RUNNER
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def run_tool(command: list, timeout: int = 120) -> str:
    kw = {}
    if IS_WINDOWS and hasattr(subprocess, "CREATE_NO_WINDOW"):
        kw["creationflags"] = subprocess.CREATE_NO_WINDOW
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, **kw)
        out = result.stdout.strip()
        err = result.stderr.strip()
        if out and err:
            return out + "\n[STDERR]\n" + err
        return out or err or "[!] Tool returned no output."
    except subprocess.TimeoutExpired:
        return f"[!] Timed out after {timeout}s: {' '.join(command)}"
    except FileNotFoundError:
        return f"[!] Tool not found: {command[0]}"
    except Exception as e:
        return f"[!] Error running {command[0]}: {e}"


def _tool_available(name: str) -> bool:
    try:
        subprocess.run([name, "--version"], capture_output=True, timeout=3)
        return True
    except Exception:
        return False


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# NMAP
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def run_nmap(target: str) -> str:
    return run_tool(["nmap", "-sV", "-sC", "-T4", "--open", target], timeout=180)


def run_nmap_deep(target: str) -> str:
    """Full port scan + NSE vuln/http/ssl scripts."""
    # Pass 1: full port discovery
    full = run_tool(["nmap", "-p-", "-T4", "--open", "-oG", "-", target], timeout=600)
    # Pass 2: service + vulnerability scripts on common range
    vuln = run_tool([
        "nmap", "-sV", "--script",
        "vuln,http-title,http-methods,http-headers,ssl-cert,ssl-enum-ciphers",
        "-T4", target,
    ], timeout=600)
    return f"[FULL PORT SCAN]\n{full}\n\n[VULN + SERVICE SCRIPTS]\n{vuln}"


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# WHOIS
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _whois_native(target: str) -> str:
    return run_tool(["whois", target], timeout=30)


def _whois_python(target: str) -> str:
    try:
        import whois as _whois
        w = _whois.whois(target)
        lines = [f"{k}: {v}" for k, v in w.items() if v]
        return "\n".join(lines) if lines else "[!] No whois data."
    except ImportError:
        return "[!] python-whois not installed: pip install python-whois"
    except Exception as e:
        return f"[!] whois error: {e}"


def run_whois(target: str) -> str:
    if not IS_WINDOWS and _tool_available("whois"):
        result = _whois_native(target)
        if "[!] Tool not found" not in result:
            return result
    return _whois_python(target)


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# WEB TECH FINGERPRINT  (whatweb replacement)
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

_TECH_PATTERNS = {
    "WordPress":  [r"wp-content", r"wordpress"],
    "Joomla":     [r"joomla"],
    "Drupal":     [r"drupal"],
    "Magento":    [r"magento", r"mage"],
    "Shopify":    [r"shopify", r"cdn\.shopify\.com"],
    "React":      [r"__REACT_DEVTOOLS", r"react-dom"],
    "Vue.js":     [r"__vue", r"vue\.min\.js"],
    "Angular":    [r"ng-version", r"angular\.min\.js"],
    "Bootstrap":  [r"bootstrap\.min"],
    "jQuery":     [r"jquery"],
    "Laravel":    [r"laravel_session", r"/vendor/laravel"],
    "Django":     [r"csrftoken", r"django"],
    "ASP.NET":    [r"__VIEWSTATE", r"\.aspx"],
    "PHP":        [r"\.php\b"],
    "Ruby/Rails": [r"_session_id", r"X-Runtime"],
}


def run_whatweb(target: str) -> str:
    # Try native whatweb on Linux
    if not IS_WINDOWS and _tool_available("whatweb"):
        result = run_tool(["whatweb", "-a", "3", target], timeout=60)
        if "[!] Tool not found" not in result:
            return result
    # Python fallback
    ua = settings.get_user_agent()
    findings = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{target}"
        try:
            resp = requests.get(url, timeout=15, allow_redirects=True,
                                headers={"User-Agent": ua}, verify=False)
            srv     = resp.headers.get("Server", "")
            powered = resp.headers.get("X-Powered-By", "")
            xfw     = resp.headers.get("X-Framework", "")
            if srv:     findings.append(f"Server: {srv}")
            if powered: findings.append(f"X-Powered-By: {powered}")
            if xfw:     findings.append(f"X-Framework: {xfw}")
            cookies = "; ".join(resp.cookies.keys())
            if cookies: findings.append(f"Cookies: {cookies}")
            html = resp.text.lower()
            for tech, pats in _TECH_PATTERNS.items():
                for p in pats:
                    if re.search(p, html):
                        findings.append(f"Detected: {tech}")
                        break
            for svc in ("nginx", "apache", "iis", "caddy", "lighttpd", "litespeed"):
                if svc in srv.lower():
                    findings.append(f"Web Server: {svc.upper()}")
            break
        except requests.exceptions.SSLError:
            continue
        except Exception as e:
            findings.append(f"[{scheme}] {e}")
    return "\n".join(findings) if findings else "[!] Could not connect."


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# HTTP HEADERS
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def run_curl_headers(target: str) -> str:
    # Try native curl on Linux
    if not IS_WINDOWS and _tool_available("curl"):
        out = run_tool(["curl", "-sI", "--max-time", "10", "--location",
                        f"http://{target}"], timeout=20)
        https_out = run_tool(["curl", "-sI", "--max-time", "10", "--location",
                              "-k", f"https://{target}"], timeout=20)
        if "[!] Tool not found" not in out:
            return f"[HTTP Headers]\n{out}\n\n[HTTPS Headers]\n{https_out}"
    # Python fallback
    ua = settings.get_user_agent()
    results = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{target}"
        try:
            resp = requests.head(url, timeout=10, allow_redirects=True,
                                 headers={"User-Agent": ua}, verify=False)
            block = f"[{scheme.upper()} Headers â€” HTTP {resp.status_code}]\n"
            for k, v in resp.headers.items():
                block += f"  {k}: {v}\n"
            results.append(block)
        except requests.exceptions.SSLError:
            results.append(f"[{scheme.upper()} Headers] SSL error")
        except Exception as e:
            results.append(f"[{scheme.upper()} Headers] {e}")
    return "\n".join(results)


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# DNS / DIG
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _dig_native(target: str) -> str:
    parts = []
    for qtype in ("A", "MX", "NS", "TXT"):
        r = run_tool(["dig", "+short", qtype, target], timeout=15)
        parts.append(f"[{qtype}]\n{r}")
    return "\n\n".join(parts)


def _dig_python(target: str) -> str:
    try:
        import dns.resolver
        output = []
        for qtype in ("A", "MX", "NS", "TXT"):
            try:
                answers = dns.resolver.resolve(target, qtype, lifetime=10)
                records = [str(r) for r in answers]
                output.append(f"[{qtype} Records]\n" + "\n".join(records))
            except Exception:
                output.append(f"[{qtype} Records]\n(none)")
        return "\n\n".join(output)
    except ImportError:
        try:
            ip = socket.gethostbyname(target)
            return f"[A Records]\n{ip}\n\n[MX/NS/TXT]\ndnspython not installed"
        except Exception as e:
            return f"[!] DNS error: {e}"


def run_dig(target: str) -> str:
    if not IS_WINDOWS and _tool_available("dig"):
        result = _dig_native(target)
        if "[!] Tool not found" not in result:
            return result
    return _dig_python(target)


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# NIKTO
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def run_nikto(target: str) -> str:
    if not IS_WINDOWS:
        result = run_tool(["nikto", "-h", target, "-nointeractive"], timeout=300)
        if "[!] Tool not found" not in result:
            return result
    # Windows: try WSL or Docker
    wsl = run_tool(["wsl", "nikto", "-h", target, "-nointeractive"], timeout=300)
    if "[!] Tool not found" not in wsl:
        return wsl
    return (
        "[!] nikto not found.\n"
        "    Linux: sudo apt install nikto\n"
        "    Windows: wsl or docker run --rm frapsoft/nikto -h TARGET\n"
        "    Analysis continues without nikto data."
    )


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# DEEP SCAN EXTRAS
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def run_security_headers(target: str) -> str:
    """Full security headers audit with graded findings."""
    ua = settings.get_user_agent()

    HEADERS_SPEC = [
        # (header-name, label, severity-if-missing, note-if-missing)
        ("strict-transport-security",   "HSTS",                 "HIGH",   "Site does not enforce HTTPS"),
        ("content-security-policy",     "Content-Security-Policy","HIGH", "No CSP â€” XSS risk"),
        ("x-frame-options",             "X-Frame-Options",      "MEDIUM", "Clickjacking risk"),
        ("x-content-type-options",      "X-Content-Type-Options","LOW",   "MIME sniffing allowed"),
        ("referrer-policy",             "Referrer-Policy",       "LOW",   "Full URL leaked in referrer"),
        ("permissions-policy",          "Permissions-Policy",   "LOW",   "Browser features unrestricted"),
        ("access-control-allow-origin", "CORS (ACAO)",          "INFO",  "Check if wildcard '*'"),
    ]

    results = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{target}"
        try:
            resp = requests.get(url, headers={"User-Agent": ua}, timeout=15,
                                allow_redirects=True, verify=False)
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            results.append(f"[Security Headers Audit â€” {scheme.upper()} {resp.status_code}]")

            for name, label, missing_sev, missing_note in HEADERS_SPEC:
                if name in hdrs:
                    val = hdrs[name][:120]
                    # Flag dangerous CORS wildcard
                    if name == "access-control-allow-origin" and val.strip() == "*":
                        results.append(f"  [WARN  ] {label}: * (wildcard â€” any origin allowed)")
                    else:
                        results.append(f"  [PRESENT] {label}: {val}")
                else:
                    results.append(f"  [MISSING/{missing_sev}] {label} â€” {missing_note}")

            # Extra info headers
            srv     = resp.headers.get("Server", "")
            powered = resp.headers.get("X-Powered-By", "")
            if srv:     results.append(f"  [INFO  ] Server header exposed: {srv}")
            if powered: results.append(f"  [INFO  ] X-Powered-By exposed: {powered}")

            # Cookie flags
            for ck_name, ck in resp.cookies.items():
                flags = []
                if not ck.has_nonstandard_attr("HttpOnly"): flags.append("missing HttpOnly")
                if not ck.secure:                           flags.append("missing Secure")
                if not ck.has_nonstandard_attr("SameSite"): flags.append("missing SameSite")
                if flags:
                    results.append(f"  [WARN  ] Cookie '{ck_name}': {', '.join(flags)}")

            break
        except Exception as e:
            results.append(f"[{scheme.upper()}] Error: {e}")

    return "\n".join(results)


def run_ssl_check(target: str) -> str:
    """SSL/TLS certificate and configuration check."""
    try:
        ctx = ssl.create_default_context()
        s   = socket.create_connection((target, 443), timeout=10)
        with ctx.wrap_socket(s, server_hostname=target) as ssock:
            cert     = ssock.getpeercert()
            protocol = ssock.version()
            cipher   = ssock.cipher()

        subject  = dict(x[0] for x in cert.get("subject", []))
        issuer   = dict(x[0] for x in cert.get("issuer", []))
        not_after = cert.get("notAfter", "")
        san      = cert.get("subjectAltName", [])

        expiry_note = ""
        if not_after:
            try:
                exp_date  = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (exp_date - datetime.datetime.utcnow()).days
                expiry_note = f"  [{'EXPIRED' if days_left < 0 else f'{days_left} days left'}]"
            except Exception:
                pass

        lines = [
            "[SSL/TLS Certificate]",
            f"  Subject:  {subject.get('commonName', 'N/A')}",
            f"  Issuer:   {issuer.get('organizationName', 'N/A')}",
            f"  Expires:  {not_after}{expiry_note}",
            f"  SANs:     {', '.join(v for _, v in san[:6])}",
            f"  Protocol: {protocol}",
            f"  Cipher:   {cipher[0] if cipher else 'N/A'}",
        ]

        # Flag weak protocols
        if protocol in ("TLSv1", "TLSv1.1", "SSLv3"):
            lines.append(f"  [WEAK PROTOCOL] {protocol} is deprecated â€” HIGH risk")

        return "\n".join(lines)

    except ssl.SSLCertVerificationError as e:
        return f"[SSL/TLS Certificate]\n  [INVALID CERT] {e}"
    except ConnectionRefusedError:
        return "[SSL/TLS Certificate]\n  Port 443 not open."
    except Exception as e:
        return f"[SSL/TLS Certificate]\n  Error: {e}"


def run_subdomain_enum(target: str) -> str:
    """Check common subdomains via DNS resolution."""
    base = re.sub(r"^www\.", "", target).strip()
    if base.count(".") < 1:
        return "[Subdomain Enum]\n  Not a domain â€” skipping."

    SUBS = [
        # Common web
        "www", "www2", "web", "app", "apps", "mobile", "m",
        # Mail
        "mail", "smtp", "pop", "pop3", "imap", "mx", "mx1", "mx2", "webmail",
        # Network
        "ftp", "sftp", "ns", "ns1", "ns2", "dns", "vpn", "proxy", "gateway",
        # Dev / ops
        "dev", "dev1", "dev2", "staging", "stage", "test", "testing",
        "qa", "uat", "sandbox", "preview", "demo", "beta", "alpha",
        "ci", "cd", "build", "deploy",
        # Admin
        "admin", "administrator", "manage", "management",
        "panel", "control", "cpanel", "plesk", "dashboard",
        # API / services
        "api", "api2", "rest", "graphql", "services",
        "auth", "oauth", "login", "sso", "id", "identity",
        # Content / CDN
        "blog", "shop", "store", "cdn", "static", "media", "assets",
        "images", "files", "upload", "downloads",
        # Infra / monitoring
        "git", "gitlab", "github", "bitbucket", "svn",
        "jenkins", "ci", "travis", "circleci",
        "jira", "confluence", "wiki", "docs", "help", "support",
        "monitor", "monitoring", "grafana", "prometheus", "kibana",
        "elastic", "elasticsearch", "logstash",
        "k8s", "kubernetes", "docker", "registry",
        # Business
        "portal", "secure", "internal", "intranet", "extranet",
        "careers", "jobs", "news", "press", "ir",
        # DB / backend
        "db", "database", "mysql", "postgres", "redis", "mongo",
        # Misc
        "backup", "old", "legacy", "archive",
    ]

    found = []
    try:
        import dns.resolver
        for sub in SUBS:
            fqdn = f"{sub}.{base}"
            try:
                answers = dns.resolver.resolve(fqdn, "A", lifetime=3)
                ips = [str(r) for r in answers]
                found.append(f"  [FOUND] {fqdn} â†’ {', '.join(ips)}")
            except Exception:
                pass
    except ImportError:
        # fallback: socket
        for sub in SUBS[:10]:
            fqdn = f"{sub}.{base}"
            try:
                ip = socket.gethostbyname(fqdn)
                found.append(f"  [FOUND] {fqdn} â†’ {ip}")
            except Exception:
                pass

    header = f"[Subdomain Enumeration â€” {base}]"
    return header + "\n" + ("\n".join(found) if found else "  No common subdomains found.")


def run_dir_enum(target: str) -> str:
    """Check common web paths for interesting endpoints."""
    ua = settings.get_user_agent()

    PATHS = [
        # Robots / sitemaps / security
        "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
        "/.well-known/security.txt", "/.well-known/change-password",
        # Git / VCS exposure
        "/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG",
        "/.svn/entries", "/.hg/", "/.bzr/",
        # Environment / secrets
        "/.env", "/.env.local", "/.env.production", "/.env.backup",
        "/.env.dev", "/.env.example", "/config.env",
        # Backup files
        "/backup", "/backup.zip", "/backup.sql", "/backup.tar.gz",
        "/db_backup.sql", "/dump.sql", "/site_backup.zip",
        "/old/", "/bak/", "/backup/",
        # Admin panels
        "/admin", "/administrator", "/admin/login", "/admin/dashboard",
        "/manager", "/management", "/cpanel", "/cPanel",
        "/plesk", "/directadmin", "/webmin", "/ispconfig",
        # Auth pages
        "/login", "/signin", "/signup", "/register", "/logout",
        "/auth", "/oauth", "/sso", "/saml",
        # WordPress
        "/wp-admin", "/wp-login.php", "/wp-config.php", "/wp-config.php.bak",
        "/wp-content/debug.log", "/xmlrpc.php", "/readme.html",
        "/wp-json/wp/v2/users",
        # Other CMS
        "/administrator/index.php", "/joomla.xml", "/configuration.php",
        "/user/login", "/CHANGELOG.txt", "/sites/default/settings.php",
        # PHP info / debug
        "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
        "/php.php", "/php_info.php",
        # Config files
        "/config.php", "/config.xml", "/config.json", "/config.yml",
        "/app/config.php", "/settings.php", "/settings.py", "/settings.yml",
        "/web.config", "/.htaccess", "/nginx.conf",
        # API endpoints
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/api/v1/users", "/api/v1/admin",
        "/graphql", "/graphiql", "/__graphql",
        "/swagger", "/swagger-ui.html", "/swagger.json",
        "/openapi.json", "/openapi.yaml", "/api-docs",
        # Debug / monitoring
        "/console", "/debug", "/trace",
        "/health", "/healthz", "/health/live", "/health/ready",
        "/status", "/metrics", "/actuator", "/actuator/health",
        "/actuator/env", "/actuator/mappings",
        "/.DS_Store",
        # Database / tools
        "/phpmyadmin", "/phpmyadmin/", "/mysql", "/adminer.php",
        "/myadmin", "/pma/", "/dbadmin",
        # Cloud metadata
        "/latest/meta-data", "/opc/v1/instance",
        # Misc sensitive
        "/server-status", "/server-info",
        "/WEB-INF/web.xml", "/WEB-INF/classes/",
        "/elmah.axd", "/trace.axd",
        "/.aws/credentials", "/.ssh/id_rsa", "/.ssh/authorized_keys",
    ]

    STATUS_NOTE = {200: "ACCESSIBLE", 403: "FORBIDDEN (exists)", 301: "REDIRECT", 302: "REDIRECT"}

    found = []
    for scheme in ("https", "http"):
        base_url = f"{scheme}://{target}"
        try:
            requests.head(base_url, timeout=5, verify=False)
            for path in PATHS:
                url = base_url + path
                try:
                    r = requests.head(url, headers={"User-Agent": ua},
                                      timeout=5, verify=False, allow_redirects=False)
                    if r.status_code in STATUS_NOTE:
                        note = STATUS_NOTE[r.status_code]
                        HIGH_PATHS = {
                            "/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG",
                            "/.env", "/.env.local", "/.env.production", "/.env.backup",
                            "/.env.dev", "/config.env",
                            "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
                            "/wp-config.php", "/wp-config.php.bak", "/wp-content/debug.log",
                            "/sites/default/settings.php", "/app/etc/local.xml",
                            "/backup.sql", "/dump.sql", "/db_backup.sql",
                            "/.aws/credentials", "/.ssh/id_rsa", "/WEB-INF/web.xml",
                            "/adminer.php", "/elmah.axd", "/trace.axd",
                        }
                        sev = "HIGH" if path in HIGH_PATHS else "INFO"
                        found.append(f"  [{r.status_code}][{sev}] {url}  ({note})")
                except Exception:
                    pass
            break
        except Exception:
            continue

    header = "[Path/Directory Discovery]"
    return header + "\n" + ("\n".join(found) if found else "  No interesting paths found.")


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# RECON PIPELINES
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def run_banner_grab(target: str) -> str:
    """Grab banners from sensitive/interesting TCP ports."""
    PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        110: "POP3", 143: "IMAP",
        3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL",
        6379: "Redis", 11211: "Memcached", 27017: "MongoDB",
        5984: "CouchDB", 9200: "Elasticsearch",
        8080: "HTTP-alt", 8443: "HTTPS-alt", 8888: "HTTP-alt2",
        2375: "Docker", 2376: "Docker-TLS", 10250: "Kubernetes",
    }
    DANGEROUS_SERVICES = {"Telnet", "Redis", "Memcached", "Docker", "Kubernetes",
                          "Elasticsearch", "MongoDB", "CouchDB"}
    findings = []
    for port, service in PORTS.items():
        try:
            s = socket.create_connection((target, port), timeout=3)
            try:
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(512).decode("utf-8", errors="replace").strip()
            except Exception:
                banner = ""
            s.close()
            first_line = banner.split("\n")[0][:120] if banner else "(no banner)"
            sev = "CRITICAL" if service in DANGEROUS_SERVICES else "INFO"
            findings.append(f"  [OPEN][{sev}] {port}/{service}: {first_line}")
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        except Exception:
            pass
    header = "[Banner Grab — Sensitive Ports]"
    return header + "\n" + ("\n".join(findings) if findings else "  No sensitive ports open.")


def run_dns_advanced(target: str) -> str:
    """Advanced DNS: AAAA, SOA, CAA, SPF, DMARC, zone transfer attempt."""
    base = re.sub(r"^www\.", "", target).strip()
    output = []
    try:
        import dns.resolver
        import dns.zone
        import dns.query
        for qtype in ("AAAA", "SOA", "CAA"):
            try:
                answers = dns.resolver.resolve(base, qtype, lifetime=5)
                output.append(f"[{qtype}]\n" + "\n".join(str(r) for r in answers))
            except Exception:
                output.append(f"[{qtype}]\n(none)")
        try:
            answers = dns.resolver.resolve(base, "TXT", lifetime=5)
            spf = [str(r) for r in answers if "spf" in str(r).lower()]
            output.append("[SPF]\n" + ("\n".join(spf) if spf else "(MISSING — email spoofing possible)"))
        except Exception:
            output.append("[SPF]\n(query failed)")
        try:
            answers = dns.resolver.resolve(f"_dmarc.{base}", "TXT", lifetime=5)
            output.append("[DMARC]\n" + "\n".join(str(r) for r in answers))
        except Exception:
            output.append("[DMARC]\n(MISSING — email spoofing possible)")
        try:
            ns_answers = dns.resolver.resolve(base, "NS", lifetime=5)
            for ns in list(ns_answers)[:2]:
                ns_name = str(ns).rstrip(".")
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_name, base, timeout=5))
                    names = [str(n) for n in zone.nodes.keys()]
                    output.append(
                        f"[Zone Transfer via {ns_name}]\n"
                        f"  [CRITICAL] SUCCEEDED — {len(names)} records leaked: {', '.join(names[:20])}"
                    )
                except Exception:
                    output.append(f"[Zone Transfer via {ns_name}]\n  (refused — good)")
        except Exception:
            output.append("[Zone Transfer]\n(NS lookup failed)")
    except ImportError:
        output.append("[Advanced DNS]\ndnspython not available")
    return "\n\n".join(output)


def run_waf_detect(target: str) -> str:
    """Detect WAF/CDN by response headers + SQLi/XSS probe behavior."""
    ua = settings.get_user_agent()
    WAF_SIGNATURES = {
        "Cloudflare":     ["cf-ray", "cf-cache-status", "cloudflare"],
        "AWS CloudFront": ["x-amz-cf-id", "amazoncloudfront"],
        "Akamai":         ["x-akamai-transformed", "akamai"],
        "Fastly":         ["x-served-by", "fastly-restarts"],
        "Incapsula":      ["x-iinfo", "visid_incap_", "incap_ses_"],
        "F5 BIG-IP":      ["bigipserver", "f5_st"],
        "Sucuri":         ["x-sucuri-id", "sucuri"],
        "ModSecurity":    ["mod_security", "modsecurity", "naxsi"],
    }
    findings = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{target}"
        try:
            resp = requests.get(url, headers={"User-Agent": ua}, timeout=10,
                                allow_redirects=True, verify=False)
            combined = " ".join(
                f"{k.lower()}:{v.lower()}" for k, v in resp.headers.items()
            ) + " " + " ".join(resp.cookies.keys()).lower()
            detected = [w for w, sigs in WAF_SIGNATURES.items() if any(s in combined for s in sigs)]
            findings.append(
                f"[WAF/CDN Detected]: {', '.join(detected)}" if detected
                else "[WAF/CDN]: Not detected"
            )
            for probe_name, probe_suffix in [
                ("SQLi",  "/?id=1' OR '1'='1--"),
                ("XSS",   '/?q=<script>alert(1)</script>'),
            ]:
                try:
                    r2 = requests.get(url + probe_suffix, headers={"User-Agent": ua},
                                      timeout=8, verify=False, allow_redirects=False)
                    if r2.status_code in (403, 406, 429, 503):
                        findings.append(f"  [WAF ACTIVE] {probe_name} probe blocked HTTP {r2.status_code}")
                    else:
                        findings.append(f"  [NO FILTER] {probe_name} probe returned {r2.status_code}")
                except Exception:
                    pass
            break
        except Exception as e:
            findings.append(f"[{scheme.upper()}] {e}")
    return "\n".join(findings) if findings else "[WAF Detection]\n  Could not connect."


def run_cms_deep(target: str) -> str:
    """Deep CMS fingerprint: WordPress, Joomla, Drupal, Magento + generic."""
    ua = settings.get_user_agent()
    CMS_PATHS = {
        "WordPress": [
            "/wp-login.php", "/wp-admin/", "/wp-json/wp/v2/users",
            "/xmlrpc.php", "/readme.html", "/license.txt",
            "/wp-content/debug.log", "/wp-includes/version.php", "/wp-config.php.bak",
        ],
        "Joomla": [
            "/administrator/", "/configuration.php", "/README.txt",
            "/htaccess.txt", "/joomla.xml", "/language/en-GB/en-GB.xml",
        ],
        "Drupal": [
            "/user/login", "/admin/", "/CHANGELOG.txt",
            "/core/CHANGELOG.txt", "/sites/default/settings.php",
            "/modules/", "/themes/",
        ],
        "Magento": [
            "/admin/", "/downloader/", "/app/etc/local.xml", "/app/etc/config.xml",
        ],
        "Generic": [
            "/phpmyadmin/", "/adminer.php", "/elmah.axd",
            "/.DS_Store", "/WEB-INF/web.xml", "/crossdomain.xml",
        ],
    }
    HIGH = {"/wp-config.php.bak", "/app/etc/local.xml",
            "/sites/default/settings.php", "/wp-content/debug.log", "/WEB-INF/web.xml"}
    findings = []
    for scheme in ("https", "http"):
        base_url = f"{scheme}://{target}"
        try:
            requests.head(base_url, timeout=5, verify=False)
            for cms, paths in CMS_PATHS.items():
                for path in paths:
                    try:
                        r = requests.get(base_url + path, headers={"User-Agent": ua},
                                         timeout=6, verify=False, allow_redirects=False)
                        if r.status_code in (200, 301, 302, 403):
                            sev = "HIGH" if path in HIGH else "INFO"
                            findings.append(f"  [{r.status_code}][{sev}][{cms}] {path}")
                    except Exception:
                        pass
            break
        except Exception:
            continue
    header = "[CMS Deep Fingerprint]"
    return header + "\n" + ("\n".join(findings) if findings else "  No CMS-specific paths found.")


def run_js_discovery(target: str) -> str:
    """Discover JS files and scan for hardcoded secrets/API keys."""
    ua = settings.get_user_agent()
    SECRET_PATTERNS = [
        (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "API Key"),
        (r'(?i)(access[_-]?token|auth[_-]?token)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{16,})["\']', "Token"),
        (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']', "Password"),
        (r'(?i)(aws[_-]?secret|aws_access_key)\s*[=:]\s*["\']([A-Z0-9/+]{20,})["\']', "AWS Secret"),
        (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key"),
        (r'ghp_[0-9a-zA-Z]{36}', "GitHub Token"),
        (r'(?i)(sk-[A-Za-z0-9]{20,})', "OpenAI-style Key"),
        (r'(?i)(secret[_-]?key)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "Secret Key"),
    ]
    js_files: set = set()
    findings = []
    for scheme in ("https", "http"):
        base_url = f"{scheme}://{target}"
        try:
            resp = requests.get(base_url, headers={"User-Agent": ua},
                                timeout=15, verify=False, allow_redirects=True)
            for m in re.finditer(r'src=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', resp.text):
                raw = m.group(1)
                if raw.startswith("//"):
                    raw = f"https:{raw}"
                elif raw.startswith("/"):
                    raw = base_url + raw
                elif not raw.startswith("http"):
                    raw = base_url + "/" + raw
                js_files.add(raw.split("?")[0])
            break
        except Exception as e:
            findings.append(f"[Error] {e}")
    findings.append(f"[JS Discovery] {len(js_files)} script(s) found")
    secret_count = 0
    for js_url in list(js_files)[:25]:
        try:
            r = requests.get(js_url, headers={"User-Agent": ua}, timeout=10, verify=False)
            if r.status_code == 200:
                for pattern, label in SECRET_PATTERNS:
                    for hit in re.finditer(pattern, r.text):
                        secret_count += 1
                        findings.append(
                            f"  [CRITICAL/SECRET/{label}] in {js_url.split('/')[-1]}: "
                            f"{hit.group(0)[:70]}..."
                        )
        except Exception:
            pass
    if secret_count == 0:
        findings.append("  No obvious secrets found in JS files.")
    return "\n".join(findings)


def run_http_methods(target: str) -> str:
    """Enumerate allowed HTTP methods; flag dangerous ones."""
    ua = settings.get_user_agent()
    DANGEROUS = {"PUT", "DELETE", "TRACE", "CONNECT", "PROPFIND", "MOVE", "COPY"}
    findings = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{target}"
        try:
            resp = requests.options(url, headers={"User-Agent": ua},
                                    timeout=10, verify=False, allow_redirects=False)
            allow = resp.headers.get("Allow", "") or resp.headers.get("Public", "")
            methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
            if methods:
                findings.append(f"[HTTP Methods — OPTIONS]\n  Allowed: {', '.join(sorted(methods))}")
                bad = methods & DANGEROUS
                if bad:
                    findings.append(f"  [HIGH] Dangerous: {', '.join(bad)}")
                if "TRACE" in methods:
                    findings.append("  [HIGH] TRACE enabled — XST attack possible")
            else:
                findings.append("[HTTP Methods — probe (no Allow header)]")
                for method in ("GET", "POST", "PUT", "DELETE", "TRACE", "OPTIONS", "PROPFIND"):
                    try:
                        r = requests.request(method, url, headers={"User-Agent": ua},
                                             timeout=5, verify=False, allow_redirects=False)
                        if r.status_code not in (405, 501):
                            tag = " [DANGEROUS]" if method in DANGEROUS else ""
                            findings.append(f"  {method}: HTTP {r.status_code}{tag}")
                    except Exception:
                        pass
            break
        except Exception as e:
            findings.append(f"[{scheme.upper()}] {e}")
    return "\n".join(findings) if findings else "[HTTP Methods]\n  Could not connect."


def run_cert_transparency(target: str) -> str:
    """Query crt.sh certificate transparency logs for subdomain discovery."""
    base = re.sub(r"^www\.", "", target).strip()
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{base}&output=json",
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0 ARGOS/1.0"},
        )
        if resp.status_code != 200:
            return f"[Certificate Transparency]\n  crt.sh returned HTTP {resp.status_code}"
        entries = resp.json()
        domains: set = set()
        for e in entries:
            for d in e.get("name_value", "").split("\n"):
                d = d.strip().lstrip("*.")
                if base in d and len(d) < 100:
                    domains.add(d)
        sorted_d = sorted(domains)[:80]
        lines = [f"[Certificate Transparency — crt.sh — {base}]",
                 f"  {len(domains)} unique (sub)domain(s) in CT logs:"]
        lines += [f"  {d}" for d in sorted_d]
        if len(domains) > 80:
            lines.append(f"  ... and {len(domains) - 80} more")
        return "\n".join(lines)
    except requests.exceptions.ConnectionError:
        return "[Certificate Transparency]\n  crt.sh unreachable"
    except Exception as e:
        return f"[Certificate Transparency]\n  Error: {e}"


# ─────────────────────────────────────────────────────────────────
# ULTRA DEEP SCAN TOOLS
# ─────────────────────────────────────────────────────────────────

def run_deface_detect(target: str) -> str:
    """Check if site is defaced and assess 'defaceability' (write-access indicators)."""
    ua = settings.get_user_agent()
    DEFACEMENT_SIGS = [
        "hacked by", "owned by", "pwned by", "defaced by", "h4ck3d", "0wn3d",
        "this site has been hacked", "you have been hacked",
        "greetz to", "shoutout to", "hack the planet",
        "deface", "attacker", "cyber team", "ghost squad",
        "anonymous hackers", "team xp", "team h4x", "cyber army",
    ]
    DEFACEABLE_PATHS = [
        "/filemanager", "/file-manager", "/elfinder", "/fm/",
        "/webdav", "/dav/", "/webdav/",
        "/upload", "/uploads/", "/uploader",
        "/shell.php", "/c99.php", "/r57.php", "/wso.php", "/b374k.php",
        "/cmd.php", "/sh.php", "/hack.php", "/backdoor.php",
        "/admin/upload", "/admin/filemanager",
        "/.git/config", "/.git/HEAD",
    ]
    findings = []

    for scheme in ("https", "http"):
        base_url = f"{scheme}://{target}"
        try:
            resp = requests.get(base_url, headers={"User-Agent": ua},
                                timeout=15, verify=False, allow_redirects=True)
            html_lower = resp.text.lower()

            # Check for active defacement patterns
            hits = [sig for sig in DEFACEMENT_SIGS if sig in html_lower]
            if hits:
                findings.append(f"[CRITICAL] SITE MAY BE DEFACED — signatures found: {', '.join(hits[:5])}")
            else:
                findings.append("[OK] No common defacement signatures found in homepage HTML.")

            # Title check for suspicious content
            title_m = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
            if title_m:
                title = title_m.group(1).strip()[:100]
                title_lower = title.lower()
                if any(sig in title_lower for sig in ("hacked", "pwned", "owned", "defaced")):
                    findings.append(f"[CRITICAL] Suspicious page title: {title}")
                else:
                    findings.append(f"[INFO] Page title: {title}")

            # Check response size anomaly (very small page could indicate defacement)
            size = len(resp.text)
            if size < 500 and resp.status_code == 200:
                findings.append(f"[WARN] Homepage is unusually small ({size} bytes) — possible defacement or placeholder")

            break
        except Exception as e:
            findings.append(f"[Error fetching {scheme}] {e}")

    # Check defaceability indicators
    findings.append("")
    findings.append("[Defaceability Assessment]")
    for scheme in ("https", "http"):
        base_url = f"{scheme}://{target}"
        try:
            requests.head(base_url, timeout=5, verify=False)
            shell_hits = []
            for path in DEFACEABLE_PATHS:
                try:
                    r = requests.head(base_url + path, headers={"User-Agent": ua},
                                      timeout=5, verify=False, allow_redirects=False)
                    if r.status_code in (200, 403):
                        shell_hits.append(f"  [{'HIGH' if r.status_code == 200 else 'WARN'}] {path} → HTTP {r.status_code}")
                except Exception:
                    pass
            if shell_hits:
                findings.extend(shell_hits)
            else:
                findings.append("  No obvious shell/file-manager endpoints found.")

            # Check WebDAV (PUT method)
            try:
                r = requests.options(base_url, headers={"User-Agent": ua}, timeout=8,
                                     verify=False, allow_redirects=False)
                allow = r.headers.get("Allow", "") + r.headers.get("Public", "")
                if "PUT" in allow.upper():
                    findings.append("  [HIGH] HTTP PUT method allowed — write access possible (WebDAV/misconfigured server)")
                if "PROPFIND" in allow.upper() or "MKCOL" in allow.upper():
                    findings.append("  [HIGH] WebDAV methods (PROPFIND/MKCOL) allowed — file management possible")
            except Exception:
                pass

            # Check exposed .git
            try:
                r = requests.get(base_url + "/.git/HEAD", headers={"User-Agent": ua},
                                 timeout=5, verify=False, allow_redirects=False)
                if r.status_code == 200 and "ref:" in r.text:
                    findings.append("  [CRITICAL] Exposed .git/HEAD — full source code may be downloadable")
            except Exception:
                pass

            break
        except Exception:
            continue

    return "[Deface Detection]\n" + "\n".join(findings)


def run_sqli_basic(target: str) -> str:
    """Basic SQL injection probe on common GET parameters."""
    ua = settings.get_user_agent()
    PAYLOADS = ["'", "''", "' OR '1'='1", "1' OR '1'='1'--", "' OR 1=1--",
                "1; SELECT 1--", "' UNION SELECT NULL--", "admin'--"]
    ERROR_SIGS = [
        "sql syntax", "mysql_fetch", "ora-", "syntax error", "unclosed quotation",
        "sqlexception", "sqlite", "pg_query", "you have an error in your sql",
        "warning: mysql", "pdoexception", "sqlstate", "db2cli",
    ]
    findings = []

    for scheme in ("https", "http"):
        base_url = f"{scheme}://{target}"
        try:
            resp = requests.get(base_url, headers={"User-Agent": ua},
                                timeout=10, verify=False, allow_redirects=True)
            # Collect param-bearing links from homepage
            param_urls = set()
            for m in re.finditer(r'href=["\']([^"\']+\?[^"\']+)["\']', resp.text):
                raw = m.group(1)
                if not raw.startswith("http"):
                    raw = base_url + raw
                param_urls.add(raw)

            if not param_urls:
                # Try common param patterns
                for suffix in ["/?id=1", "/?page=1", "/?cat=1", "/?q=test", "/?search=test"]:
                    param_urls.add(base_url + suffix)

            findings.append(f"[SQLi Probe] {len(param_urls)} URL(s) with parameters")

            confirmed = []
            for url in list(param_urls)[:10]:
                from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                for param_name in list(params.keys())[:3]:
                    for payload in PAYLOADS[:4]:
                        test_params = dict(params)
                        test_params[param_name] = [payload]
                        new_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse(parsed._replace(query=new_query))
                        try:
                            r = requests.get(test_url, headers={"User-Agent": ua},
                                             timeout=6, verify=False, allow_redirects=False)
                            body_lower = r.text.lower()
                            if any(sig in body_lower for sig in ERROR_SIGS):
                                hit = f"  [HIGH/SQLi] {param_name}={payload!r} → SQL error in response"
                                if hit not in confirmed:
                                    confirmed.append(hit)
                        except Exception:
                            pass
            if confirmed:
                findings.extend(confirmed)
            else:
                findings.append("  No SQL error signatures triggered.")
            break
        except Exception as e:
            findings.append(f"[Error] {e}")

    return "\n".join(findings) if findings else "[SQLi Probe]\n  Could not connect."


def run_xss_basic(target: str) -> str:
    """Basic reflected XSS probe on common GET parameters."""
    ua = settings.get_user_agent()
    PROBE = "<argos-xss-test>"
    findings = []

    for scheme in ("https", "http"):
        base_url = f"{scheme}://{target}"
        try:
            resp = requests.get(base_url, headers={"User-Agent": ua},
                                timeout=10, verify=False, allow_redirects=True)
            param_urls = set()
            for m in re.finditer(r'href=["\']([^"\']+\?[^"\']+)["\']', resp.text):
                raw = m.group(1)
                if not raw.startswith("http"):
                    raw = base_url + raw
                param_urls.add(raw)
            for suffix in ["/?q=test", "/?search=test", "/?name=test", "/?msg=test"]:
                param_urls.add(base_url + suffix)

            findings.append(f"[XSS Probe] {len(param_urls)} URL(s) tested")
            confirmed = []
            for url in list(param_urls)[:8]:
                from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                for param_name in list(params.keys())[:3]:
                    test_params = dict(params)
                    test_params[param_name] = [PROBE]
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                    try:
                        r = requests.get(test_url, headers={"User-Agent": ua},
                                         timeout=6, verify=False, allow_redirects=False)
                        if PROBE in r.text:
                            confirmed.append(f"  [HIGH/XSS] Reflected in {param_name} at {url.split('?')[0]}")
                    except Exception:
                        pass
            if confirmed:
                findings.extend(confirmed)
            else:
                findings.append("  No unescaped reflection detected.")
            break
        except Exception as e:
            findings.append(f"[Error] {e}")

    return "\n".join(findings) if findings else "[XSS Probe]\n  Could not connect."


def run_cors_advanced(target: str) -> str:
    """Test CORS policy for dangerous misconfigurations."""
    ua = settings.get_user_agent()
    ORIGINS_TO_TEST = [
        f"https://evil-{target}.com",
        "https://attacker.com",
        "null",
        f"https://{target}.evil.com",
        "https://localhost",
    ]
    findings = []

    for scheme in ("https", "http"):
        url = f"{scheme}://{target}"
        try:
            requests.head(url, timeout=5, verify=False)
            for origin in ORIGINS_TO_TEST:
                try:
                    r = requests.get(url, headers={"User-Agent": ua, "Origin": origin},
                                     timeout=8, verify=False, allow_redirects=True)
                    acao = r.headers.get("Access-Control-Allow-Origin", "")
                    acac = r.headers.get("Access-Control-Allow-Credentials", "")
                    if acao == origin:
                        sev = "CRITICAL" if acac.lower() == "true" else "HIGH"
                        findings.append(
                            f"  [{sev}] Origin '{origin}' reflected in ACAO"
                            + (" + credentials allowed!" if acac.lower() == "true" else "")
                        )
                    elif acao == "*":
                        findings.append(f"  [HIGH] Wildcard ACAO (*) — any origin allowed")
                    elif acao == "null":
                        findings.append(f"  [HIGH] ACAO: null — sandbox iframe bypass possible")
                except Exception:
                    pass
            if not findings:
                findings.append("  No dangerous CORS configuration detected.")
            break
        except Exception as e:
            findings.append(f"[Error] {e}")

    return "[CORS Advanced Check]\n" + "\n".join(findings)


def run_clickjacking_test(target: str) -> str:
    """Test for clickjacking — X-Frame-Options and CSP frame-ancestors."""
    ua = settings.get_user_agent()
    findings = []

    for scheme in ("https", "http"):
        url = f"{scheme}://{target}"
        try:
            r = requests.get(url, headers={"User-Agent": ua},
                             timeout=10, verify=False, allow_redirects=True)
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            xfo = hdrs.get("x-frame-options", "")
            csp = hdrs.get("content-security-policy", "")

            if xfo:
                val = xfo.upper()
                if val in ("DENY", "SAMEORIGIN"):
                    findings.append(f"  [OK] X-Frame-Options: {xfo}")
                else:
                    findings.append(f"  [WARN] X-Frame-Options: {xfo} — non-standard value")
            else:
                findings.append("  [MISSING] X-Frame-Options not set")

            if "frame-ancestors" in csp.lower():
                fa = re.search(r"frame-ancestors\s+([^;]+)", csp, re.IGNORECASE)
                val = fa.group(1).strip() if fa else csp
                if "'none'" in val.lower():
                    findings.append(f"  [OK] CSP frame-ancestors: 'none'")
                elif "'self'" in val.lower():
                    findings.append(f"  [OK] CSP frame-ancestors: 'self'")
                else:
                    findings.append(f"  [WARN] CSP frame-ancestors: {val[:80]}")
            else:
                findings.append("  [MISSING] CSP frame-ancestors directive not set")

            if not xfo and "frame-ancestors" not in csp.lower():
                findings.append("  [HIGH] No framing protection — clickjacking likely possible")
                findings.append("  [FIX] Add: X-Frame-Options: DENY")
            break
        except Exception as e:
            findings.append(f"[Error] {e}")

    return "[Clickjacking Test]\n" + "\n".join(findings)


def run_open_redirect(target: str) -> str:
    """Probe for open redirect vulnerabilities in common parameters."""
    ua = settings.get_user_agent()
    REDIRECT_PARAMS = ["url", "redirect", "redirect_to", "redirect_url", "return",
                       "return_url", "returnTo", "next", "goto", "destination",
                       "dest", "continue", "forward", "location", "callback"]
    PAYLOAD = "https://evil.com"
    findings = []

    for scheme in ("https", "http"):
        base_url = f"{scheme}://{target}"
        try:
            requests.head(base_url, timeout=5, verify=False)
            hits = []
            for param in REDIRECT_PARAMS:
                test_url = f"{base_url}/?{param}={PAYLOAD}"
                try:
                    r = requests.get(test_url, headers={"User-Agent": ua},
                                     timeout=6, verify=False, allow_redirects=False)
                    if r.status_code in (301, 302, 303, 307, 308):
                        loc = r.headers.get("Location", "")
                        if PAYLOAD in loc or "evil.com" in loc:
                            hits.append(f"  [HIGH] Open redirect via ?{param}= → Location: {loc[:80]}")
                except Exception:
                    pass
            if hits:
                findings.extend(hits)
            else:
                findings.append("  No open redirect detected on common parameters.")
            break
        except Exception as e:
            findings.append(f"[Error] {e}")

    return "[Open Redirect Test]\n" + "\n".join(findings)


def run_info_disclosure(target: str) -> str:
    """Check for sensitive information disclosure in page source and error pages."""
    ua = settings.get_user_agent()
    SENSITIVE_PATTERNS = [
        (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{3,}["\']', "Password in HTML"),
        (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\'][A-Za-z0-9_\-]{16,}["\']', "API key in HTML"),
        (r'[A-Za-z0-9+/]{40,}={0,2}', "Base64-encoded data (possible secrets)"),
        (r'(?i)(internal|private|secret|confidential)\s+ip\s*[:\-=]?\s*(\d{1,3}\.){3}\d{1,3}', "Internal IP"),
        (r'(\d{1,3}\.){3}\d{1,3}', "IP address in page source"),
        (r'(?i)(stack trace|at [a-z]+\.[a-z]+\.)', "Stack trace exposure"),
        (r'(?i)(exception|fatal error|warning:|notice:)\s+in\s+[/\\]', "Error/exception disclosure"),
        (r'(?i)<!-- .{10,100} -->', "HTML comments (possible info)"),
        (r'(?i)(debug|todo|fixme|hack|xxx|password|secret)\s*[:=]', "Debug comment/todo"),
    ]
    findings = []
    # Check for error page disclosure
    ERROR_PATHS = ["/nonexistent-page-argos-test", "/../../../etc/passwd",
                   "/index.php?id=", "/index.asp?id="]

    for scheme in ("https", "http"):
        base_url = f"{scheme}://{target}"
        try:
            resp = requests.get(base_url, headers={"User-Agent": ua},
                                timeout=15, verify=False, allow_redirects=True)
            findings.append(f"[Info Disclosure — {scheme.upper()} {resp.status_code}]")
            hit_count = 0
            for pattern, label in SENSITIVE_PATTERNS:
                matches = re.findall(pattern, resp.text)
                if matches:
                    sample = str(matches[0])[:60] if matches else ""
                    # Skip noisy IP pattern if too many matches
                    if label == "IP address in page source" and len(matches) > 5:
                        findings.append(f"  [INFO] {label}: {len(matches)} occurrences")
                    elif label != "Base64-encoded data (possible secrets)":
                        findings.append(f"  [WARN] {label}: {sample}")
                    hit_count += 1
            if hit_count == 0:
                findings.append("  No obvious sensitive data patterns in homepage.")

            # Probe 404 error page for server info
            try:
                r404 = requests.get(base_url + ERROR_PATHS[0], headers={"User-Agent": ua},
                                    timeout=6, verify=False)
                body_lower = r404.text.lower()
                if "apache" in body_lower or "nginx" in body_lower or "iis" in body_lower:
                    findings.append("  [MEDIUM] Server software version exposed in error page")
                if "stack trace" in body_lower or "at line" in body_lower:
                    findings.append("  [HIGH] Stack trace exposed in 404 error page")
                srv = r404.headers.get("Server", "")
                if srv:
                    findings.append(f"  [INFO] Server header on 404: {srv}")
            except Exception:
                pass

            break
        except Exception as e:
            findings.append(f"[Error] {e}")

    return "\n".join(findings) if findings else "[Info Disclosure]\n  Could not connect."


def run_path_traversal(target: str) -> str:
    """Test for path traversal / LFI vulnerabilities."""
    ua = settings.get_user_agent()
    PAYLOADS = [
        "/../../../etc/passwd", "/..%2F..%2F..%2Fetc%2Fpasswd",
        "/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/../../../windows/system32/drivers/etc/hosts",
        "/%5C..%5C..%5Cwindows%5Csystem32%5Cdrivers%5Cetc%5Chosts",
    ]
    LFI_PARAMS = ["file", "page", "include", "path", "template", "doc", "document",
                  "load", "read", "cat", "action", "dir"]
    UNIX_INDICATOR = "root:x:0:0:"
    WIN_INDICATOR = "localhost"
    findings = []

    for scheme in ("https", "http"):
        base_url = f"{scheme}://{target}"
        try:
            requests.head(base_url, timeout=5, verify=False)
            hits = []
            # Path traversal in URL
            for payload in PAYLOADS[:3]:
                try:
                    r = requests.get(base_url + payload, headers={"User-Agent": ua},
                                     timeout=6, verify=False, allow_redirects=False)
                    if UNIX_INDICATOR in r.text or WIN_INDICATOR in r.text:
                        hits.append(f"  [CRITICAL] Path traversal via URL: {payload}")
                except Exception:
                    pass
            # LFI via GET params
            for param in LFI_PARAMS[:6]:
                for payload in PAYLOADS[:2]:
                    test_url = f"{base_url}/?{param}={payload}"
                    try:
                        r = requests.get(test_url, headers={"User-Agent": ua},
                                         timeout=5, verify=False, allow_redirects=False)
                        if UNIX_INDICATOR in r.text or WIN_INDICATOR in r.text:
                            hits.append(f"  [CRITICAL] LFI via ?{param}= with payload {payload}")
                    except Exception:
                        pass
            if hits:
                findings.extend(hits)
            else:
                findings.append("  No path traversal / LFI detected.")
            break
        except Exception as e:
            findings.append(f"[Error] {e}")

    return "[Path Traversal / LFI Test]\n" + "\n".join(findings)


def run_nmap_ultra(target: str) -> str:
    """Ultra-aggressive nmap: all ports, OS detection, vulnerability scripts."""
    domain = target.split(":")[0]
    if _tool_available("nmap"):
        result = run_tool(
            ["nmap", "-p-", "-T4", "-A", "--open",
             "--script=vuln,auth,default,banner,http-title,ssl-heartbleed,ssl-poodle",
             "-oN", "-", domain],
            timeout=600,
        )
        if "[!] Tool not found" not in result:
            return f"[Ultra Nmap — All Ports + Vuln Scripts]\n{result}"
    return "[Ultra Nmap]\n  nmap not available — skipped."


TOOLS_MENU = {
    "1": ("nmap",         run_nmap),
    "2": ("whois",        run_whois),
    "3": ("whatweb",      run_whatweb),
    "4": ("http headers", run_curl_headers),
    "5": ("dig DNS",      run_dig),
    "6": ("nikto",        run_nikto),
}

ALLOWED_TOOLS = {"nmap", "whois", "whatweb", "curl", "dig", "nikto"}

STANDARD_TOOL_NAMES = ["nmap", "whois", "whatweb", "curl_headers", "dig"]
DEEP_TOOL_NAMES = STANDARD_TOOL_NAMES + [
    "nmap_deep", "sec_headers", "ssl_check", "subdomains", "dir_enum",
    "nikto", "banner_grab", "dns_advanced", "waf_detect", "cms_deep",
    "js_discovery", "http_methods", "cert_transparency",
]
ULTRA_TOOL_NAMES = DEEP_TOOL_NAMES + [
    "nmap_ultra", "deface_detect", "sqli_basic", "xss_basic",
    "cors_advanced", "clickjacking", "open_redirect",
    "info_disclosure", "path_traversal",
]


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# PARALLEL RUNNER
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _run_parallel(tasks: dict, max_workers: int = 5, on_done=None) -> dict:
    """Run {name: callable} in parallel. Calls on_done(name) after each finishes."""
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(fn): name for name, fn in tasks.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception as e:
                results[name] = f"[!] Error in {name}: {e}"
            if on_done:
                on_done(name)
    return results


def run_default_recon(target: str, on_done=None) -> dict:
    tasks = {
        "nmap":         lambda: run_nmap(target),
        "whois":        lambda: run_whois(target),
        "whatweb":      lambda: run_whatweb(target),
        "curl_headers": lambda: run_curl_headers(target),
        "dig":          lambda: run_dig(target),
    }
    return _run_parallel(tasks, max_workers=5, on_done=on_done)


def run_deep_recon(target: str, on_done=None) -> dict:
    # Phase 1: standard tools
    results = run_default_recon(target, on_done=on_done)
    # Phase 2: all deep tools in parallel
    deep_tasks = {
        "nmap_deep":         lambda: run_nmap_deep(target),
        "sec_headers":       lambda: run_security_headers(target),
        "ssl_check":         lambda: run_ssl_check(target),
        "subdomains":        lambda: run_subdomain_enum(target),
        "dir_enum":          lambda: run_dir_enum(target),
        "nikto":             lambda: run_nikto(target),
        "banner_grab":       lambda: run_banner_grab(target),
        "dns_advanced":      lambda: run_dns_advanced(target),
        "waf_detect":        lambda: run_waf_detect(target),
        "cms_deep":          lambda: run_cms_deep(target),
        "js_discovery":      lambda: run_js_discovery(target),
        "http_methods":      lambda: run_http_methods(target),
        "cert_transparency": lambda: run_cert_transparency(target),
    }
    results.update(_run_parallel(deep_tasks, max_workers=13, on_done=on_done))
    return results


def run_ultra_recon(target: str, on_done=None) -> dict:
    # Phase 1+2: everything from deep scan
    results = run_deep_recon(target, on_done=on_done)
    # Phase 3: ultra-aggressive tools in parallel
    ultra_tasks = {
        "nmap_ultra":       lambda: run_nmap_ultra(target),
        "deface_detect":    lambda: run_deface_detect(target),
        "sqli_basic":       lambda: run_sqli_basic(target),
        "xss_basic":        lambda: run_xss_basic(target),
        "cors_advanced":    lambda: run_cors_advanced(target),
        "clickjacking":     lambda: run_clickjacking_test(target),
        "open_redirect":    lambda: run_open_redirect(target),
        "info_disclosure":  lambda: run_info_disclosure(target),
        "path_traversal":   lambda: run_path_traversal(target),
    }
    results.update(_run_parallel(ultra_tasks, max_workers=9, on_done=on_done))
    return results


def format_recon_for_llm(results: dict) -> str:
    output = ""
    for tool, data in results.items():
        output += f"\n{'='*50}\n[ {tool.upper()} ]\n{'='*50}\n"
        output += (data or "").strip() + "\n"
    return output


def _exec_curl_as_requests(payload: str, target: str) -> str:
    """Convert a curl command string to a requests call and return the response."""
    import shlex
    try:
        args = shlex.split(payload)
    except Exception as e:
        return f"[!] Could not parse curl command: {e}"

    method = "GET"
    url = None
    headers = {}
    data = None
    idx = 0
    while idx < len(args):
        a = args[idx]
        if a in ("-X", "--request") and idx + 1 < len(args):
            method = args[idx + 1].upper(); idx += 2
        elif a in ("-H", "--header") and idx + 1 < len(args):
            k, _, v = args[idx + 1].partition(":")
            headers[k.strip()] = v.strip(); idx += 2
        elif a in ("-d", "--data", "--data-binary") and idx + 1 < len(args):
            data = args[idx + 1]; idx += 2
        elif not a.startswith("-") and ("http://" in a or "https://" in a):
            url = a; idx += 1
        else:
            idx += 1

    if not url:
        return "[!] No URL found in curl command."

    try:
        ua = settings.get_user_agent()
        headers.setdefault("User-Agent", ua)
        resp = requests.request(method, url, headers=headers, data=data,
                                timeout=30, verify=False, allow_redirects=True)
        lines = [f"[curl → requests]  HTTP {resp.status_code} {resp.reason}"]
        for k, v in list(resp.headers.items())[:12]:
            lines.append(f"  {k}: {v}")
        lines.append(f"\n[Response body — {len(resp.text)} chars]")
        lines.append(resp.text[:3000])
        if len(resp.text) > 3000:
            lines.append(f"  … [{len(resp.text) - 3000} chars truncated]")
        return "\n".join(lines)
    except Exception as e:
        return f"[!] Request failed: {e}"


EXEC_TOOL_ALLOWLIST = {
    "nmap", "sqlmap", "nikto", "dirb", "gobuster", "wfuzz",
    "hydra", "curl", "whatweb", "ffuf", "nuclei",
}


def run_suggested_exploit(exploit: dict, target: str) -> str:
    """
    Safely execute an LLM-suggested exploit.
    exploit keys: exploit_name, tool_used, payload, notes
    Returns output string.
    """
    import shlex

    tool    = (exploit.get("tool_used") or "").lower().strip()
    payload = (exploit.get("payload") or "").strip()

    if not tool:
        return "[!] No tool specified in exploit."
    if tool not in EXEC_TOOL_ALLOWLIST:
        return (f"[!] Tool '{tool}' not in execution allowlist.\n"
                f"    Allowed: {', '.join(sorted(EXEC_TOOL_ALLOWLIST))}")
    if not payload:
        return "[!] No payload/command specified."

    # Substitute common target placeholders
    for placeholder in ["{target}", "TARGET", "<TARGET>", "target.com",
                         "example.com", "DOMAIN", "<domain>", "<host>"]:
        payload = payload.replace(placeholder, target)

    if tool == "curl":
        return _exec_curl_as_requests(payload, target)

    try:
        args = shlex.split(payload)
    except Exception as e:
        return f"[!] Could not parse command: {e}"

    # Ensure the tool is the first element
    first = args[0].lower().split("/")[-1].split("\\")[-1] if args else ""
    if first != tool:
        args = [tool] + args

    return run_tool(args, timeout=300)


def run_tool_by_command(command_str: str) -> str:
    parts = command_str.strip().split()
    if not parts:
        return "[!] Empty command."
    tool = parts[0].lower().split("/")[-1].split("\\")[-1]
    if tool not in ALLOWED_TOOLS:
        return f"[!] Tool '{parts[0]}' not permitted. Allowed: {ALLOWED_TOOLS}"
    return run_tool(parts)

