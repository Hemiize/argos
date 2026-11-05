#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARGOS — LLM bridge.
Supports llama.cpp (OpenAI-compatible) and Ollama.
Streaming mode with live token/s counter.
"""

import os
import json
import time
import subprocess
import requests
import settings
from config import LLM_TIMEOUT

# ─────────────────────────────────────────────────────────────────────────────
# SYSTEM PROMPTS
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are ARGOS — an expert offensive and defensive web security analyst.
Your task: analyse raw recon data from automated tools and produce a structured JSON report.

## Analysis Layers
Examine findings across five layers:
1. INFRASTRUCTURE  — hosting, IPs, CDN, DNS, open ports, server software versions
2. CONFIGURATION   — TLS/SSL quality, security headers, cookie flags, CORS policy
3. APPLICATION     — tech stack, CMS/framework vulns, exposed admin interfaces, information disclosure
4. NETWORK         — firewall posture, exposed services, dangerous open ports
5. RISK AGGREGATION — combine all findings into a single risk verdict

## Output Rules
- Respond ONLY with valid JSON — no markdown fences, no prose before or after
- JSON schema (strict):

{
  "risk_level": "<CRITICAL|HIGH|MEDIUM|LOW>",
  "summary": "<2-4 sentence executive summary>",
  "vulnerabilities": [
    {
      "vuln_name":   "<short descriptive name>",
      "severity":    "<critical|high|medium|low|info>",
      "port":        "<port or '-'>",
      "service":     "<service name or '-'>",
      "description": "<1-3 sentences: what it is and why it matters>",
      "fix":         "<concrete remediation step>"
    }
  ],
  "exploits": [
    {
      "exploit_name": "<name>",
      "tool_used":    "<tool>",
      "payload":      "<example command or payload>",
      "result":       "suggested",
      "notes":        "<context or preconditions>"
    }
  ]
}

## Severity Guidelines
- critical : RCE, pre-auth SQLi, full data exposure, default admin credentials
- high     : XSS (stored), SSRF, auth bypass, unpatched critical CVE, weak TLS
- medium   : reflected XSS, missing HSTS/CSP, info disclosure, outdated software
- low      : missing minor headers, verbose errors, weak cipher suites
- info     : exposed but not exploitable

## Exploit Suggestions
- Only include exploits the data strongly supports
- Include PoC commands or payloads where helpful
- Use tool names: nmap, sqlmap, hydra, nikto, curl, metasploit, dirb, wfuzz

## Quality Rules
- Be specific: reference actual ports, software versions, header names from the scan data
- Do not hallucinate CVEs — only cite CVEs visible in the scan data or CVE enrichment block
- If scan data is too sparse for a finding, omit it rather than guess
- risk_level must reflect the worst confirmed vulnerability
"""

CHAT_SYSTEM_PROMPT = """You are ARGOS — a web security analyst in an interactive follow-up chat session.
You have already analysed a target. The full scan data and your initial report are in the conversation history.

Guidelines:
- Answer follow-up questions concisely and specifically
- Reference exact ports, services, and CVEs from the scan data
- Provide real PoC commands and payloads when asked
- Use markdown code blocks for commands (```bash ... ```)
- If you need more context, say so
- Respond in plain text with optional markdown — NOT in JSON
"""


# ─────────────────────────────────────────────────────────────────────────────
# HTTP CALLERS — NON-STREAMING (fallback)
# ─────────────────────────────────────────────────────────────────────────────

def _call_llamacpp_plain(messages: list, cfg: dict) -> str:
    payload = {
        "model": cfg["model"], "messages": messages,
        "stream": False, "temperature": 0.3,
        "top_p": 0.9, "max_tokens": 4096,
    }
    resp = requests.post(cfg["chat_url"], json=payload, timeout=LLM_TIMEOUT)
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"].strip()


def _call_ollama_plain(messages: list, cfg: dict) -> str:
    payload = {
        "model": cfg["model"], "messages": messages,
        "stream": False,
        "options": {"temperature": 0.3, "top_p": 0.9, "num_predict": 4096},
    }
    resp = requests.post(cfg["chat_url"], json=payload, timeout=LLM_TIMEOUT)
    resp.raise_for_status()
    return resp.json()["message"]["content"].strip()


# ─────────────────────────────────────────────────────────────────────────────
# HTTP CALLERS — STREAMING
# ─────────────────────────────────────────────────────────────────────────────

def _stream_llamacpp(messages: list, cfg: dict, writer=None) -> str:
    """Stream llama.cpp (OpenAI SSE). Calls writer(token, stats) for each chunk."""
    payload = {
        "model": cfg["model"], "messages": messages,
        "stream": True, "temperature": 0.3,
        "top_p": 0.9, "max_tokens": 4096,
    }
    full_text = ""
    token_count = 0
    start_time = time.monotonic()

    with requests.post(cfg["chat_url"], json=payload, timeout=LLM_TIMEOUT, stream=True) as resp:
        resp.raise_for_status()
        for line in resp.iter_lines():
            if not line:
                continue
            line_str = line.decode("utf-8") if isinstance(line, bytes) else line
            if line_str.startswith("data: "):
                data_str = line_str[6:].strip()
                if data_str == "[DONE]":
                    break
                try:
                    chunk = json.loads(data_str)
                    delta = chunk.get("choices", [{}])[0].get("delta", {})
                    token = delta.get("content", "")
                    if token:
                        full_text += token
                        token_count += 1
                        elapsed = time.monotonic() - start_time
                        tps = token_count / elapsed if elapsed > 0.1 else None
                        if writer:
                            writer(token, {"tokens": token_count, "tokens_per_sec": tps})
                except (json.JSONDecodeError, KeyError):
                    pass
    return full_text


def _stream_ollama(messages: list, cfg: dict, writer=None) -> str:
    """Stream Ollama NDJSON. Calls writer(token, stats) for each chunk."""
    payload = {
        "model": cfg["model"], "messages": messages,
        "stream": True,
        "options": {"temperature": 0.3, "top_p": 0.9, "num_predict": 4096},
    }
    full_text = ""
    token_count = 0
    start_time = time.monotonic()

    with requests.post(cfg["chat_url"], json=payload, timeout=LLM_TIMEOUT, stream=True) as resp:
        resp.raise_for_status()
        for line in resp.iter_lines():
            if not line:
                continue
            line_str = line.decode("utf-8") if isinstance(line, bytes) else line
            try:
                chunk = json.loads(line_str)
                token = chunk.get("message", {}).get("content", "")
                if token:
                    full_text += token
                    token_count += 1
                    elapsed = time.monotonic() - start_time
                    tps = token_count / elapsed if elapsed > 0.1 else None
                    if writer:
                        writer(token, {"tokens": token_count, "tokens_per_sec": tps})
                if chunk.get("done"):
                    break
            except (json.JSONDecodeError, KeyError):
                pass
    return full_text


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────────────────────────────────────

def ask_llm(messages: list, writer=None) -> str:
    """
    Send messages to the active backend and return the assistant reply.
    If writer is provided, stream tokens to it: writer(token, {"tokens": N, "tokens_per_sec": float}).
    """
    cfg = settings.get_backend_config()
    try:
        if writer is not None:
            if cfg["type"] == "llamacpp":
                return _stream_llamacpp(messages, cfg, writer)
            else:
                return _stream_ollama(messages, cfg, writer)
        else:
            if cfg["type"] == "llamacpp":
                return _call_llamacpp_plain(messages, cfg)
            else:
                return _call_ollama_plain(messages, cfg)
    except Exception as e:
        # Streaming may fail on some builds — fall back to non-streaming
        if writer is not None:
            try:
                if cfg["type"] == "llamacpp":
                    result = _call_llamacpp_plain(messages, cfg)
                else:
                    result = _call_ollama_plain(messages, cfg)
                # Deliver the whole text as one "chunk"
                writer(result, {"tokens": len(result.split()), "tokens_per_sec": None})
                return result
            except Exception as e2:
                raise RuntimeError(f"LLM error: {e2}") from e2
        raise RuntimeError(f"LLM error: {e}") from e


def analyse_target(target: str, raw_scan: str) -> dict:
    """
    Send scan data to the LLM and return parsed result dict.
    Keys: risk_level, summary, vulnerabilities, exploits, raw_scan, full_response, cve_context.
    Shows live streaming display during analysis.
    """
    # CVE enrichment from nmap section of scan data
    cve_context = ""
    try:
        import cve as cve_mod
        cve_context = cve_mod.enrich_with_cves(raw_scan)
    except Exception:
        pass

    user_msg = f"TARGET: {target}\n\nRAW SCAN DATA:\n{raw_scan}"
    if cve_context:
        user_msg += f"\n\n{cve_context}"
    user_msg += "\n\nAnalyse the scan data and respond with a JSON report following the schema exactly."

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": user_msg},
    ]

    cfg = settings.get_backend_config()
    full_response = ""

    import ui as _ui
    from rich.live import Live
    from rich.text import Text

    stats = {"tokens": 0, "tps": None}
    _last_ui_update = [0.0]

    def _writer(token, s):
        stats["tokens"] = s.get("tokens", 0) or stats["tokens"] + 1
        stats["tps"]    = s.get("tokens_per_sec")
        now = time.monotonic()
        if now - _last_ui_update[0] >= 0.15:
            _last_ui_update[0] = now
            tps_str = f"{stats['tps']:.1f} t/s" if stats["tps"] else "starting…"
            _live_ref[0].update(
                Text(
                    f"  [{cfg['label']}]  {stats['tokens']} tokens  ·  {tps_str}",
                    style="dim cyan",
                )
            )

    _live_ref = [None]
    with Live(
        Text(f"  [{cfg['label']}]  0 tokens  ·  starting…", style="dim cyan"),
        console=_ui.console,
        refresh_per_second=8,
        transient=False,
    ) as live:
        _live_ref[0] = live
        full_response = ask_llm(messages, writer=_writer)

    tps_final = f"{stats['tps']:.1f} t/s" if stats["tps"] else "—"
    _ui.console.print(f"  [dim cyan]⚡  {stats['tokens']} tokens  ·  {tps_final}[/]")

    clean_response, thinking_text = strip_thinking(full_response)
    show_think = settings.load().get("show_thinking", False)
    if thinking_text and show_think:
        _ui.console.print()
        from rich.panel import Panel
        _ui.console.print(Panel(
            f"[dim]{thinking_text[:4000]}[/]",
            title="[bold dim] Reasoning / Thinking [/]",
            border_style="dim",
            padding=(0, 2),
        ))

    parsed = _parse_response(clean_response or full_response)
    parsed["raw_scan"]      = raw_scan
    parsed["full_response"] = clean_response or full_response
    parsed["cve_context"]   = cve_context
    return parsed


def build_chat_history(target: str, raw_scan: str, result: dict) -> list:
    """Build the initial message history for follow-up chat from a completed scan."""
    vulns = result.get("vulnerabilities", [])
    vuln_list = "\n".join(
        f"- [{v.get('severity','?').upper()}] {v.get('vuln_name','?')}"
        for v in vulns
    )
    assistant_summary = (
        f"I have completed the security analysis of **{target}**.\n\n"
        f"**Risk Level:** {result.get('risk_level','UNKNOWN')}\n\n"
        f"**Summary:** {result.get('summary','')}\n\n"
        f"**Vulnerabilities ({len(vulns)}):**\n{vuln_list or '(none)'}"
    )
    return [
        {"role": "system",    "content": CHAT_SYSTEM_PROMPT},
        {"role": "user",      "content": f"TARGET: {target}\n\nSCAN DATA:\n{raw_scan}"},
        {"role": "assistant", "content": assistant_summary},
    ]


def chat_reply(question: str, history: list) -> tuple:
    """
    Send a follow-up question and return (reply_text, updated_history).
    Uses streaming with live display.
    """
    history = list(history) + [{"role": "user", "content": question}]
    cfg     = settings.get_backend_config()
    reply   = ""

    import ui as _ui
    from rich.live import Live
    from rich.text import Text

    stats = {"tokens": 0, "tps": None}
    _last_ui_update = [0.0]

    def _writer(token, s):
        stats["tokens"] = s.get("tokens", 0) or stats["tokens"] + 1
        stats["tps"]    = s.get("tokens_per_sec")
        now = time.monotonic()
        if now - _last_ui_update[0] >= 0.15:
            _last_ui_update[0] = now
            tps_str = f"{stats['tps']:.1f} t/s" if stats["tps"] else "starting…"
            _live_ref[0].update(
                Text(
                    f"  [{cfg['label']}]  {stats['tokens']} tokens  ·  {tps_str}",
                    style="dim cyan",
                )
            )

    _live_ref = [None]
    with Live(
        Text(f"  [{cfg['label']}]  0 tokens  ·  starting…", style="dim cyan"),
        console=_ui.console,
        refresh_per_second=8,
        transient=False,
    ) as live:
        _live_ref[0] = live
        reply = ask_llm(history, writer=_writer)

    tps_final = f"{stats['tps']:.1f} t/s" if stats["tps"] else "—"
    _ui.console.print(f"  [dim cyan]⚡  {stats['tokens']} tokens  ·  {tps_final}[/]")

    clean_reply, thinking_text = strip_thinking(reply)
    show_think = settings.load().get("show_thinking", False)
    if thinking_text and show_think:
        _ui.console.print()
        from rich.panel import Panel
        _ui.console.print(Panel(
            f"[dim]{thinking_text[:4000]}[/]",
            title="[bold dim] Reasoning / Thinking [/]",
            border_style="dim",
            padding=(0, 2),
        ))
    reply = clean_reply or reply
    history = history + [{"role": "assistant", "content": reply}]
    return reply, history


def strip_thinking(text: str) -> tuple:
    """
    Split out <think>…</think> blocks.
    Returns (clean_text, thinking_text).
    If show_thinking is off, thinking_text is returned only for internal use.
    """
    import re
    parts = re.findall(r'<think>(.*?)</think>', text, re.DOTALL)
    clean = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL).strip()
    return clean, "\n\n".join(parts).strip()


def _parse_response(text: str) -> dict:
    """Extract and parse the JSON block from the LLM response."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        inner = lines[1:-1] if lines and lines[-1].strip() == "```" else lines[1:]
        cleaned = "\n".join(inner).strip()

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        import re
        m = re.search(r"\{[\s\S]+\}", cleaned)
        if m:
            try:
                data = json.loads(m.group(0))
            except json.JSONDecodeError:
                data = {}
        else:
            data = {}

    return {
        "risk_level":      data.get("risk_level", "UNKNOWN").upper(),
        "summary":         data.get("summary", ""),
        "vulnerabilities": data.get("vulnerabilities", []),
        "exploits":        data.get("exploits", []),
    }


def check_llm_online() -> bool:
    """Return True if the active backend responds. Never raises."""
    try:
        health_url = settings.get_backend_health_url()
        resp = requests.get(health_url, timeout=4)
        return resp.status_code < 500
    except KeyboardInterrupt:
        raise
    except Exception:
        pass
    try:
        cfg = settings.get_backend_config()
        if cfg["type"] == "llamacpp":
            requests.post(
                cfg["chat_url"],
                json={"model": cfg["model"], "messages": [], "max_tokens": 1},
                timeout=4,
            )
        else:
            requests.post(
                cfg["chat_url"],
                json={"model": cfg["model"], "messages": [], "stream": False},
                timeout=4,
            )
        return True
    except KeyboardInterrupt:
        raise
    except Exception:
        return False

# ─────────────────────────────────────────────────────────────────────────────
# EXPLOIT RESULT ANALYSER
# ─────────────────────────────────────────────────────────────────────────────

_EXPLOIT_ANALYSIS_PROMPT = """Analyze the output of a security exploit/probe attempt and determine whether it succeeded.

Exploit name : {exploit_name}
Tool used    : {tool_used}
Payload      : {payload}
Raw output   :
{output}

Reply with ONLY a valid JSON object (no markdown fences, no extra text):
{{
  "success": true,
  "verdict": "one-line summary",
  "evidence": "most relevant line(s) from the output",
  "severity": "critical",
  "recommendation": "what this means / next step"
}}

Rules:
- success: true = vulnerability confirmed, false = blocked / not vulnerable, "partial" = ambiguous
- severity: one of critical / high / medium / low / info
- verdict and recommendation each under 120 characters
"""


def analyze_exploit_result(exploit: dict, raw_output: str) -> dict:
    """
    Ask the active LLM to interpret exploit output.
    Returns dict with keys: success, verdict, evidence, severity, recommendation.
    Returns {} on failure (LLM offline or parse error).
    """
    prompt = _EXPLOIT_ANALYSIS_PROMPT.format(
        exploit_name=exploit.get("exploit_name", "unknown"),
        tool_used=exploit.get("tool_used", "unknown"),
        payload=(exploit.get("payload") or "")[:300],
        output=raw_output[:3000],
    )
    messages = [
        {"role": "system",
         "content": "You are a security analyst. Output ONLY valid JSON, nothing else."},
        {"role": "user", "content": prompt},
    ]
    try:
        raw = ask_llm(messages)
        raw = raw.strip()
        # Strip optional markdown fences
        if raw.startswith("```"):
            lines = raw.splitlines()
            raw = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:]).strip()
        data = json.loads(raw)
        return {
            "success":        data.get("success", False),
            "verdict":        str(data.get("verdict", ""))[:200],
            "evidence":       str(data.get("evidence", ""))[:400],
            "severity":       str(data.get("severity", "info")).lower(),
            "recommendation": str(data.get("recommendation", ""))[:200],
        }
    except Exception:
        return {}



# ─────────────────────────────────────────────────────────────────────────────
# PAYLOAD / TEMPLATE / WORDLIST GENERATION  (local LLM, authorized testing)
# ─────────────────────────────────────────────────────────────────────────────

_GEN_SYSTEM = (
    "You are an offensive-security assistant helping a professional on an AUTHORIZED "
    "penetration test of their own system. Produce the requested artifact directly, "
    "with no disclaimers and no commentary unless asked. Output only the artifact."
)

_GEN_GUIDES = {
    "nuclei":   ("Write ONE valid nuclei v3 YAML template for the described finding. "
                 "Output only the YAML, starting at 'id:'."),
    "wordlist": ("Produce a newline-separated wordlist tailored to the described target/tech. "
                 "One entry per line, no numbering, no commentary."),
    "poc":      ("Write a minimal, self-contained Python 3 proof-of-concept script for the "
                 "described finding. Use only the standard library + requests. Output only code."),
    "sqli":     ("Provide tailored SQL-injection test payloads for the described parameter/DBMS, "
                 "one per line, with a one-line '# ' comment above each explaining it."),
    "xss":      ("Provide tailored XSS test payloads for the described context (HTML/attr/JS/URL), "
                 "one per line, with a one-line '# ' comment above each explaining the context."),
    "custom":   ("Produce the requested security testing artifact for the described target."),
}


def generate_payload(kind: str, context: str, target: str = "") -> str:
    """Use the active LLM to generate a payload/template/wordlist/PoC for authorized testing.

    kind: one of nuclei | wordlist | poc | sqli | xss | custom
    context: free-text description of the target/tech/finding.
    Returns the generated text (thinking stripped).
    """
    guide = _GEN_GUIDES.get(kind, _GEN_GUIDES["custom"])
    user = ""
    if target:
        user += f"Target: {target}\n"
    user += f"Context / tech stack / finding:\n{context}\n\nTask: {guide}"
    messages = [
        {"role": "system", "content": _GEN_SYSTEM},
        {"role": "user",   "content": user},
    ]
    raw = ask_llm(messages)
    clean, _ = strip_thinking(raw)
    return clean.strip()


# ─────────────────────────────────────────────────────────────────────────────
# KILL-CHAIN / ATTACK-NARRATIVE REPORT
# ─────────────────────────────────────────────────────────────────────────────

_KILLCHAIN_SYSTEM = (
    "You are a senior penetration tester writing the attack-narrative section of a report "
    "for an AUTHORIZED engagement. Be concrete, technical and concise. Output Markdown only."
)


def generate_kill_chain(target: str, data: dict) -> str:
    """Produce an ordered attack-chain narrative from a session's findings.

    data: the dict returned by db.get_session (keys: vulns, exploits, summary).
    Returns Markdown text.
    """
    vulns = data.get("vulns", []) or []
    lines = []
    for v in vulns:
        sev  = (v[3] or "?").upper()
        lines.append(f"- [{sev}] {v[2]} (port {v[4] or '-'}, {v[5] or '-'}): {v[6] or ''}")
    findings = "\n".join(lines) or "(no structured vulnerabilities recorded)"

    exploits = data.get("exploits", []) or []
    exp_lines = [f"- {e[2]} via {e[3]}: {str(e[5] or '')[:120]}" for e in exploits]
    exp_txt = "\n".join(exp_lines) or "(none run)"

    summary = data.get("summary")
    ai = summary[3] if summary else ""

    user = (
        f"Target: {target}\n\n"
        f"Confirmed findings:\n{findings}\n\n"
        f"Exploits attempted:\n{exp_txt}\n\n"
        f"Prior AI analysis:\n{str(ai)[:1500]}\n\n"
        "Write the attack-chain / kill-chain narrative: how a realistic attacker could chain "
        "these findings from initial access to maximum impact. Use ordered steps; for each step "
        "give the technique and a one-line mitigation. If findings are weak, say so honestly. "
        "No preamble, Markdown only."
    )
    messages = [
        {"role": "system", "content": _KILLCHAIN_SYSTEM},
        {"role": "user",   "content": user},
    ]
    raw = ask_llm(messages)
    clean, _ = strip_thinking(raw)
    return clean.strip()


# ─────────────────────────────────────────────────────────────────────────────
# MODEL DISCOVERY
# ─────────────────────────────────────────────────────────────────────────────

def list_models() -> list:
    """Return the model ids available on the active backend.

    llama.cpp : GET {url}/v1/models  -> {"data": [{"id": ...}]}
    Ollama    : GET {url}/api/tags   -> {"models": [{"name": ...}]}
    Returns an empty list if the backend is unreachable or returns nothing.
    """
    cfg = settings.get_backend_config()
    try:
        if cfg["type"] == "llamacpp":
            url  = cfg["url"].rstrip("/") + "/v1/models"
            resp = requests.get(url, timeout=5)
            resp.raise_for_status()
            data = resp.json().get("data", [])
            return [m.get("id", "") for m in data if m.get("id")]
        else:  # ollama
            url  = cfg["url"].rstrip("/") + "/api/tags"
            resp = requests.get(url, timeout=5)
            resp.raise_for_status()
            models = resp.json().get("models", [])
            return [m.get("name", "") for m in models if m.get("name")]
    except Exception:
        return []


# ─────────────────────────────────────────────────────────────────────────────
# LOCAL GGUF MODEL LAUNCHER (llama.cpp)
# ─────────────────────────────────────────────────────────────────────────────

def list_gguf_models(models_dir: str) -> list:
    """Return [(filename, full_path)] for every *.gguf in models_dir (sorted)."""
    out = []
    if not models_dir or not os.path.isdir(models_dir):
        return out
    try:
        for entry in sorted(os.listdir(models_dir)):
            full = os.path.join(models_dir, entry)
            if os.path.isfile(full) and entry.lower().endswith(".gguf"):
                out.append((entry, full))
    except Exception:
        pass
    return out


def _health_ok(timeout: float = 3.0) -> bool:
    try:
        return requests.get(settings.get_backend_health_url(), timeout=timeout).status_code == 200
    except Exception:
        return False


def stop_llama_server(stop_cmd: str = "") -> None:
    """Stop a running llama-server: run stop_cmd if given, else kill it by process name."""
    if stop_cmd.strip():
        try:
            subprocess.run(stop_cmd, shell=True, capture_output=True, timeout=30)
        except Exception:
            pass
        return
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/IM", "llama-server.exe", "/F"],
                           capture_output=True, timeout=15)
        else:
            subprocess.run(["pkill", "-f", "llama-server"], capture_output=True, timeout=15)
    except Exception:
        pass


def start_llama_server(launch_cmd: str, model_path: str, port="8080") -> bool:
    """Spawn the launch command detached (new console). Returns True if the spawn succeeded."""
    cmd = launch_cmd.replace("{model}", model_path).replace("{port}", str(port))
    try:
        if os.name == "nt":
            CREATE_NEW_CONSOLE = 0x00000010
            subprocess.Popen(cmd, shell=True, creationflags=CREATE_NEW_CONSOLE)
        else:
            subprocess.Popen(cmd, shell=True, start_new_session=True)
        return True
    except Exception:
        return False


def wait_until_down(timeout: int = 15, poll: float = 1.0) -> bool:
    """Poll until the server stops answering health (old instance gone)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _health_ok(timeout=2.0):
            return True
        time.sleep(poll)
    return False


def wait_until_ready(timeout: int = 240, poll: float = 2.0) -> bool:
    """Poll the backend health endpoint until it is ready (model loaded) or timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _health_ok():
            return True
        time.sleep(poll)
    return False
