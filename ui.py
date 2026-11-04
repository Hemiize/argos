# -*- coding: utf-8 -*-
"""ARGOS — Rich-based terminal UI components."""

import threading
from contextlib import contextmanager
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.markup import escape
from rich.rule import Rule
from rich import box
from rich.progress import (
    Progress, SpinnerColumn, BarColumn, TextColumn,
    TimeElapsedColumn, TaskProgressColumn,
)
from rich.prompt import Prompt, Confirm
from rich.markdown import Markdown
from rich.live import Live
from rich.columns import Columns

console = Console()

# ── Colour / badge maps ───────────────────────────────────────────────────────

SEVERITY_COLOR = {
    "critical": "bold red",
    "high":     "bold dark_orange",
    "medium":   "bold yellow",
    "low":      "bold green",
    "info":     "bold cyan",
    "unknown":  "dim white",
}

RISK_COLOR = {
    "CRITICAL": "red",
    "HIGH":     "dark_orange",
    "MEDIUM":   "yellow",
    "LOW":      "green",
    "UNKNOWN":  "dim white",
}

SEVERITY_BADGE = {
    "critical": "[bold white on red] CRITICAL [/]",
    "high":     "[bold white on dark_orange] HIGH [/]",
    "medium":   "[bold black on yellow] MEDIUM [/]",
    "low":      "[bold white on green] LOW [/]",
    "info":     "[bold white on cyan] INFO [/]",
    "unknown":  "[dim] UNKNOWN [/]",
}

RISK_BADGE = {
    "CRITICAL": "[bold white on red]  ■ CRITICAL  [/]",
    "HIGH":     "[bold white on dark_orange]  ■ HIGH  [/]",
    "MEDIUM":   "[bold black on yellow]  ■ MEDIUM  [/]",
    "LOW":      "[bold white on green]  ■ LOW  [/]",
    "UNKNOWN":  "[dim]  ■ UNKNOWN  [/]",
}


# ── Banner ────────────────────────────────────────────────────────────────────

_BANNER = r"""
  ▄████████    ▄████████    ▄██████▄     ▄██████▄     ▄████████
  ███    ███   ███    ███   ███    ███   ███    ███   ███    ███
  ███    ███   ███    ███   ███    █▀    ███    ███   ███    █▀
  ███    ███  ▄███▄▄▄▄██▀  ▄███         ███    ███   ███
▀███████████ ▀▀███▀▀▀▀▀   ▀▀███ ████▄  ███    ███ ▀███████████
  ███    ███ ▀███████████   ███    ███  ███    ███          ███
  ███    ███   ███    ███   ███    ███  ███    ███    ▄█    ███
  ███    █▀    ███    ███   ████████▀    ▀██████▀   ▄████████▀
               ███    ███
"""

_BANNER_FALLBACK = r"""
   _   ___ ___ ___  ___
  /_\ | _ \ __/ _ \/ __|
 / _ \|   / _| (_) \__ \
/_/ \_\_|_\___\___/|___/
"""


def clear_screen():
    """Clear the terminal — works on both Windows and Linux."""
    import os
    import platform
    try:
        os.system("cls" if platform.system() == "Windows" else "clear")
    except Exception:
        console.clear()


def print_banner(llm_online: bool = False, ua_name: str = "",
                  backend_name: str = "", model_name: str = "", session_count: int = 0):
    # Caller is responsible for clearing before calling this
    try:
        console.print(Text(_BANNER, style="bold cyan"), highlight=False)
    except Exception:
        console.print(Text(_BANNER_FALLBACK, style="bold cyan"), highlight=False)

    console.print("  [dim]Web Security Analysis Assistant[/]")
    console.print()

    display_backend = backend_name or "LLM"
    llm_dot = "[bold green]●[/]" if llm_online else "[bold red]●[/]"
    status  = "online" if llm_online else "offline"
    model_txt = f"  [dim]│[/]  [dim]model:[/] [bold]{model_name}[/]" if model_name else ""
    ua_txt    = f"  [dim]│[/]  [dim]UA:[/] {ua_name}" if ua_name else ""
    console.print(f"  {llm_dot} [bold]{display_backend}[/] {status}{model_txt}{ua_txt}")
    if session_count:
        console.print(f"  [dim]│[/]  [dim]sessions:[/] [bold cyan]{session_count}[/] saved")
    console.print()


# ── Simple primitives ─────────────────────────────────────────────────────────

@contextmanager
def spinner(text: str):
    with Progress(
        SpinnerColumn(style="bold cyan"),
        TextColumn(f"[cyan]{text}[/]"),
        transient=True,
        console=console,
    ) as p:
        p.add_task("", total=None)
        yield


def divider(label: str = ""):
    if label:
        console.print(Rule(f"[bold yellow] {label} [/]", style="dim yellow"))
    else:
        console.print(Rule(style="dim"))


def success(msg: str): console.print(f"[bold green][+][/] {msg}")
def warn(msg: str):    console.print(f"[bold yellow][!][/] {msg}")
def error(msg: str):   console.print(f"[bold red][x][/] {msg}")
def info(msg: str):    console.print(f"[bold cyan][*][/] {msg}")


def prompt(text: str, default: str = "") -> str:
    if default:
        return Prompt.ask(f"[cyan]{text}[/]", default=default)
    return Prompt.ask(f"[cyan]{text}[/]")


def confirm(text: str, default: bool = False) -> bool:
    return Confirm.ask(f"[cyan]{text}[/]", default=default)


# ── Live scan progress ────────────────────────────────────────────────────────

@contextmanager
def scan_progress(total: int, label: str = "Scanning"):
    """
    Context manager for parallel tool execution.
    Yields on_done(tool_name) — call it once per finished tool.
    """
    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=28, complete_style="cyan", finished_style="green"),
        TaskProgressColumn(),
        TextColumn("[dim]{task.fields[last]}[/]"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task_id = progress.add_task(f"{label} [0/{total}]", total=total, last="")
        lock = threading.Lock()
        completed = [0]

        def on_done(tool_name: str):
            with lock:
                completed[0] += 1
                progress.update(task_id, advance=1,
                               description=f"{label} [{completed[0]}/{total}]",
                               last=f"✓ {tool_name}")

        yield on_done


# ── Live LLM streaming ────────────────────────────────────────────────────────

@contextmanager
def llm_live_display(backend_label: str = "LLM"):
    """
    Context manager for streaming LLM output.
    Yields a writer(token, stats_dict) callable.
    stats_dict keys: tokens, tokens_per_sec (optional).
    """
    buffer = [""]
    stats  = [{}]

    def _make_panel():
        body = buffer[0] if buffer[0] else "[dim]Waiting for model…[/]"
        tps = stats[0].get("tokens_per_sec")
        total_tok = stats[0].get("tokens", 0)
        stat_line = ""
        if total_tok:
            tps_str = f"  [dim]{tps:.1f} tok/s[/]" if tps else ""
            stat_line = f"\n\n[dim]tokens: {total_tok}{tps_str}[/]"
        return Panel(
            body + stat_line,
            title=f"[bold cyan] {backend_label} [/]",
            border_style="dim cyan",
            padding=(0, 2),
        )

    with Live(_make_panel(), console=console, refresh_per_second=8) as live:
        def writer(token: str, s: dict = None):
            buffer[0] += token
            if s:
                stats[0] = s
            live.update(_make_panel())

        yield writer


# ── History table ─────────────────────────────────────────────────────────────

def print_history_table(rows):
    if not rows:
        warn("No scans in database yet.")
        return
    table = Table(box=box.ROUNDED, border_style="dim", header_style="bold cyan")
    table.add_column("SL#",    style="dim",        width=5)
    table.add_column("Target", min_width=28)
    table.add_column("Date",   width=20)
    table.add_column("Status", width=10)
    for row in rows:
        status_style = "green" if row[3] == "active" else "dim"
        table.add_row(str(row[0]), row[1], str(row[2]), f"[{status_style}]{row[3]}[/]")
    console.print(table)


# ── Analysis result ───────────────────────────────────────────────────────────

def print_analysis_result(result: dict, target: str):
    risk      = result.get("risk_level", "UNKNOWN").upper()
    summary   = result.get("summary", "")
    vulns     = result.get("vulnerabilities", [])
    exploits  = result.get("exploits", [])
    cve_info  = result.get("cve_context", "")

    risk_col  = RISK_COLOR.get(risk, "white")
    risk_badge = RISK_BADGE.get(risk, f"[bold] {risk} [/]")

    console.print()
    console.print(Rule(style=f"bold {risk_col}"))
    console.print(f"  {risk_badge}   [dim]Target:[/] {escape(str(target))}")
    console.print(Rule(style=f"bold {risk_col}"))
    console.print()

    if summary:
        console.print(Panel(
            f"[white]{escape(str(summary))}[/]",
            title="[bold]Executive Summary[/]",
            border_style="dim",
            padding=(0, 2),
        ))
        console.print()

    if cve_info:
        console.print(Panel(
            f"[dim]{escape(str(cve_info))}[/]",
            title="[bold cyan]CVE Enrichment[/]",
            border_style="dim cyan",
            padding=(0, 2),
        ))
        console.print()

    console.print(Rule(f"[bold cyan] Vulnerabilities ({len(vulns)}) [/]", style="cyan"))
    if vulns:
        t = Table(box=box.SIMPLE_HEAVY, border_style="dim", header_style="bold dim")
        t.add_column("#",           style="dim",  width=4)
        t.add_column("Vulnerability",             min_width=32)
        t.add_column("Severity",                  width=12)
        t.add_column("Port",        style="dim",  width=7)
        t.add_column("Service",     style="dim",  width=18)
        for i, v in enumerate(vulns, 1):
            sev   = v.get("severity", "unknown").lower()
            badge = SEVERITY_BADGE.get(sev, f"[dim]{sev.upper()}[/]")
            t.add_row(
                str(i),
                escape(str(v.get("vuln_name", ""))),
                badge,
                escape(str(v.get("port", "-"))),
                escape(str(v.get("service", "-"))),
            )
        console.print(t)

        console.print()
        console.print(Rule("[bold cyan] Details [/]", style="dim cyan"))
        for v in vulns:
            sev  = v.get("severity", "unknown").lower()
            col  = SEVERITY_COLOR.get(sev, "white")
            name = escape(str(v.get("vuln_name", "")))
            port = escape(str(v.get("port", "-")))
            svc  = escape(str(v.get("service", "-")))
            desc = escape(str(v.get("description", "")))
            fix  = escape(str(v.get("fix", "")))
            body = f"[dim]Port:[/] {port}   [dim]Service:[/] {svc}\n\n"
            if desc: body += f"{desc}\n"
            if fix:  body += f"\n[bold green]► Fix:[/] {fix}"
            border = {"critical": "red", "high": "dark_orange",
                      "medium": "yellow", "low": "green"}.get(sev, "dim")
            console.print(Panel(
                body.strip(),
                title=f"[{col}][{sev.upper()}][/] {name}",
                border_style=border,
                padding=(1, 2),
            ))
    else:
        console.print("[dim]  No vulnerabilities recorded.[/]")

    if exploits:
        console.print()
        console.print(Rule(f"[bold red] Exploits ({len(exploits)}) [/]", style="red"))
        for e in exploits:
            name    = escape(str(e.get("exploit_name", "")))
            tool    = escape(str(e.get("tool_used", "")))
            payload = escape(str(e.get("payload", "")))
            notes   = escape(str(e.get("notes", "")))
            body    = ""
            if tool:    body += f"[dim]Tool:[/]    {tool}\n"
            if payload: body += f"[dim]Payload:[/] [bold]{payload}[/]\n"
            if notes:   body += f"[dim]Notes:[/]   {notes}"
            console.print(Panel(
                body.strip() or "[dim]No details.[/]",
                title=f"[bold red]{name}[/]",
                border_style="red",
                padding=(0, 2),
            ))

    console.print()


# ── Session detail view ───────────────────────────────────────────────────────

def print_session_detail(data: dict):
    h = data["history"]
    console.print()
    console.print(Panel(
        f"[dim]SL#[/] [bold]{h[0]}[/]   [dim]Target:[/] [bold cyan]{escape(str(h[1]))}[/]"
        f"   [dim]Date:[/] {escape(str(h[2]))}   [dim]Status:[/] {escape(str(h[3]))}",
        border_style="cyan",
        padding=(0, 2),
    ))

    console.print()
    console.print(Rule("[bold cyan] Vulnerabilities [/]", style="dim"))
    if data["vulns"]:
        t = Table(box=box.SIMPLE_HEAVY, border_style="dim", header_style="bold dim")
        t.add_column("id",    style="dim", width=5)
        t.add_column("Vulnerability",      min_width=28)
        t.add_column("Severity",           width=12)
        t.add_column("Port",  style="dim", width=7)
        t.add_column("Service", style="dim", width=15)
        for v in data["vulns"]:
            sev   = (v[3] or "unknown").lower()
            badge = SEVERITY_BADGE.get(sev, f"[dim]{escape(sev.upper())}[/]")
            t.add_row(str(v[0]), escape(str(v[2] or "")), badge,
                      escape(str(v[4] or "-")), escape(str(v[5] or "-")))
        console.print(t)
    else:
        console.print("  [dim]None recorded.[/]")

    console.print()
    console.print(Rule("[bold cyan] Fixes [/]", style="dim"))
    if data["fixes"]:
        for f in data["fixes"]:
            console.print(f"  [dim]id={f[0]}  vuln_id={f[2]}  \\[{escape(str(f[4] or ''))}][/]  {escape(str(f[3] or ''))}")
    else:
        console.print("  [dim]None recorded.[/]")

    console.print()
    console.print(Rule("[bold cyan] Exploits [/]", style="dim"))
    if data["exploits"]:
        for e in data["exploits"]:
            console.print(f"  [dim]id={e[0]}[/]  {escape(str(e[2] or ''))}  [dim]Tool:[/] {escape(str(e[3] or ''))}  [dim]Result:[/] {escape(str(e[5] or ''))}")
    else:
        console.print("  [dim]None recorded.[/]")

    console.print()
    console.print(Rule("[bold cyan] Summary [/]", style="dim"))
    if data["summary"]:
        s = data["summary"]
        risk  = (s[4] or "UNKNOWN").upper()
        badge = RISK_BADGE.get(risk, f"[dim]{risk}[/]")
        console.print(f"  Risk: {badge}   [dim]Generated:[/] {s[5]}")
        if s[3]:
            snippet = escape(str(s[3])[:600])
            console.print(Panel(
                snippet + ("…" if len(str(s[3])) > 600 else ""),
                border_style="dim", padding=(0, 2),
            ))
    else:
        console.print("  [dim]None recorded.[/]")
    console.print()


# ── Chat reply ────────────────────────────────────────────────────────────────

def print_chat_reply(text: str):
    """Render an LLM chat response — tries Markdown, falls back to plain text."""
    console.print()
    try:
        console.print(Panel(
            Markdown(text),
            title="[bold cyan] ARGOS [/]",
            border_style="cyan",
            padding=(1, 2),
        ))
    except Exception:
        console.print(Panel(
            text,
            title="[bold cyan] ARGOS [/]",
            border_style="cyan",
            padding=(1, 2),
        ))
    console.print()


# ── Diff display ──────────────────────────────────────────────────────────────

def print_diff(diff: dict, sl_a: int, sl_b: int):
    """Display a comparison between two scan sessions."""
    console.print()
    console.print(Rule(f"[bold cyan] Scan Diff — SL#{sl_a} vs SL#{sl_b} [/]", style="cyan"))
    console.print()

    new_   = diff.get("new", [])
    fixed_ = diff.get("fixed", [])
    changed= diff.get("changed", [])
    same_  = diff.get("same", [])

    if new_:
        console.print(Rule("[bold red] NEW  (appeared in second scan) [/]", style="red"))
        for v in new_:
            sev   = v.get("severity", "unknown").lower()
            badge = SEVERITY_BADGE.get(sev, sev.upper())
            console.print(f"  [red]+[/] {badge} {v.get('vuln_name','')}")
        console.print()

    if fixed_:
        console.print(Rule("[bold green] FIXED  (gone in second scan) [/]", style="green"))
        for v in fixed_:
            sev   = v.get("severity", "unknown").lower()
            badge = SEVERITY_BADGE.get(sev, sev.upper())
            console.print(f"  [green]-[/] {badge} {v.get('vuln_name','')}")
        console.print()

    if changed:
        console.print(Rule("[bold yellow] SEVERITY CHANGED [/]", style="yellow"))
        for v in changed:
            console.print(
                f"  [yellow]~[/] {v['vuln_name']}  "
                f"[dim]{v['old_sev']} → {v['new_sev']}[/]"
            )
        console.print()

    if same_:
        console.print(f"  [dim]{len(same_)} vulnerability/ies unchanged.[/]")

    if not new_ and not fixed_ and not changed:
        console.print("  [dim]No differences found between the two scans.[/]")
    console.print()
