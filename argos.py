#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ARGOS — Web Security Analysis Assistant  (main entry point)"""

import sys
import argparse
import ui
import settings
import tools
import llm
from config import DEFAULT_SCAN_DEPTH
from db import (
    create_session, save_vulnerability, save_fix, save_exploit, save_summary,
    get_all_history, get_session, get_vulnerabilities, get_fixes, get_exploits,
    edit_vulnerability, edit_fix, edit_exploit, edit_summary_risk,
    delete_vulnerability, delete_exploit, delete_fix, delete_full_session,
    diff_sessions, get_session_count, mark_session_partial, mark_session_complete,
    save_tool_result, get_tool_results,
)
from export import export_menu


# ─────────────────────────────────────────────────────────────────────────────
# FOLLOW-UP CHAT
# ─────────────────────────────────────────────────────────────────────────────

def followup_chat(target: str, raw_scan: str, result: dict):
    ui.divider("FOLLOW-UP CHAT")
    ui.info("Ask follow-up questions about the scan results.")
    ui.info("Type [bold]exit[/] or leave blank to quit.")
    ui.console.print()

    history = llm.build_chat_history(target, raw_scan, result)

    while True:
        try:
            question = ui.prompt("You").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not question or question.lower() in ("exit", "quit", "q"):
            break
        cfg = settings.get_backend_config()
        ui.info(f"Sending to {cfg['label']} ({cfg['model']}) …")
        try:
            reply, history = llm.chat_reply(question, history)
            ui.print_chat_reply(reply)
        except Exception as e:
            ui.error(f"Chat error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# EXPLOIT EXECUTION MODE
# ─────────────────────────────────────────────────────────────────────────────

def exploit_mode(sl_no: int, exploits: list, target: str):
    """Interactive payload execution mode — runs suggested exploits against the target."""
    if not exploits:
        ui.warn("No exploit suggestions available.")
        return

    ui.divider("PAYLOAD EXECUTION MODE")
    ui.warn("[bold red]WARNING:[/] This will actively probe/attack the target.")
    ui.warn("Only proceed on systems you [bold]own[/] or have [bold]written permission[/] to test.")
    ui.console.print()

    if not ui.confirm("[bold red]Proceed with active payload execution?[/]", default=False):
        ui.info("Aborted.")
        return

    ui.console.print()
    for i, e in enumerate(exploits, 1):
        badge = f"[dim cyan][{i}][/]"
        ui.console.print(f"  {badge} [bold]{e.get('exploit_name', '?')}[/]")
        ui.console.print(f"       [dim]Tool:[/]    {e.get('tool_used', '?')}")
        payload_preview = (e.get('payload') or '')[:100]
        ui.console.print(f"       [dim]Payload:[/] {payload_preview}")
        if e.get('notes'):
            ui.console.print(f"       [dim]Notes:[/]   {e['notes'][:100]}")
        ui.console.print()

    sel = ui.prompt("Run which? (number, 'all', or Enter to skip)", default="").strip()
    if not sel:
        ui.info("Skipped.")
        return

    if sel.lower() == "all":
        to_run = list(exploits)
    elif sel.isdigit() and 1 <= int(sel) <= len(exploits):
        to_run = [exploits[int(sel) - 1]]
    else:
        ui.error("Invalid selection.")
        return

    for e in to_run:
        name = e.get("exploit_name", "?")
        ui.divider(f"RUNNING: {name}")
        ui.info(f"Tool: {e.get('tool_used','?')}  |  Target: {target}")
        try:
            with ui.spinner(f"Executing {name} …"):
                output = tools.run_suggested_exploit(e, target)

            with ui.spinner("AI analysiert Ergebnis …"):
                analysis = llm.analyze_exploit_result(e, output)

            ui.console.print()
            if analysis:
                success = analysis.get("success")
                if success is True:
                    icon   = "[bold green]✔  ERFOLG[/]"
                    bstyle = "green"
                elif success == "partial":
                    icon   = "[bold yellow]⚠  TEILWEISE[/]"
                    bstyle = "yellow"
                else:
                    icon   = "[bold red]✘  FEHLGESCHLAGEN[/]"
                    bstyle = "red"

                sev_colors = {"critical": "bold red", "high": "red",
                              "medium": "yellow", "low": "cyan", "info": "dim"}
                sev     = analysis.get("severity", "info")
                sev_col = sev_colors.get(sev, "dim")

                from rich.panel import Panel
                body_lines = [
                    icon,
                    "",
                    f"[bold]Ergebnis  :[/] {analysis.get('verdict', '?')}",
                ]
                if analysis.get("evidence"):
                    body_lines.append(
                        f"[bold]Beweis    :[/] [dim]{analysis['evidence']}[/]"
                    )
                body_lines.append(
                    f"[bold]Severity  :[/] [{sev_col}]{sev.upper()}[/]"
                )
                if analysis.get("recommendation"):
                    body_lines.append(
                        f"[bold]Next step :[/] {analysis['recommendation']}"
                    )

                ui.console.print(Panel(
                    "\n".join(body_lines),
                    title=f"[bold]{name}[/]",
                    border_style=bstyle,
                ))
                result_str = (
                    f"[{success}] {analysis.get('verdict', '')} | "
                    f"sev:{sev} | {analysis.get('evidence', '')}"
                )
            else:
                # LLM offline — show trimmed raw output
                ui.console.print(output[:1500])
                if len(output) > 1500:
                    ui.info(f"[dim]… {len(output)-1500} Zeichen ausgeblendet[/]")
                result_str = output[:2000]

            save_exploit(
                sl_no,
                name + " [EXECUTED]",
                e.get("tool_used", ""),
                e.get("payload", ""),
                result_str[:2000],
                e.get("notes", ""),
            )
            ui.success(f"Ergebnis gespeichert: {name}")
        except Exception as ex:
            ui.error(f"Execution failed: {ex}")

    ui.console.print()


# ─────────────────────────────────────────────────────────────────────────────
# NEW SCAN
# ─────────────────────────────────────────────────────────────────────────────

def new_scan(prefill_target=None, prefill_depth=None):
    ui.divider("NEW SCAN")
    if prefill_target:
        target = prefill_target.strip()
        ui.info(f"Target: [bold cyan]{target}[/]")
    else:
        target = ui.prompt("Target (IP or domain)").strip()
    if not target:
        ui.warn("No target entered.")
        return

    # ── Target validation
    with ui.spinner("Validating target …"):
        ok, msg = tools.validate_target(target)
    if ok:
        ui.success(f"Target reachable: {msg}")
    else:
        ui.warn(f"Target validation: {msg}")
        if not ui.confirm("Continue anyway?", default=False):
            return

    history = get_all_history()
    past = [row for row in history if row[1] == target and row[3] == "active"]
    if past:
        ui.warn(f"'{target}' has been scanned {len(past)} time(s) before.")
        if not ui.confirm("Continue with a new scan?", default=False):
            return

    # ── Scan depth
    _depth_default = {"standard": "1", "deep": "2", "ultra": "3"}.get(DEFAULT_SCAN_DEPTH, "1")
    if prefill_depth:
        depth_choice = prefill_depth
    else:
        ui.divider("SCAN DEPTH")
        ui.info("[1] Standard    — nmap, whois, whatweb, headers, DNS  (~2 min)")
        ui.info("[2] Deep        — + SSL, security headers, WAF, CMS, subdomains, dir enum, nikto, CT logs  (~10 min)")
        ui.info("[3] Ultra Deep  — + all vuln probes: SQLi, XSS, CORS, clickjacking, open redirect,")
        ui.info("                   deface detection, path traversal, info disclosure, full nmap vuln scripts  (~30 min)")
        depth_choice = ui.prompt("Depth", default=_depth_default).strip()

    if depth_choice == "3":
        depth = "ultra"
    elif depth_choice == "2":
        depth = "deep"
    else:
        depth = "standard"

    # ── Resume check
    partial = [row for row in get_all_history() if row[1] == target and row[3] == "partial"]
    existing = {}
    if partial:
        latest = partial[0]
        completed = get_tool_results(latest[0])
        ui.warn(f"Found interrupted scan SL# {latest[0]} ({len(completed)} tools done on {latest[2]}).")
        if ui.confirm("Resume this scan?", default=True):
            sl_no = latest[0]
            existing = completed
            ui.success(f"Resuming SL# {sl_no} — {len(existing)} tools already done.")
        else:
            sl_no = create_session(target)
            mark_session_partial(sl_no)
            ui.success(f"Session created — SL# {sl_no}")
    else:
        sl_no = create_session(target)
        mark_session_partial(sl_no)
        ui.success(f"Session created — SL# {sl_no}")

    # ── Recon
    ui.divider("RECON")
    if depth == "ultra":
        tool_names = tools.ULTRA_TOOL_NAMES
    elif depth == "deep":
        tool_names = tools.DEEP_TOOL_NAMES
    else:
        tool_names = tools.STANDARD_TOOL_NAMES
    total_tools = len([n for n in tool_names if n not in existing]) if existing else len(tool_names)
    _save_fn = lambda n, r: save_tool_result(sl_no, n, r)

    with ui.scan_progress(total_tools, label="Recon") as on_done:
        if depth == "ultra":
            recon_data = tools.run_ultra_recon(target, on_done=on_done, save_fn=_save_fn, existing=existing)
        elif depth == "deep":
            recon_data = tools.run_deep_recon(target, on_done=on_done, save_fn=_save_fn, existing=existing)
        else:
            recon_data = tools.run_default_recon(target, on_done=on_done, save_fn=_save_fn, existing=existing)

    raw_scan = tools.format_recon_for_llm(recon_data)

    if not raw_scan.strip():
        ui.warn("No scan data collected. Aborting.")
        delete_full_session(sl_no)
        return


    # ── AI Analysis ─────────────────────────────────────────────────────────
    ui.divider("AI ANALYSIS")
    try:
        result = llm.analyse_target(target, raw_scan)
    except Exception as e:
        ui.error(f"Analysis failed: {e}")
        delete_full_session(sl_no)
        return

    # ── Results ──────────────────────────────────────────────────────────────
    ui.divider("RESULTS")
    ui.print_analysis_result(result, target)

    # ── Save ─────────────────────────────────────────────────────────────────
    ui.divider("SAVING")
    for vuln in result.get("vulnerabilities", []):
        vuln_id = save_vulnerability(
            sl_no, vuln.get("vuln_name", ""), vuln.get("severity", "unknown"),
            vuln.get("port", ""), vuln.get("service", ""), vuln.get("description", ""),
        )
        if vuln.get("fix"):
            save_fix(sl_no, vuln_id, vuln["fix"], source="ai")
        ui.success(f"Saved: {vuln.get('vuln_name', '?')} [{vuln.get('severity', '?')}]")

    for exp in result.get("exploits", []):
        save_exploit(
            sl_no,
            exp.get("exploit_name", ""),
            exp.get("tool_used", ""),
            exp.get("payload", ""),
            exp.get("result", "suggested"),
            exp.get("notes", ""),
        )
        ui.success(f"Saved exploit: {exp.get('exploit_name', '?')}")

    save_summary(sl_no, result["raw_scan"], result["full_response"], result["risk_level"])
    mark_session_complete(sl_no)
    ui.success(f"All data saved — SL# {sl_no} | Risk: {result['risk_level']}")

    # ── Post-scan options ────────────────────────────────────────────────────
    exploits_list = result.get("exploits", [])
    if exploits_list and ui.confirm(
        f"Execute payloads? ({len(exploits_list)} exploit(s) suggested)", default=False
    ):
        exploit_mode(sl_no, exploits_list, target)

    if ui.confirm("Ask follow-up questions? (Chat with ARGOS about these results)", default=False):
        followup_chat(target, raw_scan, result)

    if ui.confirm("Export this session?", default=False):
        data = get_session(sl_no)
        export_menu(data)

    if ui.confirm("Edit or delete anything in this session?", default=False):
        edit_delete_menu(sl_no)


# ─────────────────────────────────────────────────────────────────────────────
# VIEW HISTORY
# ─────────────────────────────────────────────────────────────────────────────

def view_history():
    ui.divider("SCAN HISTORY")
    rows = get_all_history()
    ui.print_history_table(rows)
    if not rows:
        return

    sl_str = ui.prompt("SL# to view (or Enter to go back)", default="").strip()
    if not sl_str:
        return
    if not sl_str.isdigit():
        ui.error("Invalid SL#.")
        return

    sl_no = int(sl_str)
    data  = get_session(sl_no)
    if not data["history"]:
        ui.error(f"SL# {sl_no} not found.")
        return

    ui.print_session_detail(data)

    # Reload session exploits from DB for payload execution
    db_exploits = get_exploits(sl_no)
    suggested = [
        {"exploit_name": e[2], "tool_used": e[3],
         "payload": e[4], "result": e[5], "notes": e[6]}
        for e in db_exploits if e[5] and "EXECUTED" not in str(e[2])
    ]
    if suggested and ui.confirm(
        f"Execute payloads? ({len(suggested)} exploit(s) in this session)", default=False
    ):
        h = data["history"]
        exploit_mode(sl_no, suggested, h[1])

    if ui.confirm("Export this session?", default=False):
        export_menu(data)
    if ui.confirm("Edit or delete anything?", default=False):
        edit_delete_menu(sl_no)
    if ui.confirm("Compare with another session?", default=False):
        diff_menu(sl_no)


# ─────────────────────────────────────────────────────────────────────────────
# DIFF / COMPARE
# ─────────────────────────────────────────────────────────────────────────────

def diff_menu(sl_a: int = None):
    ui.divider("COMPARE SESSIONS")
    rows = get_all_history()
    ui.print_history_table(rows)
    if len(rows) < 2:
        ui.warn("Need at least 2 sessions to compare.")
        return

    if sl_a is None:
        a_str = ui.prompt("First SL# (older scan)").strip()
        if not a_str.isdigit():
            ui.error("Invalid SL#.")
            return
        sl_a = int(a_str)

    b_str = ui.prompt("Second SL# (newer scan)").strip()
    if not b_str.isdigit():
        ui.error("Invalid SL#.")
        return
    sl_b = int(b_str)

    if sl_a == sl_b:
        ui.warn("Select two different sessions.")
        return

    diff = diff_sessions(sl_a, sl_b)
    ui.print_diff(diff, sl_a, sl_b)


# ─────────────────────────────────────────────────────────────────────────────
# EDIT / DELETE
# ─────────────────────────────────────────────────────────────────────────────

def edit_delete_menu(sl_no: int):
    while True:
        ui.divider(f"EDIT / DELETE — SL# {sl_no}")
        ui.info("[1] Edit vulnerability")
        ui.info("[2] Edit fix")
        ui.info("[3] Edit exploit")
        ui.info("[4] Edit risk level")
        ui.info("[5] Delete vulnerability")
        ui.info("[6] Delete fix")
        ui.info("[7] Delete exploit")
        ui.info("[8] Delete ENTIRE session")
        ui.info("[9] Back")
        ui.divider()
        choice = ui.prompt("Choice").strip()

        if choice == "1":
            vulns = get_vulnerabilities(sl_no)
            if not vulns:
                ui.warn("No vulnerabilities recorded."); continue
            for v in vulns:
                ui.info(f"id={v[0]} | {v[2]} | {v[3]} | port {v[4]} | {v[5]}")
            vid = ui.prompt("Vulnerability id to edit").strip()
            if not vid.isdigit():
                ui.error("Invalid id."); continue
            ui.info("Fields: vuln_name / severity / port / service / description")
            field = ui.prompt("Field").strip()
            value = ui.prompt(f"New value for '{field}'").strip()
            if edit_vulnerability(int(vid), field, value):
                ui.success("Updated.")
            else:
                ui.error(f"Invalid field '{field}'. Allowed: vuln_name, severity, port, service, description")

        elif choice == "2":
            fixes = get_fixes(sl_no)
            if not fixes:
                ui.warn("No fixes recorded."); continue
            for f in fixes:
                ui.info(f"id={f[0]} | vuln_id={f[2]} | {f[3][:80]}")
            fid = ui.prompt("Fix id to edit").strip()
            if not fid.isdigit():
                ui.error("Invalid id."); continue
            new_text = ui.prompt("New fix text").strip()
            edit_fix(int(fid), new_text)
            ui.success("Updated.")

        elif choice == "3":
            exploits = get_exploits(sl_no)
            if not exploits:
                ui.warn("No exploits recorded."); continue
            for e in exploits:
                ui.info(f"id={e[0]} | {e[2]} | tool: {e[3]} | result: {e[5]}")
            eid = ui.prompt("Exploit id to edit").strip()
            if not eid.isdigit():
                ui.error("Invalid id."); continue
            ui.info("Fields: exploit_name / tool_used / payload / result / notes")
            field = ui.prompt("Field").strip()
            value = ui.prompt(f"New value for '{field}'").strip()
            if edit_exploit(int(eid), field, value):
                ui.success("Updated.")
            else:
                ui.error(f"Invalid field '{field}'. Allowed: exploit_name, tool_used, payload, result, notes")

        elif choice == "4":
            ui.info("Options: CRITICAL / HIGH / MEDIUM / LOW")
            risk = ui.prompt("New risk level").strip().upper()
            if risk not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                ui.error("Invalid risk level."); continue
            edit_summary_risk(sl_no, risk)
            ui.success(f"Risk level set to {risk}.")

        elif choice == "5":
            vulns = get_vulnerabilities(sl_no)
            if not vulns:
                ui.warn("No vulnerabilities to delete."); continue
            for v in vulns:
                ui.info(f"id={v[0]} | {v[2]} | {v[3]}")
            vid = ui.prompt("Vulnerability id to delete").strip()
            if not vid.isdigit():
                ui.error("Invalid id."); continue
            if ui.confirm(f"Delete vulnerability id={vid} and linked fixes?"):
                delete_vulnerability(int(vid))
                ui.success("Deleted.")

        elif choice == "6":
            fixes = get_fixes(sl_no)
            if not fixes:
                ui.warn("No fixes to delete."); continue
            for f in fixes:
                ui.info(f"id={f[0]} | vuln_id={f[2]} | {f[3][:80]}")
            fid = ui.prompt("Fix id to delete").strip()
            if not fid.isdigit():
                ui.error("Invalid id."); continue
            if ui.confirm(f"Delete fix id={fid}?"):
                delete_fix(int(fid))
                ui.success("Deleted.")

        elif choice == "7":
            exploits = get_exploits(sl_no)
            if not exploits:
                ui.warn("No exploits to delete."); continue
            for e in exploits:
                ui.info(f"id={e[0]} | {e[2]} | result: {e[5]}")
            eid = ui.prompt("Exploit id to delete").strip()
            if not eid.isdigit():
                ui.error("Invalid id."); continue
            if ui.confirm(f"Delete exploit id={eid}?"):
                delete_exploit(int(eid))
                ui.success("Deleted.")

        elif choice == "8":
            if ui.confirm(f"[bold red]Permanently delete ENTIRE session SL# {sl_no}?[/]"):
                delete_full_session(sl_no)
                ui.success(f"Session SL# {sl_no} wiped.")
                return

        elif choice == "9":
            break
        else:
            ui.warn("Invalid choice.")


# ─────────────────────────────────────────────────────────────────────────────
# SETTINGS MENU
# ─────────────────────────────────────────────────────────────────────────────

def settings_menu():
    while True:
        s = settings.load()
        current_backend = settings.get_backend_name()
        current_ua      = settings.get_user_agent_name()
        cfg             = settings.get_backend_config()

        try:
            import cve as cve_mod
            cve_stats = cve_mod.show_cve_cache_stats()
        except Exception:
            cve_stats = "unavailable"

        show_thinking = s.get("show_thinking", False)
        think_label   = "[bold green]ON[/]" if show_thinking else "[dim]OFF[/]"

        ui.divider("SETTINGS")
        proxy_val = settings.get_proxy() or "[dim](not set)[/]"
        cookie_val = "[dim](set)[/]" if settings.get_auth_cookie() else "[dim](not set)[/]"
        basic_val  = "[dim](set)[/]" if settings.get_basic_auth() else "[dim](not set)[/]"
        dir_wl     = settings.get_wordlist("dir") or "[dim](built-in)[/]"
        sub_wl     = settings.get_wordlist("subdomain") or "[dim](built-in)[/]"
        ui.info(f"[1] LLM Backend     : {current_backend} — {cfg['label']}")
        ui.info(f"[2] Model name      : {cfg['model']}")
        ui.info(f"[3] Server URL      : {cfg['url']}")
        ui.info(f"[4] User-Agent      : {current_ua}")
        ui.info(f"[5] Show thinking   : {think_label}  (show <think>…</think> from reasoning models)")
        ui.info(f"[6] CVE cache       : {cve_stats}")
        ui.info(f"[7] Proxy           : {proxy_val}")
        ui.info(f"[8] Auth cookie     : {cookie_val}")
        ui.info(f"[9] Basic auth      : {basic_val}")
        ui.info(f"[A] Dir wordlist    : {dir_wl}")
        ui.info(f"[B] Sub wordlist    : {sub_wl}")
        ui.info("[0] Back")
        ui.divider()
        choice = ui.prompt("Choice").strip()

        if choice == "1":
            ui.info("Available backends:")
            for i, name in enumerate(settings.BACKEND_KEYS, 1):
                marker = " [bold cyan][active][/]" if name == current_backend else ""
                ui.info(f"  [{i}] {name}{marker}")
            bc = ui.prompt("Select backend number", default="").strip()
            if bc.isdigit() and 1 <= int(bc) <= len(settings.BACKEND_KEYS):
                new_be = settings.BACKEND_KEYS[int(bc) - 1]
                s["backend"] = new_be
                settings.save(s)
                ui.success(f"Backend set to: {new_be}")
            else:
                ui.warn("Cancelled.")

        elif choice == "2":
            be = settings.get_backend_name()
            new_model = ui.prompt("New model name", default=cfg["model"]).strip()
            if new_model:
                key = "llamacpp_model" if be == "llama.cpp" else "ollama_model"
                s[key] = new_model
                settings.save(s)
                ui.success(f"Model set to: {new_model}")

        elif choice == "3":
            be = settings.get_backend_name()
            new_url = ui.prompt("New server URL", default=cfg["url"]).strip()
            if new_url:
                key = "llamacpp_url" if be == "llama.cpp" else "ollama_url"
                s[key] = new_url
                settings.save(s)
                ui.success(f"URL set to: {new_url}")

        elif choice == "4":
            ua_names = list(settings.USER_AGENTS.keys())
            ui.info("Available user agents:")
            for i, name in enumerate(ua_names, 1):
                marker = " [bold cyan][active][/]" if name == current_ua else ""
                ui.info(f"  [{i:2d}] {name}{marker}")
            uc = ui.prompt("Select number", default="").strip()
            if uc.isdigit() and 1 <= int(uc) <= len(ua_names):
                new_ua = ua_names[int(uc) - 1]
                s["user_agent"] = new_ua
                settings.save(s)
                ui.success(f"User-Agent set to: {new_ua}")
            else:
                ui.warn("Cancelled.")

        elif choice == "5":
            s["show_thinking"] = not s.get("show_thinking", False)
            settings.save(s)
            state = "ON" if s["show_thinking"] else "OFF"
            ui.success(f"Show thinking: {state}")

        elif choice == "6":
            if ui.confirm("Clear CVE cache? (will re-fetch on next scan)", default=False):
                try:
                    import sqlite3
                    from config import DB_PATH
                    conn = sqlite3.connect(DB_PATH)
                    conn.execute("DELETE FROM cve_cache")
                    conn.commit()
                    conn.close()
                    ui.success("CVE cache cleared.")
                except Exception as e:
                    ui.error(f"Could not clear cache: {e}")

        elif choice == "7":
            proxy_new = ui.prompt("Proxy URL (empty to clear)", default=settings.get_proxy()).strip()
            s["proxy_url"] = proxy_new
            settings.save(s)
            ui.success(f"Proxy set to: {proxy_new or '(none)'}")

        elif choice == "8":
            cookie_new = ui.prompt("Cookie string (empty to clear)", default="").strip()
            s["auth_cookie"] = cookie_new
            settings.save(s)
            ui.success("Auth cookie " + ("set." if cookie_new else "cleared."))

        elif choice == "9":
            user = ui.prompt("Username (empty to clear)", default="").strip()
            if user:
                pw = ui.prompt("Password", default="").strip()
                s["auth_basic_user"] = user
                s["auth_basic_pass"] = pw
                settings.save(s)
                ui.success(f"Basic auth set for user: {user}")
            else:
                s["auth_basic_user"] = ""
                s["auth_basic_pass"] = ""
                settings.save(s)
                ui.success("Basic auth cleared.")

        elif choice.upper() == "A":
            wl = ui.prompt("Dir wordlist path (empty for built-in)", default=settings.get_wordlist("dir")).strip()
            s["dir_wordlist"] = wl
            settings.save(s)
            ui.success(f"Dir wordlist: {wl or '(built-in)'}")

        elif choice.upper() == "B":
            wl = ui.prompt("Subdomain wordlist path (empty for built-in)", default=settings.get_wordlist("subdomain")).strip()
            s["subdomain_wordlist"] = wl
            settings.save(s)
            ui.success(f"Subdomain wordlist: {wl or '(built-in)'}")

        elif choice == "0":
            break
        else:
            ui.warn("Invalid choice.")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN MENU
# ─────────────────────────────────────────────────────────────────────────────

def _parse_args():
    p = argparse.ArgumentParser(
        prog="argos",
        description="ARGOS — Web Security Analysis Assistant",
    )
    p.add_argument("--target", "-t", metavar="TARGET",
                   help="Target IP or domain (skip the prompt)")
    p.add_argument("--depth", "-d", choices=["1", "2", "3"], metavar="DEPTH",
                   help="Scan depth: 1=standard 2=deep 3=ultra")
    p.add_argument("--proxy", "-p", metavar="URL",
                   help="Proxy URL for all requests (e.g. http://127.0.0.1:8080)")
    p.add_argument("--cookie", metavar="COOKIE",
                   help="Raw Cookie header for authenticated scans")
    p.add_argument("--auth", metavar="USER:PASS",
                   help="HTTP Basic Auth credentials")
    return p.parse_args()


def main():
    args = _parse_args()

    # Apply CLI overrides to settings (saved for duration of run)
    if args.proxy or args.cookie or args.auth:
        s = settings.load()
        if args.proxy:
            s["proxy_url"] = args.proxy
        if args.cookie:
            s["auth_cookie"] = args.cookie
        if args.auth:
            user, _, pw = args.auth.partition(":")
            s["auth_basic_user"] = user
            s["auth_basic_pass"] = pw
        settings.save(s)

    # Direct scan via CLI args (--target bypasses the menu)
    if args.target:
        new_scan(prefill_target=args.target, prefill_depth=args.depth)
        return

    first_run = True
    while True:
        # Clear exactly once per loop iteration, before printing the banner
        if not first_run:
            ui.clear_screen()
        first_run = False

        online      = llm.check_llm_online()
        ua_name     = settings.get_user_agent_name()
        cfg         = settings.get_backend_config()
        sess_count  = get_session_count()

        ui.print_banner(llm_online=online, ua_name=ua_name,
                        backend_name=cfg["label"], model_name=cfg["model"],
                        session_count=sess_count)

        ui.info("[1] New Scan")
        ui.info("[2] View History")
        ui.info("[3] Compare Sessions")
        ui.info("[4] Settings")
        ui.info("[5] Exit")
        ui.divider()
        choice = ui.prompt("argos>").strip()

        if choice == "1":
            new_scan()
            ui.prompt("Press Enter to return to menu …", default="")
        elif choice == "2":
            view_history()
            ui.prompt("Press Enter to return to menu …", default="")
        elif choice == "3":
            diff_menu()
            ui.prompt("Press Enter to return to menu …", default="")
        elif choice == "4":
            settings_menu()
            ui.prompt("Press Enter to return to menu …", default="")
        elif choice == "5":
            ui.console.print("\n[dim]Stay legal. Goodbye.[/dim]\n")
            sys.exit(0)
        else:
            ui.warn("Invalid choice — press Enter to continue.")
            ui.prompt("", default="")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        ui.console.print("\n[dim]Interrupted. Goodbye.[/dim]\n")
        sys.exit(0)
