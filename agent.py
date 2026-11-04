#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARGOS — agent.py
Autonomous recon→exploit loop. The LLM observes results and decides the next
command, step by step, scope-locked to a single authorized host.

Human-in-the-loop by default: every command is shown and confirmed before it runs.
Only use against systems you own or are explicitly authorized to test.
"""

import re
import json
from urllib.parse import urlparse

from rich.panel import Panel
from rich.markup import escape

import ui
import llm
import tools


AGENT_SYSTEM = """You are ARGOS-Agent, an autonomous penetration-testing assistant working ONLY against a host the operator is explicitly authorized to test.

You operate in a loop. Each turn you receive the target, the goal, and the history of commands already run with their output. You decide the single next best action.

Respond with ONLY a JSON object (no markdown, no prose outside the JSON):
{
  "thought": "brief reasoning, <=200 chars",
  "action": "run" | "done",
  "tool": "<one allowed tool>",
  "command": "<full command line including the tool name>",
  "reason": "why this command — or, if action is done, your final findings"
}

Rules:
- Only use these tools: {TOOLS}
- Every command must target ONLY the host: {HOST}. Never reference any other host or IP.
- Start with light information gathering, then escalate step by step based on what you learn.
- Prefer non-destructive actions. Do not attempt DoS, brute-force at scale, or data destruction.
- When the goal is met, or no further useful step exists, set "action":"done" and put your
  conclusions in "reason"."""


def _host_of(target: str) -> str:
    t = target if "://" in target else "http://" + target
    return urlparse(t).netloc.split(":")[0] or target


def _command_in_scope(command: str, host: str) -> bool:
    """Reject a command that references a host/IP other than the locked target."""
    refs = re.findall(r"https?://([^/\s:]+)", command)
    refs += re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", command)
    for h in refs:
        if host not in h and h not in host:
            return False
    return True


def _parse_json(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:]).strip()
    try:
        return json.loads(text)
    except Exception:
        m = re.search(r"\{[\s\S]+\}", text)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                return {}
    return {}


def run_agent(target: str,
              goal: str = "Find and verify the most impactful vulnerability",
              max_steps: int = 8) -> list:
    """Run the autonomous loop. Returns a transcript (list of step dicts)."""
    host      = _host_of(target)
    installed = [t for t in sorted(tools.EXEC_TOOL_ALLOWLIST)
                 if t == "curl" or tools.tool_installed(t)]

    ui.divider("AGENT MODE")
    ui.warn("[bold red]Autonomous mode[/] — only run against systems you own or "
            "are explicitly authorized to test.")
    ui.info(f"Target host (scope-locked): [bold cyan]{escape(host)}[/]")
    ui.info(f"Goal: {escape(goal)}")
    ui.info(f"Tools available: {', '.join(installed) or '(none installed!)'}")
    if not installed:
        ui.error("No exploit tools installed — run setup.bat first.")
        return []
    if not ui.confirm(f"[bold red]Start autonomous loop? (max {max_steps} steps)[/]",
                      default=False):
        ui.info("Aborted.")
        return []

    system = AGENT_SYSTEM.replace("{TOOLS}", ", ".join(installed)).replace("{HOST}", host)
    history    = []   # [{command, output}]
    transcript = []

    for step in range(1, max_steps + 1):
        ui.divider(f"STEP {step}/{max_steps}")
        hist_txt = "\n\n".join(f"$ {h['command']}\n{h['output'][:1500]}"
                               for h in history) or "(nothing run yet)"
        user = (f"TARGET: {target}\nHOST: {host}\nGOAL: {goal}\n\n"
                f"HISTORY:\n{hist_txt}\n\nDecide the next action as JSON.")

        try:
            with ui.spinner("Agent is thinking …"):
                raw = llm.ask_llm([{"role": "system", "content": system},
                                   {"role": "user", "content": user}])
        except Exception as e:
            ui.error(f"LLM error: {e}")
            break

        raw, _  = llm.strip_thinking(raw)
        action  = _parse_json(raw)
        if not action:
            ui.error("Could not parse the agent's decision. Stopping.")
            break

        thought = str(action.get("thought", "")).strip()
        if thought:
            ui.console.print(f"  [dim]* {escape(thought)}[/]")

        if str(action.get("action", "")).lower() == "done":
            concl = str(action.get("reason", "")).strip() or "(no conclusion given)"
            ui.success("Agent decided it is finished.")
            ui.console.print(Panel(escape(concl), title="[bold green]Conclusion[/]",
                                   border_style="green", padding=(1, 2)))
            transcript.append({"step": step, "done": True, "conclusion": concl})
            break

        tool    = str(action.get("tool", "")).lower().strip()
        command = str(action.get("command", "")).strip()
        reason  = str(action.get("reason", "")).strip()

        ui.console.print(f"  [bold]-> {escape(command)}[/]")
        if reason:
            ui.console.print(f"  [dim]{escape(reason)}[/]")

        if tool not in installed:
            msg = f"[blocked] tool '{tool}' not allowed or not installed."
            ui.warn(msg)
            history.append({"command": command, "output": msg})
            continue
        if not _command_in_scope(command, host):
            msg = f"[blocked] command references a host outside scope ({host})."
            ui.warn(msg)
            history.append({"command": command, "output": msg})
            continue
        if not ui.confirm("Run this command?", default=True):
            history.append({"command": command, "output": "[skipped by operator]"})
            continue

        with ui.spinner(f"Running {tool} …"):
            out = tools.run_suggested_exploit({"tool_used": tool, "payload": command}, target)
        ui.console.print(out[:1500] if out else "[dim](no output)[/]")
        history.append({"command": command, "output": out})
        transcript.append({"step": step, "command": command, "output": out[:2000]})
    else:
        ui.warn(f"Reached step limit ({max_steps}).")

    ui.console.print()
    return transcript
