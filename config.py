#!/usr/bin/env python3
"""
ARGOS config — edit to match your local LLM setup.
Backend is selected at runtime via settings.json (llama.cpp or Ollama).
"""
import os

APP_NAME  = "ARGOS"
BASE_DIR  = os.path.dirname(os.path.abspath(__file__))

# ── llama.cpp ──────────────────────────────────────────────────────────────
LLAMA_URL   = "http://localhost:8080/v1/chat/completions"
LLAMA_MODEL = "bench"        # model id as reported by /v1/models

# ── Ollama ─────────────────────────────────────────────────────────────────
OLLAMA_URL   = "http://localhost:11434/api/chat"
OLLAMA_MODEL = "llama3"      # e.g. llama3, mistral, gemma3, phi4 …

# ── SQLite database (auto-created) ─────────────────────────────────────────
DB_PATH = os.path.join(BASE_DIR, "argos.db")

# ── Report output directory ────────────────────────────────────────────────
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

# ── Timeouts (seconds) ─────────────────────────────────────────────────────
LLM_TIMEOUT       = 600
TOOL_TIMEOUT      = 180
DEEP_SCAN_TIMEOUT = 900
