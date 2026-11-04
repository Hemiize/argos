#!/usr/bin/env python3
"""ARGOS — persistent settings manager."""

import json
import os
from config import BASE_DIR

SETTINGS_FILE = os.path.join(BASE_DIR, "settings.json")

# ── LLM Backends ────────────────────────────────────────────────────────────

BACKENDS = {
    "llama.cpp": {
        "type":    "llamacpp",
        "label":   "llama.cpp",
        "default": {"url": "http://localhost:8080", "model": "bench"},
    },
    "Ollama": {
        "type":    "ollama",
        "label":   "Ollama",
        "default": {"url": "http://localhost:11434", "model": "llama3"},
    },
}

BACKEND_KEYS = list(BACKENDS.keys())   # ["llama.cpp", "Ollama"]

# ── User Agents ─────────────────────────────────────────────────────────────

USER_AGENTS = {
    "Firefox 120 (Windows)": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Firefox 120 (Linux)":   "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Chrome 120 (Windows)":  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Chrome 120 (Linux)":    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Safari 17 (macOS)":     "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Edge 120 (Windows)":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Chrome (Android)":      "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Safari (iPhone)":       "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Googlebot 2.1":         "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "curl 8.4":              "curl/8.4.0",
    "Python requests":       "python-requests/2.33.1",
}

# ── Defaults ─────────────────────────────────────────────────────────────────

DEFAULTS = {
    "user_agent": "Firefox 120 (Windows)",
    "backend":    "llama.cpp",
    "llamacpp_url":   "http://localhost:8080",
    "llamacpp_model": "bench",
    "ollama_url":     "http://localhost:11434",
    "ollama_model":   "llama3",
    "show_thinking":  False,
}


# ── I/O ───────────────────────────────────────────────────────────────────────

def load() -> dict:
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, encoding="utf-8") as f:
                data = json.load(f)
            merged = DEFAULTS.copy()
            merged.update(data)
            return merged
        except Exception:
            pass
    return DEFAULTS.copy()


def save(s: dict):
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(s, f, indent=2)


# ── User-Agent helpers ────────────────────────────────────────────────────────

def get_user_agent() -> str:
    name = load().get("user_agent", "Firefox 120 (Windows)")
    return USER_AGENTS.get(name, USER_AGENTS["Firefox 120 (Windows)"])


def get_user_agent_name() -> str:
    return load().get("user_agent", "Firefox 120 (Windows)")


# ── Backend helpers ───────────────────────────────────────────────────────────

def get_backend_name() -> str:
    s = load()
    name = s.get("backend", "llama.cpp")
    return name if name in BACKENDS else "llama.cpp"


def get_backend_config() -> dict:
    s    = load()
    name = get_backend_name()
    cfg  = BACKENDS[name]

    if name == "llama.cpp":
        url   = s.get("llamacpp_url",   cfg["default"]["url"])
        model = s.get("llamacpp_model", cfg["default"]["model"])
        chat_url = url.rstrip("/") + "/v1/chat/completions"
    else:
        url   = s.get("ollama_url",   cfg["default"]["url"])
        model = s.get("ollama_model", cfg["default"]["model"])
        chat_url = url.rstrip("/") + "/api/chat"

    return {
        "type":     cfg["type"],
        "label":    cfg["label"],
        "url":      url,
        "model":    model,
        "chat_url": chat_url,
    }


def get_backend_health_url() -> str:
    s    = load()
    name = get_backend_name()
    if name == "llama.cpp":
        url = s.get("llamacpp_url", BACKENDS["llama.cpp"]["default"]["url"])
        return url.rstrip("/") + "/health"
    else:
        url = s.get("ollama_url", BACKENDS["Ollama"]["default"]["url"])
        return url.rstrip("/") + "/api/tags"
