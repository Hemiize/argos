#!/usr/bin/env python3
"""
ARGOS - db.py  (Windows / Linux — SQLite backend)
No server, no credentials, no setup. Database is argos.db in the project folder.
"""

import sqlite3
from datetime import datetime
from config import DB_PATH


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    _ensure_schema(conn)
    return conn


def _ensure_schema(conn: sqlite3.Connection):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS history (
            sl_no     INTEGER PRIMARY KEY AUTOINCREMENT,
            target    TEXT NOT NULL,
            scan_date TEXT NOT NULL,
            status    TEXT DEFAULT 'active'
        );

        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            sl_no       INTEGER,
            vuln_name   TEXT,
            severity    TEXT,
            port        TEXT,
            service     TEXT,
            description TEXT,
            FOREIGN KEY (sl_no) REFERENCES history(sl_no)
        );

        CREATE TABLE IF NOT EXISTS fixes (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            sl_no    INTEGER,
            vuln_id  INTEGER,
            fix_text TEXT,
            source   TEXT,
            FOREIGN KEY (sl_no)    REFERENCES history(sl_no),
            FOREIGN KEY (vuln_id)  REFERENCES vulnerabilities(id)
        );

        CREATE TABLE IF NOT EXISTS exploits_attempted (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            sl_no        INTEGER,
            exploit_name TEXT,
            tool_used    TEXT,
            payload      TEXT,
            result       TEXT,
            notes        TEXT,
            FOREIGN KEY (sl_no) REFERENCES history(sl_no)
        );

        CREATE TABLE IF NOT EXISTS summary (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            sl_no        INTEGER,
            raw_scan     TEXT,
            ai_analysis  TEXT,
            risk_level   TEXT,
            generated_at TEXT,
            FOREIGN KEY (sl_no) REFERENCES history(sl_no)
        );
    """)
    conn.commit()


def create_session(target: str) -> int:
    conn = get_connection()
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur  = conn.execute("INSERT INTO history (target, scan_date, status) VALUES (?, ?, ?)",
                        (target, now, "active"))
    conn.commit()
    sl_no = cur.lastrowid
    conn.close()
    return sl_no


def save_vulnerability(sl_no, vuln_name, severity, port, service, description) -> int:
    conn = get_connection()
    cur  = conn.execute(
        "INSERT INTO vulnerabilities (sl_no, vuln_name, severity, port, service, description) VALUES (?, ?, ?, ?, ?, ?)",
        (sl_no, vuln_name, severity, port, service, description))
    conn.commit()
    vid = cur.lastrowid
    conn.close()
    return vid


def save_fix(sl_no, vuln_id, fix_text, source="ai"):
    conn = get_connection()
    conn.execute("INSERT INTO fixes (sl_no, vuln_id, fix_text, source) VALUES (?, ?, ?, ?)",
                 (sl_no, vuln_id, fix_text, source))
    conn.commit()
    conn.close()


def save_exploit(sl_no, exploit_name, tool_used, payload, result, notes):
    conn = get_connection()
    conn.execute(
        "INSERT INTO exploits_attempted (sl_no, exploit_name, tool_used, payload, result, notes) VALUES (?, ?, ?, ?, ?, ?)",
        (sl_no, str(exploit_name or "")[:1000], str(tool_used or "")[:500],
         str(payload or ""), str(result or "")[:2000], str(notes or "")))
    conn.commit()
    conn.close()


def save_summary(sl_no, raw_scan, ai_analysis, risk_level):
    conn = get_connection()
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT INTO summary (sl_no, raw_scan, ai_analysis, risk_level, generated_at) VALUES (?, ?, ?, ?, ?)",
        (sl_no, raw_scan, ai_analysis, risk_level, now))
    conn.commit()
    conn.close()


def get_all_history():
    conn = get_connection()
    rows = conn.execute("SELECT sl_no, target, scan_date, status FROM history ORDER BY sl_no DESC").fetchall()
    conn.close()
    return rows


def get_session(sl_no: int) -> dict:
    conn = get_connection()
    history  = conn.execute("SELECT * FROM history WHERE sl_no = ?", (sl_no,)).fetchone()
    vulns    = conn.execute("SELECT * FROM vulnerabilities WHERE sl_no = ?", (sl_no,)).fetchall()
    fixes    = conn.execute("SELECT * FROM fixes WHERE sl_no = ?", (sl_no,)).fetchall()
    exploits = conn.execute("SELECT * FROM exploits_attempted WHERE sl_no = ?", (sl_no,)).fetchall()
    summary  = conn.execute("SELECT * FROM summary WHERE sl_no = ?", (sl_no,)).fetchone()
    conn.close()
    return {"history": history, "vulns": vulns, "fixes": fixes,
            "exploits": exploits, "summary": summary}


def get_vulnerabilities(sl_no):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM vulnerabilities WHERE sl_no = ?", (sl_no,)).fetchall()
    conn.close()
    return rows


def get_fixes(sl_no):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM fixes WHERE sl_no = ?", (sl_no,)).fetchall()
    conn.close()
    return rows


def get_exploits(sl_no):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM exploits_attempted WHERE sl_no = ?", (sl_no,)).fetchall()
    conn.close()
    return rows


def edit_vulnerability(vuln_id, field, value):
    allowed = {"vuln_name", "severity", "port", "service", "description"}
    if field not in allowed:
        return False
    conn = get_connection()
    conn.execute(f"UPDATE vulnerabilities SET {field} = ? WHERE id = ?", (value, vuln_id))
    conn.commit()
    conn.close()
    return True


def edit_fix(fix_id, fix_text):
    conn = get_connection()
    conn.execute("UPDATE fixes SET fix_text = ? WHERE id = ?", (fix_text, fix_id))
    conn.commit()
    conn.close()


def edit_exploit(exploit_id, field, value):
    allowed = {"exploit_name", "tool_used", "payload", "result", "notes"}
    if field not in allowed:
        return False
    conn = get_connection()
    conn.execute(f"UPDATE exploits_attempted SET {field} = ? WHERE id = ?", (value, exploit_id))
    conn.commit()
    conn.close()
    return True


def edit_summary_risk(sl_no, risk_level):
    conn = get_connection()
    conn.execute("UPDATE summary SET risk_level = ? WHERE sl_no = ?", (risk_level, sl_no))
    conn.commit()
    conn.close()


def delete_vulnerability(vuln_id):
    conn = get_connection()
    conn.execute("DELETE FROM fixes WHERE vuln_id = ?", (vuln_id,))
    conn.execute("DELETE FROM vulnerabilities WHERE id = ?", (vuln_id,))
    conn.commit()
    conn.close()


def delete_exploit(exploit_id):
    conn = get_connection()
    conn.execute("DELETE FROM exploits_attempted WHERE id = ?", (exploit_id,))
    conn.commit()
    conn.close()


def delete_fix(fix_id):
    conn = get_connection()
    conn.execute("DELETE FROM fixes WHERE id = ?", (fix_id,))
    conn.commit()
    conn.close()


def delete_full_session(sl_no):
    conn = get_connection()
    conn.execute("DELETE FROM fixes WHERE sl_no = ?", (sl_no,))
    conn.execute("DELETE FROM exploits_attempted WHERE sl_no = ?", (sl_no,))
    conn.execute("DELETE FROM vulnerabilities WHERE sl_no = ?", (sl_no,))
    conn.execute("DELETE FROM summary WHERE sl_no = ?", (sl_no,))
    conn.execute("DELETE FROM history WHERE sl_no = ?", (sl_no,))
    conn.commit()
    conn.close()


def print_history(rows):
    print("\n" + "─"*65)
    print(f"{'SL#':<6} {'TARGET':<28} {'DATE':<22} {'STATUS'}")
    print("─"*65)
    for row in rows:
        print(f"{row[0]:<6} {row[1]:<28} {str(row[2]):<22} {row[3]}")
    print()


def print_session(data: dict):
    h = data["history"]
    print(f"\n{'='*60}")
    print(f"  SL# {h[0]} | Target: {h[1]} | {h[2]} | {h[3]}")
    print(f"{'='*60}")
    print("\n[ VULNERABILITIES ]")
    if data["vulns"]:
        for v in data["vulns"]:
            print(f"  id={v[0]} | {v[2]} | Severity: {v[3]} | Port: {v[4]} | Service: {v[5]}")
            print(f"           {v[6]}")
    else:
        print("  None recorded.")
    print("\n[ FIXES ]")
    if data["fixes"]:
        for f in data["fixes"]:
            print(f"  id={f[0]} | vuln_id={f[2]} | [{f[4]}] {f[3]}")
    else:
        print("  None recorded.")
    print("\n[ EXPLOITS ATTEMPTED ]")
    if data["exploits"]:
        for e in data["exploits"]:
            print(f"  id={e[0]} | {e[2]} | Tool: {e[3]} | Result: {e[5]}")
            print(f"           Payload: {e[4]}")
            print(f"           Notes:   {e[6]}")
    else:
        print("  None recorded.")
    print("\n[ SUMMARY ]")
    if data["summary"]:
        s = data["summary"]
        print(f"  Risk Level : {s[4]}")
        print(f"  Generated  : {s[5]}")
        print(f"\n  AI Analysis:\n  {s[3][:500]}{'...' if len(str(s[3])) > 500 else ''}")
    else:
        print("  None recorded.")
    print()


def diff_sessions(sl_a: int, sl_b: int) -> dict:
    def _vuln_map(sl_no):
        rows = get_vulnerabilities(sl_no)
        return {(r[2] or "").lower(): {"vuln_name": r[2], "severity": (r[3] or "unknown").lower()}
                for r in rows}

    a = _vuln_map(sl_a)
    b = _vuln_map(sl_b)

    new_    = [b[k] for k in b if k not in a]
    fixed_  = [a[k] for k in a if k not in b]
    changed = []
    same    = []
    for k in a:
        if k in b:
            if a[k]["severity"] != b[k]["severity"]:
                changed.append({
                    "vuln_name": a[k]["vuln_name"],
                    "old_sev":   a[k]["severity"],
                    "new_sev":   b[k]["severity"],
                })
            else:
                same.append(a[k])

    return {"new": new_, "fixed": fixed_, "changed": changed, "same": same}


if __name__ == "__main__":
    try:
        conn = get_connection()
        print(f"[+] SQLite database OK: {DB_PATH}")
        conn.close()
    except Exception as e:
        print(f"[!] Database error: {e}")
