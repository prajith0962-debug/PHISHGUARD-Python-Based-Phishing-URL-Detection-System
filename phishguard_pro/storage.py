"""
PhishGuard Pro - scan history (SQLite, part of the Python standard library)
"""

import contextlib
import json
import os
import sqlite3
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB = os.path.join(HERE, "history.db")


@contextlib.contextmanager
def _connect(path):
    """Open the database, commit on success, ALWAYS close."""
    con = sqlite3.connect(path or DEFAULT_DB)
    try:
        _init(con)
        with con:
            yield con
    finally:
        con.close()


def _init(con):
    con.execute(
        "CREATE TABLE IF NOT EXISTS scans ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, kind TEXT, input TEXT, "
        "verdict TEXT, score INTEGER, reasons TEXT)"
    )


def add_scan(kind: str, text: str, verdict: str, score: int, reasons, path=None) -> None:
    with _connect(path) as con:
        con.execute(
            "INSERT INTO scans (ts, kind, input, verdict, score, reasons) VALUES (?,?,?,?,?,?)",
            (time.strftime("%Y-%m-%d %H:%M:%S"), kind, text[:500], verdict, int(score), json.dumps(reasons)),
        )


def recent(limit: int = 200, path=None):
    with _connect(path) as con:
        return con.execute(
            "SELECT ts, kind, input, verdict, score FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()


def stats(path=None) -> dict:
    with _connect(path) as con:
        rows = con.execute("SELECT verdict, COUNT(*) FROM scans GROUP BY verdict").fetchall()
    out = {"Looks Safe": 0, "Suspicious": 0, "Likely Phishing": 0}
    out.update(dict(rows))
    out["total"] = sum(out.values())
    return out


def clear(path=None) -> None:
    with _connect(path) as con:
        con.execute("DELETE FROM scans")
