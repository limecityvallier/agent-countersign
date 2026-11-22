"""SQLite store for the audit trail and the approval queue.

The audit trail is append-only and hash-chained: every event records the hash
of the event before it, so editing or deleting any past event breaks the chain
and ``verify_chain`` reports exactly where.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    agent       TEXT NOT NULL,
    tool        TEXT NOT NULL,
    args        TEXT NOT NULL,
    event       TEXT NOT NULL,      -- decided | executed | failed | approved | denied
    decision    TEXT,
    rule        TEXT,
    detail      TEXT,
    actor       TEXT,
    approval_id INTEGER,
    cost_usd    REAL NOT NULL DEFAULT 0,
    prev_hash   TEXT NOT NULL,
    hash        TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created     TEXT NOT NULL,
    agent       TEXT NOT NULL,
    tool        TEXT NOT NULL,
    args        TEXT NOT NULL,      -- full arguments, needed to execute later
    rule        TEXT NOT NULL,
    approvers   TEXT NOT NULL,
    status      TEXT NOT NULL,      -- pending | approved | denied | executed
    decided_by  TEXT,
    decided_at  TEXT,
    note        TEXT
);
"""

_HASHED_FIELDS = ("ts", "agent", "tool", "args", "event", "decision", "rule",
                  "detail", "actor", "approval_id", "cost_usd", "prev_hash")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _hash(row: dict[str, Any]) -> str:
    payload = json.dumps({k: row.get(k) for k in _HASHED_FIELDS}, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


@dataclass
class Approval:
    id: int
    created: str
    agent: str
    tool: str
    args: dict[str, Any]
    rule: str
    approvers: list[str]
    status: str
    decided_by: str | None
    decided_at: str | None
    note: str | None


class Store:
    def __init__(self, path: str | Path = "countersign.db"):
        self.path = str(path)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(_SCHEMA)
        self._db.commit()

    # ---- audit ---------------------------------------------------------

    def log(self, *, agent: str, tool: str, args: dict[str, Any], event: str,
            decision: str | None = None, rule: str | None = None, detail: str | None = None,
            actor: str | None = None, approval_id: int | None = None,
            cost_usd: float = 0.0) -> int:
        with self._lock:
            last = self._db.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
            row = {
                "ts": _now(), "agent": agent, "tool": tool,
                "args": json.dumps(args, sort_keys=True, default=str),
                "event": event, "decision": decision, "rule": rule, "detail": detail,
                "actor": actor, "approval_id": approval_id, "cost_usd": float(cost_usd),
                "prev_hash": last["hash"] if last else GENESIS,
            }
            row["hash"] = _hash(row)
            cols = ", ".join(row)
            marks = ", ".join("?" for _ in row)
            cur = self._db.execute(f"INSERT INTO audit ({cols}) VALUES ({marks})", list(row.values()))
            self._db.commit()
            return int(cur.lastrowid)

    def events(self, limit: int | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM audit ORDER BY id"
        rows = self._db.execute(sql).fetchall()
        out = [dict(r) for r in rows]
        return out[-limit:] if limit else out

    def verify_chain(self) -> tuple[bool, int | None]:
        """Return (ok, first_bad_event_id)."""
        prev = GENESIS
        for row in self.events():
            if row["prev_hash"] != prev or _hash(row) != row["hash"]:
                return False, row["id"]
            prev = row["hash"]
        return True, None

    def spend_today(self, agent: str) -> float:
        today = datetime.now(timezone.utc).date().isoformat()
        r = self._db.execute(
            "SELECT COALESCE(SUM(cost_usd), 0) AS s FROM audit "
            "WHERE agent = ? AND event = 'executed' AND substr(ts, 1, 10) = ?",
            (agent, today)).fetchone()
        return float(r["s"])

    # ---- approvals -----------------------------------------------------

    def create_approval(self, *, agent: str, tool: str, args: dict[str, Any], rule: str,
                        approvers: list[str]) -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO approvals (created, agent, tool, args, rule, approvers, status) "
                "VALUES (?, ?, ?, ?, ?, ?, 'pending')",
                (_now(), agent, tool, json.dumps(args, default=str), rule, json.dumps(approvers)))
            self._db.commit()
            return int(cur.lastrowid)

    def get_approval(self, approval_id: int) -> Approval | None:
        r = self._db.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        return _to_approval(r) if r else None

    def list_approvals(self, status: str | None = "pending") -> list[Approval]:
        if status:
            rows = self._db.execute("SELECT * FROM approvals WHERE status = ? ORDER BY id", (status,))
        else:
            rows = self._db.execute("SELECT * FROM approvals ORDER BY id")
        return [_to_approval(r) for r in rows.fetchall()]

    def set_approval_status(self, approval_id: int, status: str, *, by: str | None = None,
                            note: str | None = None) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE approvals SET status = ?, decided_by = COALESCE(?, decided_by), "
                "decided_at = CASE WHEN ? IS NULL THEN decided_at ELSE ? END, "
                "note = COALESCE(?, note) WHERE id = ?",
                (status, by, by, _now(), note, approval_id))
            self._db.commit()


def _to_approval(r: sqlite3.Row) -> Approval:
    return Approval(
        id=r["id"], created=r["created"], agent=r["agent"], tool=r["tool"],
        args=json.loads(r["args"]), rule=r["rule"], approvers=json.loads(r["approvers"]),
        status=r["status"], decided_by=r["decided_by"], decided_at=r["decided_at"], note=r["note"])
