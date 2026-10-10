"""Durable Gateway-native candidates and their immutable admission receipts.

Admission is the SQLite commit of the *candidate*, including its prompt. Execution
is separate: a dispatch CAS is written before crossing into the adapter. An
interrupted dispatch is never replayed automatically (the turn may have started).
Rows are retained indefinitely: deleting a receipt would authorize a duplicate.
"""
from __future__ import annotations

import os
import hashlib
import sqlite3
import uuid
from contextlib import contextmanager
from pathlib import Path

from hermes_cli.plugins_injection import AdmissionReceipt


class NativePluginQueue:
    """One on-disk authoritative queue per Gateway session store."""

    def __init__(self, sessions_dir: Path):
        directory = sessions_dir / "native-plugin-admission"
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = directory / "candidates.sqlite3"
        fd = os.open(self.path, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
        with self._connection() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS candidates (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                profile TEXT NOT NULL, epoch TEXT NOT NULL, delivery TEXT NOT NULL,
                session_key TEXT NOT NULL, native_id TEXT NOT NULL, owner TEXT NOT NULL,
                plugin TEXT NOT NULL, content TEXT NOT NULL, payload_digest TEXT NOT NULL,
                candidate TEXT, state TEXT NOT NULL, reason TEXT NOT NULL,
                execution TEXT NOT NULL,
                UNIQUE(profile, epoch, delivery)
            )""")
        # SQLite FULL uses the platform VFS flush on every commit. POSIX additionally
        # allows synchronizing directory entries; Windows does not expose directory fsync.
        for parent in ((directory, sessions_dir) if os.name == "posix" else ()):
            directory_fd = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)

    @contextmanager
    def _connection(self):
        db = sqlite3.connect(self.path, timeout=1.0)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA synchronous=FULL")
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def receipt(row) -> AdmissionReceipt:
        return AdmissionReceipt(row["state"], row["reason"], row["delivery"],
                                row["epoch"], row["candidate"])

    def lookup(self, profile: str, epoch: str, delivery: str):
        with self._connection() as db:
            row = db.execute("SELECT * FROM candidates WHERE profile=? AND epoch=? AND delivery=?",
                             (profile, epoch, delivery)).fetchone()
            return dict(row) if row else None

    @staticmethod
    def payload_digest(content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    @staticmethod
    def conflict(row):
        return dict(row) | {"state": "unknown", "reason": "native_delivery_conflict", "candidate": None}

    def admit(self, *, profile: str, epoch: str, delivery: str, session_key: str,
              native_id: str, owner: str, plugin: str, content: str, cap: int = 100,
              rejection_reason: str | None = None):
        """Insert a distinct candidate and receipt in the same transaction, or read existing."""
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM candidates WHERE profile=? AND epoch=? AND delivery=?",
                             (profile, epoch, delivery)).fetchone()
            if row:
                if (row["session_key"] != session_key or row["native_id"] != native_id
                        or row["plugin"] != plugin or row["payload_digest"] != self.payload_digest(content)):
                    return self.conflict(row)
                return dict(row)
            depth = db.execute("""SELECT COUNT(*) FROM candidates WHERE profile=? AND session_key=?
                               AND execution='queued'""", (profile, session_key)).fetchone()[0]
            state, reason, candidate, execution = "admitted", "native_queue_committed", uuid.uuid4().hex, "queued"
            if rejection_reason or depth >= cap:
                state, reason, candidate, execution = ("rejected", rejection_reason or "native_queue_full",
                                                        None, "not_inserted")
            db.execute("""INSERT INTO candidates
                (profile, epoch, delivery, session_key, native_id, owner, plugin, content, payload_digest,
                 candidate, state, reason, execution) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (profile, epoch, delivery, session_key, native_id, owner, plugin,
                 content if candidate else "", self.payload_digest(content), candidate, state, reason, execution))
            row = db.execute("SELECT * FROM candidates WHERE profile=? AND epoch=? AND delivery=?",
                             (profile, epoch, delivery)).fetchone()
        # Return only after the context manager committed successfully.
        return dict(row)

    def queued(self):
        with self._connection() as db:
            return [dict(row) for row in db.execute(
                """SELECT * FROM candidates WHERE sequence IN (
                    SELECT MIN(sequence) FROM candidates WHERE execution='queued'
                    GROUP BY profile, session_key) ORDER BY sequence LIMIT 100""")]

    def transition(self, candidate: str, expected: str, execution: str) -> bool:
        with self._connection() as db:
            changed = db.execute("UPDATE candidates SET execution=? WHERE candidate=? AND execution=?",
                                 (execution, candidate, expected)).rowcount
        return changed == 1
