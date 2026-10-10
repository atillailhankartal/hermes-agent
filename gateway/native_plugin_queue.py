"""Durable Gateway-native candidates and their immutable admission receipts.

Candidates begin unknown; admission additionally requires the native slot and turn lease. Execution
is separate: a dispatch CAS is written before crossing into the adapter. An
interrupted dispatch is never replayed automatically (the turn may have started).
Rows are retained indefinitely: deleting a receipt would authorize a duplicate.
"""
from __future__ import annotations

import os
import hashlib
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from hermes_cli.plugins_injection import AdmissionReceipt


class NativePluginQueue:
    """One on-disk authoritative queue per Gateway session store."""

    def __init__(self, sessions_dir: Path):
        self._pre_model_grants = {}
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
                execution TEXT NOT NULL, enrollment_id TEXT, native_event_id TEXT,
                UNIQUE(profile, epoch, delivery)
            )""")
            columns = {row[1] for row in db.execute("PRAGMA table_info(candidates)")}
            for name in ("enrollment_id", "native_event_id"):
                if name not in columns:
                    db.execute(f"ALTER TABLE candidates ADD COLUMN {name} TEXT")
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
                                row["epoch"], row["candidate"] if row["state"] == "admitted" else None)

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

    def install_pre_model_grant(self, grant) -> bool:
        """Hold a broker reservation in host memory; never persist its capability."""
        from hermes_cli.trusted_inbound_broker import PreModelBrokerGrant
        if (type(grant) is not PreModelBrokerGrant or grant.surface not in ("cli", "gateway")
                or any(not isinstance(value, str) or not value.strip() for value in (
                    grant.delivery_id, grant.profile_home_key, grant.session_key, grant.native_session_id,
                    grant.host_owner_id, grant.route_epoch, grant.enrollment_id,
                    grant.reserved_candidate_id, grant.capability))
                or not isinstance(grant.payload_sha256, str)
                or len(grant.payload_sha256) != 64
                or any(character not in "0123456789abcdef" for character in grant.payload_sha256)
                or type(grant.expires_at_unix_ms) is not int
                or grant.expires_at_unix_ms <= int(time.time() * 1000)):
            return False
        key = (grant.profile_home_key, grant.route_epoch, grant.delivery_id)
        previous = self._pre_model_grants.get(key)
        if previous is not None and previous != grant:
            return False
        self._pre_model_grants[key] = grant
        return True

    def _queued_depth(self, db, *, profile, session_key, epoch, owner):
        return db.execute("""SELECT COUNT(*) FROM candidates WHERE profile=? AND session_key=?
                           AND execution='queued'""", (profile, session_key)).fetchone()[0]

    def admit(self, *, profile: str, epoch: str, delivery: str, session_key: str,
              native_id: str, owner: str, plugin: str, content: str, cap: int = 100,
              rejection_reason: str | None = None):
        """Insert a distinct candidate and receipt in the same transaction, or read existing."""
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM candidates WHERE profile=? AND epoch=? AND delivery=?",
                             (profile, epoch, delivery)).fetchone()
            grant = self._pre_model_grants.get((profile, epoch, delivery))
            if row:
                if (row["session_key"] != session_key or row["native_id"] != native_id
                        or row["plugin"] != plugin or row["payload_digest"] != self.payload_digest(content)
                        or (grant is not None and (row["candidate"] != grant.reserved_candidate_id
                                                   or row["enrollment_id"] != grant.enrollment_id))):
                    return self.conflict(row)
                return dict(row)
            if grant is not None:
                from hermes_cli.cli_plugin_ledger import CliPluginLedger
                surface = "cli" if isinstance(self, CliPluginLedger) else "gateway"
                if (grant.expires_at_unix_ms <= int(time.time() * 1000)
                        or not grant.matches(delivery=delivery, surface=surface,
                                             profile=profile, session_key=session_key,
                                             native_id=native_id, owner=owner, epoch=epoch,
                                             digest=self.payload_digest(content))):
                    rejection_reason = "broker_grant_conflict"
            depth = self._queued_depth(db, profile=profile, session_key=session_key,
                                       epoch=epoch, owner=owner)
            state, reason, candidate, execution = ("unknown", "native_queue_pending",
                                                   grant.reserved_candidate_id if grant else uuid.uuid4().hex,
                                                   "queued")
            if rejection_reason or depth >= cap:
                state, reason, candidate, execution = ("rejected", rejection_reason or "native_queue_full",
                                                        None, "not_inserted")
            db.execute("""INSERT INTO candidates
                (profile, epoch, delivery, session_key, native_id, owner, plugin, content, payload_digest,
                 candidate, state, reason, execution) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (profile, epoch, delivery, session_key, native_id, owner, plugin,
                 content if candidate else "", self.payload_digest(content), candidate, state, reason, execution))
            if candidate and grant is not None:
                db.execute("UPDATE candidates SET enrollment_id=? WHERE profile=? AND epoch=? AND delivery=?",
                           (grant.enrollment_id, profile, epoch, delivery))
            row = db.execute("SELECT * FROM candidates WHERE profile=? AND epoch=? AND delivery=?",
                             (profile, epoch, delivery)).fetchone()
        # Return only after the context manager committed successfully.
        return dict(row)

    def queued(self, after=0, through=None):
        # A fixed cycle boundary prevents new arrivals from postponing earlier busy heads.
        with self._connection() as db:
            rows = [dict(row) for row in db.execute(
                """SELECT * FROM candidates WHERE sequence IN (
                    SELECT MIN(sequence) FROM candidates WHERE execution='queued'
                    GROUP BY profile, session_key) AND sequence > ?
                    AND (? IS NULL OR sequence <= ?) ORDER BY sequence LIMIT 100""",
                (after, through, through))]
        return rows

    def next_queued_page(self):
        """Visit a finite snapshot of route heads before starting another scan cycle.

        New candidates wait for the next cycle. Previously busy heads are revisited
        after at most the remaining pages, even if arrivals continue on every poll.
        The cursor is only a wake-loop optimization; restart safely starts at zero.
        """
        after = getattr(self, "_scan_after", 0)
        through = getattr(self, "_scan_through", None)
        if through is None:
            with self._connection() as db:
                through = db.execute("SELECT COALESCE(MAX(sequence), 0) FROM candidates").fetchone()[0]
        rows = self.queued(after, through)
        if len(rows) < 100 or rows[-1]["sequence"] >= through:
            self._scan_after, self._scan_through = 0, None
        else:
            self._scan_after, self._scan_through = rows[-1]["sequence"], through
        return rows

    def settle(self, original: dict) -> bool:
        """Atomically settle only the exact candidate seen under the native turn lease."""
        fields = ("sequence", "profile", "epoch", "delivery", "session_key", "native_id",
                  "owner", "plugin", "content", "payload_digest", "candidate", "reason")
        where = " AND ".join(f"{field}=?" for field in fields)
        with self._connection() as db:
            changed = db.execute(
                "UPDATE candidates SET state='admitted', reason='native_turn_admitted', native_event_id=? "
                f"WHERE state='unknown' AND execution='running' AND {where}",
                (uuid.uuid4().hex, *(original[field] for field in fields)),
            ).rowcount
        return changed == 1

    def transition(self, candidate: str, expected: str, execution: str) -> bool:
        with self._connection() as db:
            changed = db.execute("UPDATE candidates SET execution=? WHERE candidate=? AND execution=?",
                                 (execution, candidate, expected)).rowcount
        return changed == 1
