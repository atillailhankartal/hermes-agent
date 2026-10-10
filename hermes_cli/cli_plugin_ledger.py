"""CLI selection over the shared durable candidate/status schema."""
from gateway.native_plugin_queue import NativePluginQueue


class CliPluginLedger(NativePluginQueue):
    def _queued_depth(self, db, *, profile, session_key, epoch, owner):
        # Count only selectable work, inside the parent's insertion transaction.
        # Historical receipts remain durable but can never run in this incarnation.
        return db.execute("""SELECT COUNT(*) FROM candidates WHERE profile=? AND session_key=?
            AND epoch=? AND owner=? AND execution='queued'""",
            (profile, session_key, epoch, owner)).fetchone()[0]

    def next_candidate(self, profile, epoch, owner):
        # A CLI owns one route. Earlier boots/epochs never block or replay into it.
        with self._connection() as db:
            row = db.execute("""SELECT * FROM candidates WHERE profile=? AND epoch=?
                AND owner=? AND execution='queued' ORDER BY sequence LIMIT 1""",
                (profile, epoch, owner)).fetchone()
        return dict(row) if row else None
