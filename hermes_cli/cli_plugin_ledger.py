"""CLI selection over the shared durable candidate/status schema."""
from gateway.native_plugin_queue import NativePluginQueue


class CliPluginLedger(NativePluginQueue):
    def next_candidate(self, profile, epoch, owner):
        # A CLI owns one route. Earlier boots/epochs never block or replay into it.
        with self._connection() as db:
            row = db.execute("""SELECT * FROM candidates WHERE profile=? AND epoch=?
                AND owner=? AND execution='queued' ORDER BY sequence LIMIT 1""",
                (profile, epoch, owner)).fetchone()
        return dict(row) if row else None
