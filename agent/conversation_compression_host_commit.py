"""Publish a host's transcript under the same short fence as a durable compression commit."""

from __future__ import annotations

import contextlib
import logging
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


def _commit_deferred_memory_session(agent: Any, messages: list, old_session_id: str | None) -> None:
    """Run possibly network-bound memory hooks after the durable host fence is released."""
    current_session_id = agent.session_id
    try:
        if old_session_id:
            # Provider rebinding runs after this callback; extraction belongs to the old session.
            agent.session_id = old_session_id
        try:
            agent.commit_memory_session(messages)
        except Exception:
            logger.debug("deferred compression memory commit failed", exc_info=True)
    finally:
        agent.session_id = current_session_id


def run_compaction_host_commit(
    commit_fn: Callable[[Any], Any], *, host_commit: Any, agent: Any, messages: list,
    prepare_fn: Callable[[], Any],
) -> Any:
    """Call core persistence then publish the host route before either ownership lock is freed."""
    prepared = prepare_fn() if host_commit is not None else None
    with host_commit if host_commit is not None else contextlib.nullcontext() as publication:
        outcome = commit_fn(prepared)
        if publication is not None and outcome.session_commit_succeeded:
            publication.publish(agent, outcome)
    if host_commit is not None and not outcome.session_commit_succeeded and outcome.refused_prompt is None:
        raise RuntimeError("Compression persistence failed before host publication")
    if host_commit is not None and outcome.session_commit_succeeded:
        _commit_deferred_memory_session(agent, messages, outcome.old_session_id)
    return outcome


def publish_rotated_with_host_commit(agent: Any, child_id: str, host_commit: Any, **kwargs) -> None:
    """Stage the registry route before SQLite COMMIT and settle uncertain COMMIT errors."""
    try:
        agent._session_db.publish_compression_child(
            **kwargs, **({"route_before_commit": host_commit.stage_route_before_sqlite_commit}
                       if host_commit is not None else {}))
    except Exception:
        if host_commit is None or not host_commit.reconcile_failed_rotation(agent, child_id):
            raise


def prepare_host_candidate(compressed: list, salvage: Callable[[list], tuple]) -> tuple:
    """Run anti-growth feedback outside the registry lock; it can emit host callbacks."""
    tagged_ids = {id(m) for m in compressed if isinstance(m, dict) and m.pop("_compaction_tail", None)}
    candidate, refused_prompt = salvage(compressed)
    return candidate, refused_prompt, tagged_ids


def held_archive_watermark(
    session_db: Any, session_id: str, watermark: Optional[int], messages: list, verbatim_tail: Optional[list] = None,
    *, stale_raises: bool = False,
) -> Optional[int]:
    """The in-place archive watermark, capped at the newest durable row the compressor was handed.

    The lease watermark is the newest row in state.db, but a surface compacts the history it holds, and that
    can be older: a Desktop/TUI or CLI ``/compress`` does not hold turns another surface appended to the same
    session since it loaded. Archived under the watermark, those rows would leave every surface's
    history and search, and the summary never saw them. Above the cap they take the concurrent-append path
    instead (cloned after the compacted set).

    Only while the held history is a live prefix of the session: its LAST row names an exact ``_row_id``, and
    that row is still active (after another surface compacted, the held rows are archived and every live row
    would be cloned beside the new summary). An id is exact while its dict is unchanged since it was loaded: a
    dict loaded from the DB is born carrying both the id and the persist marker, and a pass that rewrote its
    content drops the marker and keeps the id (the user/assistant merges in ``repair_message_sequence``, or a
    context engine that rewrites in place). Such a row absorbed later durable rows whose ids are gone from the
    held set, so its id no longer names what the summary covered: capped there, those rows would be cloned
    live beside a summary that already contains them. A trailing row of unknown provenance may be durable
    under the lease watermark without any stamp (the TUI model-switch marker, written with a bare
    ``append_message``); capped below it, the clone would land beside its own carried copy. A ``here N`` tail
    is marker-swept copies, so ``compress_now`` keeps a copy's id only when its source still carried the
    marker; their ids are trusted as given.

    *stale_raises*: the newest exact held row being inactive means another compaction already committed.
    Under the in-place lease that cannot overlap a live compaction, so the lease watermark is returned; a
    lease-less caller (prune, micro-compaction) passes ``True`` and gets :class:`StaleHeldHistory` instead,
    because for it the fallback would publish a stale generation beside the winner.
    """
    if watermark is None:
        return None
    from agent.context_compressor import _DB_PERSISTED_MARKER, StaleHeldHistory

    def _exact_id(m: dict, copied: bool) -> Optional[int]:
        rid = m.get("_row_id")
        if not isinstance(rid, int) or isinstance(rid, bool) or rid <= 0:
            return None
        return rid if copied or m.get(_DB_PERSISTED_MARKER) else None

    ids = [_exact_id(m, False) for m in messages if isinstance(m, dict)]
    ids += [_exact_id(m, True) for m in (verbatim_tail or ()) if isinstance(m, dict)]
    held = [rid for rid in ids if rid is not None]
    if not ids or ids[-1] is None:
        return watermark
    newest_held = max(held)
    # A lease-less caller checks liveness even when nothing was appended: a commit-time re-check against a
    # watermark read before the slow step never sees newest_held < watermark, yet the winner may have landed.
    if newest_held >= watermark and not stale_raises:
        return watermark
    if session_db.get_message_role(session_id, newest_held) is None:
        if stale_raises:
            raise StaleHeldHistory(f"held row {newest_held} of session {session_id} is no longer active")
        return watermark
    return min(newest_held, watermark)
