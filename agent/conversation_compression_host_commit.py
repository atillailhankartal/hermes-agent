"""Publish a host's transcript under the same short fence as a durable compression commit."""

from __future__ import annotations

import contextlib
import logging
from typing import Any, Callable

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
