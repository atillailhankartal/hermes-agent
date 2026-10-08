"""Process-isolated real SessionStore probe for strict hygiene commit admission.

The parent test kills this process on a lock recursion, so a failing regression
cannot leave a blocked executor thread in the test runner.
"""

import asyncio
from datetime import datetime
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from threading import Event
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from gateway.config import GatewayConfig
from gateway.run import GatewayRunner
from gateway.session import SessionEntry, SessionStore


async def probe(reset_before_commit: bool) -> None:
    with TemporaryDirectory() as root:
        store = SessionStore(Path(root) / "sessions", GatewayConfig())
        store.close_all_db_handles()
        store._db = None
        entry = SessionEntry(
            session_key="route", session_id="old", created_at=datetime.now(),
            updated_at=datetime.now(),
        )
        store._entries["route"] = entry
        store._loaded = True
        runner = object.__new__(GatewayRunner)
        runner.session_store = store
        runner._is_session_run_current = MagicMock(return_value=True)
        entered, release = Event(), Event()
        admitted = []

        def compress(*_args, commit_fence, **_kwargs):
            entered.set()
            assert release.wait(5)
            accepted = commit_fence.begin_commit()
            admitted.append(accepted)
            if accepted:
                commit_fence.finish_commit()
            return [], None

        agent = SimpleNamespace(
            context_compressor=SimpleNamespace(bind_session_state=lambda *_: None),
            _compress_context=compress,
        )
        runner._hmwa_hygiene_build_agent = AsyncMock(return_value=(agent, None))

        async def wait_summary(attempt, *_):
            return (await attempt.future)[0]

        runner._hmwa_hygiene_wait_for_summary = AsyncMock(side_effect=wait_summary)
        runner._hmwa_hygiene_apply_result = AsyncMock(return_value=True)
        runner._evict_cached_agent = MagicMock()
        runner._cleanup_agent_resources_off_loop = AsyncMock()
        attempt = SimpleNamespace(agent=None, cleanup_deferred=False, history=[])
        event = SimpleNamespace(metadata={
            "gateway_session_strict": True, "gateway_session_key": "route",
            "gateway_session_id": "old",
        })
        task = asyncio.create_task(runner._hmwa_hygiene_detached_attempt(
            attempt, SimpleNamespace(total_ceiling_seconds=30),
            SimpleNamespace(approx_tokens=10), [], [], None, {}, None,
            entry, "route", "route", 1, strict_event=event,
        ))
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            if reset_before_commit:
                store.reset_session("route")
            release.set()
            await asyncio.wait_for(task, 4)
            assert admitted == [not reset_before_commit]
            if reset_before_commit:
                runner._hmwa_hygiene_apply_result.assert_not_awaited()
                runner._evict_cached_agent.assert_not_called()
            else:
                runner._hmwa_hygiene_apply_result.assert_awaited_once()
                runner._evict_cached_agent.assert_called_once_with("route")
        finally:
            release.set()


if __name__ == "__main__":
    asyncio.run(probe(sys.argv[1] == "reset"))
