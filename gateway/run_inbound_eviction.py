"""Stale Gateway turn eviction with route admission fencing."""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import suppress


logger = logging.getLogger("gateway.run")


class GatewayInboundEvictionMixin:
    async def _hm_evict_idle_stale_agent(self, _quick_key: str) -> None:
        """Evict an agent only after it has been idle past the timeout. Pending setup survives."""
        from gateway.run import _AGENT_PENDING_SENTINEL, _float_env
        _raw_stale_timeout = _float_env("HERMES_AGENT_TIMEOUT", 1800)
        _quick_state = self._peek_session_state(_quick_key)
        _stale_ts = _quick_state.turn.started_ts if _quick_state else 0
        if _quick_state is None or _quick_state.turn.agent is None or not _stale_ts:
            return
        _stale_age = time.time() - _stale_ts
        _stale_agent = _quick_state.turn.agent
        _stale_idle = float("inf")
        _stale_detail = ""
        _activity_summary_valid = False
        if _stale_agent and hasattr(_stale_agent, "get_activity_summary"):
            with suppress(Exception):
                _sa = _stale_agent.get_activity_summary()
                from gateway.session_stall import resolve_session_idle_seconds_from_activity

                _sa_d = _sa if isinstance(_sa, dict) else {}
                _resolved_idle = resolve_session_idle_seconds_from_activity(
                    _sa if isinstance(_sa, dict) else None, now=time.time(),
                )
                if _resolved_idle is not None:
                    _stale_idle = _resolved_idle
                    _activity_summary_valid = True
                _stale_detail = (
                    f" | last_activity={_sa_d.get('last_activity_desc', 'unknown')} "
                    f"({_stale_idle:.0f}s ago) "
                    f"| iteration={_sa_d.get('api_call_count', 0)}/{_sa_d.get('max_iterations', 0)}"
                )
        _wall_ttl = max(_raw_stale_timeout * 10, 7200) if _raw_stale_timeout > 0 else float("inf")
        _should_evict = _stale_agent is not _AGENT_PENDING_SENTINEL and (
            (_activity_summary_valid and _raw_stale_timeout > 0 and _stale_idle >= _raw_stale_timeout)
            or (not _activity_summary_valid and _stale_age > _wall_ttl)
        )
        if _should_evict:
            logger.warning(
                "Evicting stale _running_agents entry for %s "
                "(age: %.0fs, idle: %.0fs, timeout: %.0fs)%s",
                _quick_key, _stale_age, _stale_idle, _raw_stale_timeout, _stale_detail,
            )
            await self._hm_evict_running_agent(
                _quick_key, "stale_running_agent_eviction", expected_agent=_stale_agent,
            )

    async def _hm_evict_reaped_agent(self, _quick_key: str) -> None:
        """Evict a turn whose durable session was ended while the Gateway stayed alive."""
        try:
            _reap_store = getattr(self, "session_store", None)
            _reap_peek = getattr(_reap_store, "peek_session_id", None)
            _is_ended = getattr(_reap_store, "_is_session_ended_in_db", None)
            _reap_sid = await asyncio.to_thread(_reap_peek, _quick_key) if callable(_reap_peek) else None
            _ended = (await asyncio.to_thread(_is_ended, _reap_sid)
                      if isinstance(_reap_sid, str) and _reap_sid and callable(_is_ended) else False)
            if _ended is True:
                logger.warning(
                    "Evicting stale _running_agents entry for %s — "
                    "durable session %s is ended (reaped) in state.db; "
                    "healing routing on next message (#99106)", _quick_key, _reap_sid,
                )
                state = self._peek_session_state(_quick_key)
                await self._hm_evict_running_agent(
                    _quick_key, "reaped_session_eviction",
                    expected_agent=state.turn.agent if state else None,
                    expected_session_id=_reap_sid,
                )
        except Exception:
            logger.debug("reaped-session staleness check failed", exc_info=True)

    async def _hm_evict_running_agent(
        self, _quick_key: str, reason: str, *, expected_agent=None, expected_session_id=None,
    ) -> None:
        from gateway.run import _INTERRUPT_REASON_EVICTED, _INTERRUPT_TOOL_REASON_EVICTED
        async with self._session_route_gate(_quick_key):
            state = self._peek_session_state(_quick_key)
            if expected_agent is not None and (state is None or state.turn.agent is not expected_agent):
                return
            if expected_session_id is not None:
                current = await asyncio.to_thread(self.session_store.peek_session_id, _quick_key)
                if current != expected_session_id:
                    return
            _generation_at_interrupt = self._interrupt_running_turn(
                _quick_key, interrupt_reason=_INTERRUPT_REASON_EVICTED, invalidation_reason=reason,
                tool_reason=_INTERRUPT_TOOL_REASON_EVICTED)
            self._drop_turn_slot(_quick_key, run_generation=_generation_at_interrupt)
