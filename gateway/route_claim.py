"""Private host-issued identity for a Gateway conversation route."""

import secrets
import logging
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator, Optional

from hermes_constants import get_hermes_home, hermes_home_key

logger = logging.getLogger(__name__)


def new_route_epoch() -> str:
    """Mint an opaque epoch; native session IDs may later be reused by /resume."""
    return secrets.token_urlsafe(24)


@dataclass(frozen=True, eq=False)
class RouteClaim:
    """Snapshot issued by the current Gateway owner, never supplied by model arguments."""

    surface: str
    profile_home_key: str
    session_key: str
    native_session_id: str
    route_epoch: str
    host_owner_id: str
    _proof: object = field(repr=False, compare=False)
    _validate: Callable[["RouteClaim"], bool] = field(repr=False, compare=False)
    _validate_route: Callable[["RouteClaim"], bool] = field(repr=False, compare=False)

    def is_current(
        self, *, profile_home_key: Optional[str] = None, session_key: Optional[str] = None,
        native_session_id: Optional[str] = None,
    ) -> bool:
        """Check the exact issued proof against live host route, owner and turn lease."""
        if (profile_home_key is not None and profile_home_key != self.profile_home_key
                or session_key is not None and session_key != self.session_key
                or native_session_id is not None and native_session_id != self.native_session_id):
            return False
        return self._validate(self)

    def is_route_current(self) -> bool:
        """Validate a delayed delivery binding after its issuing turn lease has ended.

        This does not grant admission; the host must acquire a fresh lease/slot and settle an
        exact delivery receipt under its own route gate. Never use this as a tool join check.
        """
        return self._validate_route(self)


@dataclass(frozen=True)
class _BoundGatewayRoute:
    runner: Any
    session_key: str
    run_generation: int
    profile_home_key: str
    profile_matches: bool
    agent_holder: Any = None


_BOUND_ROUTE: ContextVar[Optional[_BoundGatewayRoute]] = ContextVar("gateway_host_route", default=None)


@contextmanager
def gateway_route_scope(
    runner: Any, session_key: str, run_generation: int, source: Any, *, agent_holder: Any = None,
) -> Iterator[None]:
    """Bind private host authority only for one executor turn and its copied tool contexts."""
    actual_home = hermes_home_key(get_hermes_home())
    try:
        expected_home = hermes_home_key(runner._resolve_profile_home_for_source(source))
    except Exception:
        logger.debug("Gateway route profile resolution failed", exc_info=True)
        expected_home = ""
    token = _BOUND_ROUTE.set(_BoundGatewayRoute(
        runner, session_key, run_generation, actual_home, actual_home == expected_home, agent_holder,
    ))
    try:
        yield
    finally:
        _BOUND_ROUTE.reset(token)


def gateway_route_bound() -> bool:
    """Distinguish a denied Gateway claim from a CLI tool with no Gateway route."""
    return _BOUND_ROUTE.get() is not None


def claim_for_route(runner: Any, entry: Any, source: Any) -> Optional[RouteClaim]:
    """Issue an observation-only binding for a published lifecycle route.

    It can validate a delayed route snapshot, but cannot join tools or admit delivery by itself.
    """
    store = runner.session_store
    try:
        home = hermes_home_key(runner._resolve_profile_home_for_source(source))
    except Exception:
        logger.debug("Gateway lifecycle route profile resolution failed", exc_info=True)
        return None
    key, native_id, epoch = entry.session_key, entry.session_id, entry.route_epoch
    owner, proof = store._route_owner_id, store._route_claim_proof
    if not home or not key or not native_id or not epoch:
        return None

    def validate_route(claim: RouteClaim) -> bool:
        if (getattr(store, "_route_owner_retired", False) or claim._proof is not proof
                or claim.surface != "gateway" or claim.profile_home_key != home
                or claim.session_key != key or claim.native_session_id != native_id
                or claim.route_epoch != epoch or claim.host_owner_id != owner):
            return False
        with store._lock:
            current = store._entry_locked(key)
            return bool(current and current.session_id == native_id and current.route_epoch == epoch
                        and not current.route_claim_blocked and store._route_owner_id == owner
                        and store._route_claim_proof is proof)

    return RouteClaim("gateway", home, key, native_id, epoch, owner, proof,
                      lambda _claim: False, validate_route)


def claim_for_tool(native_session_id: str) -> Optional[RouteClaim]:
    """Issue a fresh claim for the *actual* tool-call native ID, only with its held turn lease."""
    bound = _BOUND_ROUTE.get()
    if bound is None or not bound.profile_matches or not native_session_id or not bound.session_key:
        return None
    runner, key, generation = bound.runner, bound.session_key, bound.run_generation
    store = runner.session_store

    def compacted_in_place() -> bool:
        holder = bound.agent_holder
        agent = holder[0] if holder else None
        return bool(agent and getattr(agent, "_last_compaction_in_place", False))

    def owns_turn() -> bool:
        if not runner._is_session_run_current(key, generation):
            return False
        held = runner._held_turn_lease(key, generation)
        if held is None:
            return False
        token = held[1].get(generation)
        return bool(token and not token.released and token.lease.holder is token
                    and token.session_id == native_session_id)

    if getattr(store, "_route_owner_retired", False) or compacted_in_place() or not owns_turn():
        return None
    held = runner._held_turn_lease(key, generation)
    if held is None or generation not in held[1]:
        return None
    token = held[1][generation]
    if not store._reopen_route_claim_with_lease(key, native_session_id, token):
        return None
    with store._lock:
        entry = store._entry_locked(key)
        if entry is None or entry.session_id != native_session_id or entry.route_claim_blocked:
            return None
        if not entry.route_epoch:
            # Legacy routing rows predate epochs. Persist a candidate before making any proof
            # available; failure leaves the row and all Bee ingress closed.
            candidate = entry.to_dict()
            candidate["route_epoch"] = new_route_epoch()
            store._save_entry(key, entry_data=candidate, lock_held=True)
            entry.route_epoch = candidate["route_epoch"]
        epoch = entry.route_epoch
        owner, proof = store._route_owner_id, store._route_claim_proof
    if not owns_turn():
        return None

    def validate_route(claim: RouteClaim) -> bool:
        if (getattr(store, "_route_owner_retired", False) or compacted_in_place()
                or claim._proof is not proof):
            return False
        if (claim.surface != "gateway" or claim.profile_home_key != bound.profile_home_key
                or claim.session_key != key or claim.native_session_id != native_session_id
                or claim.route_epoch != epoch or claim.host_owner_id != owner):
            return False
        with store._lock:
            current = store._entry_locked(key)
            valid = bool(current and current.session_id == native_session_id
                         and current.route_epoch == epoch
                         and not current.route_claim_blocked
                         and store._route_owner_id == owner
                         and store._route_claim_proof is proof)
        return valid

    def validate(claim: RouteClaim) -> bool:
        return owns_turn() and validate_route(claim) and owns_turn()

    return RouteClaim("gateway", bound.profile_home_key, key, native_session_id, epoch,
                      owner, proof, validate, validate_route)
