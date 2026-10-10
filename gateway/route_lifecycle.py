"""Host-owned, epoch-keyed Gateway lifecycle notifications."""

import asyncio
import logging

from gateway.route_claim import claim_for_route

logger = logging.getLogger("gateway.run")


def route_lifecycle_payload(runner, entry, source) -> dict:
    """Capture one route epoch; a delayed observer can test that exact publication."""
    store = runner.session_store
    key, native_id, epoch = entry.session_key, entry.session_id, entry.route_epoch
    claim = claim_for_route(runner, entry, source)

    return {
        "surface": "gateway", "profile_home_key": claim.profile_home_key if claim else "", "session_key": key,
        "session_id": native_id, "native_session_id": native_id,
        "route_epoch": epoch, "host_owner_id": store._route_owner_id,
        "route_claim": claim, "route_is_current": claim.is_route_current if claim else lambda: False,
        "platform": source.platform.value if source and source.platform else "",
    }


async def emit_route_lifecycle(runner, hook_name: str, payload: dict) -> None:
    """Invoke plugin observers off-loop; route guards survive timeout and delayed completion."""
    def call() -> None:
        from hermes_cli.lifecycle import invoke_hook
        invoke_hook(hook_name, **payload)

    try:
        await asyncio.wait_for(
            runner._run_housekeeping_in_executor(
                runner._run_release_in_profile_scope, call, (), payload["session_key"],
            ),
            timeout=runner._FINALIZE_TIMEOUT_S,
        )
    except asyncio.TimeoutError:
        logger.warning("Gateway %s hook exceeded %ss for route %s", hook_name,
                       runner._FINALIZE_TIMEOUT_S, payload["session_key"])
    except Exception:
        logger.warning("Gateway %s hook failed for route %s", hook_name,
                       payload["session_key"], exc_info=True)
