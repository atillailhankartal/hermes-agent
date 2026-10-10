"""Lazy classic-CLI branding labels (keeps the widget facade bounded)."""

def _agent_name() -> str:
    try:
        from hermes_cli.skin_engine import get_active_skin
        return get_active_skin().get_branding("agent_name", "Hermes")
    except Exception:
        return "Hermes"
