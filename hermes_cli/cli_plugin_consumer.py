"""Consume durable CLI candidates without parsing commands or merging input."""


def _eligible(host, row):
    claim = host.claim()
    loaded = host.manager._plugins.get(row["plugin"])
    registered = host.manager._admission_hosts.get("cli")
    return (claim is not None and row["epoch"] == claim.route_epoch
            and row["native_id"] == claim.native_session_id and row["owner"] == host.owner
            and row["profile"] == host.profile and loaded is not None
            and loaded.enabled and not loaded.error and registered is not None
            and registered[0] is host)


def drain_one(host, run_turn=None):
    cli = host.cli
    with host.lock, host.manager._admission_host_lock:
        if host.closed or host.blocked or host.active_turn is not None or getattr(cli, "_agent_running", False):
            return False
        row = None
        while candidate := host.queue.next_candidate(host.profile, host.epoch, host.owner):
            if not _eligible(host, candidate):
                host.queue.transition(candidate["candidate"], "queued", "stale_route")
                continue
            if host.queue.transition(candidate["candidate"], "queued", "dispatching"):
                row = candidate
                break
        if row is None:
            return False
        host.candidate = row
        cli._agent_running = True
    try:
        from hermes_cli.cli_plugin_turn import candidate_scope
        with candidate_scope(row):
            (run_turn or cli.chat)(row["content"])
    finally:
        with host.lock:
            try:
                host.queue.transition(row["candidate"], "running", "handler_returned")
                host.queue.transition(row["candidate"], "dispatching", "execution_unknown")
            finally:
                host.candidate = None
                cli._agent_running = False
    return True
