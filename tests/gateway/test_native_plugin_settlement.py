"""Settlement keeps the enrollment and one durable native event immutable."""
import pytest

from gateway.native_plugin_queue import NativePluginQueue
from hermes_cli.cli_plugin_ledger import CliPluginLedger


@pytest.mark.parametrize("queue_type", [NativePluginQueue, CliPluginLedger])
@pytest.mark.parametrize("before,after", [(None, "other"), ("enrolled", None), ("enrolled", "other")])
def test_enrollment_compare_and_set_rejects_interleaving(tmp_path, queue_type, before, after):
    queue = queue_type(tmp_path)
    row = queue.admit(profile="profile", epoch="epoch", delivery="delivery", session_key="key",
                      native_id="native", owner="owner", plugin="bee", content="payload")
    with queue._connection() as db:
        db.execute("UPDATE candidates SET enrollment_id=? WHERE candidate=?", (before, row["candidate"]))
    assert queue.transition(row["candidate"], "queued", "running")
    running = queue.lookup("profile", "epoch", "delivery")
    with queue._connection() as db:
        db.execute("UPDATE candidates SET enrollment_id=? WHERE candidate=?", (after, row["candidate"]))
    assert not queue.settle(running)
    recovered = queue_type(tmp_path).lookup("profile", "epoch", "delivery")
    assert recovered["state"] == "unknown" and recovered["native_event_id"] is None
    assert recovered["enrollment_id"] == after


@pytest.mark.parametrize("queue_type", [NativePluginQueue, CliPluginLedger])
def test_settlement_returns_exact_event_and_reopen_cannot_replace_it(tmp_path, queue_type):
    queue = queue_type(tmp_path)
    row = queue.admit(profile="profile", epoch="epoch", delivery="delivery", session_key="key",
                      native_id="native", owner="owner", plugin="bee", content="payload")
    assert queue.transition(row["candidate"], "queued", "running")
    running = queue.lookup("profile", "epoch", "delivery")
    event_id = queue.settle(running)
    restarted = queue_type(tmp_path)
    recovered = restarted.lookup("profile", "epoch", "delivery")
    assert isinstance(event_id, str) and event_id == recovered["native_event_id"]
    assert not restarted.settle(running)
    assert restarted.lookup("profile", "epoch", "delivery")["native_event_id"] == event_id
