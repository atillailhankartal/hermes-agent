"""Mutation controls for the repository's self-hosted runner gate."""

import json
import shutil
from pathlib import Path

import yaml

from scripts.ci.selfhosted_workflow_policy import UniqueBaseLoader, check, topology_digest


REPOSITORY = Path(__file__).resolve().parents[2]


def real_tree(tmp_path: Path):
    shutil.copytree(REPOSITORY / ".github" / "workflows", tmp_path / ".github" / "workflows")
    manifest = json.loads((REPOSITORY / "scripts" / "ci" / "selfhosted_workflow_manifest.json").read_text())
    return tmp_path / ".github" / "workflows", manifest


def mutate(workflow: Path, before: str, after: str):
    original = workflow.read_text()
    changed = original.replace(before, after, 1)
    assert changed != original
    workflow.write_text(changed)


def refresh_digest(manifest: dict, workflow: Path):
    document = yaml.load(workflow.read_text(), Loader=UniqueBaseLoader)
    manifest["workflows"][workflow.name] = topology_digest(document)


def test_actual_repository_passes_pinned_policy():
    manifest = json.loads((REPOSITORY / "scripts" / "ci" / "selfhosted_workflow_manifest.json").read_text())
    assert check(REPOSITORY, manifest) == []


def test_hosted_runner_mutation_makes_policy_red(tmp_path):
    workflows, manifest = real_tree(tmp_path)
    mutate(workflows / "ci.yaml", "runs-on: [self-hosted, Linux, X64, hermes-ci]", "runs-on: ubuntu-latest")
    assert any("self-hosted" in issue for issue in check(tmp_path, manifest))


def test_removed_arm64_matrix_row_makes_coverage_red(tmp_path):
    workflows, manifest = real_tree(tmp_path)
    mutate(workflows / "windows-bundle-sdk.yml",
           "runner: [hermes-windows-x64, hermes-windows-arm64]", "runner: [hermes-windows-x64]")
    assert any("matrix coverage" in issue for issue in check(tmp_path, manifest))


def test_replaced_arm64_matrix_row_makes_coverage_red(tmp_path):
    workflows, manifest = real_tree(tmp_path)
    mutate(workflows / "windows-bundle-sdk.yml",
           "runner: [hermes-windows-x64, hermes-windows-arm64]",
           "runner: [hermes-windows-x64, hermes-windows-x64]")
    assert any("matrix coverage" in issue for issue in check(tmp_path, manifest))


def test_new_workflow_and_new_event_fail_closed(tmp_path):
    workflows, manifest = real_tree(tmp_path)
    (workflows / "extra.yml").write_text("on:\n  push:\njobs:\n  test:\n    runs-on: ubuntu-latest\n")
    assert any("workflow file set changed" in issue for issue in check(tmp_path, manifest))
    (workflows / "extra.yml").unlink()
    mutate(workflows / "ci.yaml", "  pull_request:\n  push:", "  pull_request:\n  issues:\n  push:")
    assert any("event/job/condition" in issue for issue in check(tmp_path, manifest))


def test_external_reusable_is_rejected(tmp_path):
    workflows, manifest = real_tree(tmp_path)
    mutate(workflows / "install-e2e-macos-run.yml",
           "uses: ./.github/workflows/install-e2e-run.yml",
           "uses: owner/repo/.github/workflows/install-e2e-run.yml@main")
    assert any("external or unpinned" in issue for issue in check(tmp_path, manifest))


def test_actual_macos_caller_cannot_reroute_to_linux(tmp_path):
    workflows, manifest = real_tree(tmp_path)
    mutate(workflows / "install-e2e-macos-run.yml", "runner: hermes-macos-arm64", "runner: hermes-linux-x64")
    assert check(tmp_path, manifest)


def test_actual_macos_caller_cannot_switch_reusable_target(tmp_path):
    workflows, manifest = real_tree(tmp_path)
    mutate(workflows / "install-e2e-macos-run.yml",
           "uses: ./.github/workflows/install-e2e-run.yml",
           "uses: ./.github/workflows/install-e2e-windows-run.yml")
    assert check(tmp_path, manifest)


def test_unapproved_caller_runner_is_rejected_even_when_digest_is_refreshed(tmp_path):
    workflows, manifest = real_tree(tmp_path)
    caller = workflows / "install-e2e-macos-run.yml"
    mutate(caller, "runner: hermes-macos-arm64", "runner: ubuntu-latest")
    refresh_digest(manifest, caller)
    assert any("caller runner" in issue for issue in check(tmp_path, manifest))


def test_macos_caller_cannot_use_approved_linux_runner_with_refreshed_digest(tmp_path):
    workflows, manifest = real_tree(tmp_path)
    caller = workflows / "install-e2e-macos-run.yml"
    mutate(caller, "runner: hermes-macos-arm64", "runner: hermes-linux-x64")
    refresh_digest(manifest, caller)
    assert any("caller runner changed" in issue for issue in check(tmp_path, manifest))


def test_empty_workflow_set_and_empty_manifest_fail_closed(tmp_path):
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    assert check(tmp_path, {"workflows": {}})


def test_required_ci_policy_job_cannot_be_removed_with_refreshed_digest(tmp_path):
    workflows, manifest = real_tree(tmp_path)
    workflow = workflows / "ci.yaml"
    original = workflow.read_text()
    start = original.index("  runner-policy:\n")
    end = original.index("  # ─", start)
    workflow.write_text(original[:start] + original[end:])
    refresh_digest(manifest, workflow)
    assert any("required jobs missing" in issue for issue in check(tmp_path, manifest))
