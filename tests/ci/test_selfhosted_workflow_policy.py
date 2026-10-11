"""Mutation controls for the repository's self-hosted runner gate."""

import json
import shutil
from pathlib import Path

import pytest
import yaml

from scripts.ci.selfhosted_workflow_policy import UniqueBaseLoader, check, topology_digest


FIXTURE = """\
name: CI
on:
  pull_request:
permissions:
  contents: read
jobs:
  build:
    runs-on: [self-hosted, Linux, '${{ matrix.arch }}', hermes-ci]
    strategy:
      matrix:
        include:
          - arch: X64
            platform: linux/amd64
          - arch: ARM64
            platform: linux/arm64
    steps:
      - run: echo ok
"""


def tree(tmp_path: Path):
    directory = tmp_path / ".github" / "workflows"
    directory.mkdir(parents=True)
    workflow = directory / "ci.yml"
    workflow.write_text(FIXTURE)
    manifest = {"workflows": {"ci.yml": topology_digest(yaml.load(FIXTURE, Loader=UniqueBaseLoader))}}
    return workflow, manifest


def test_positive_control_accepts_pinned_selfhosted_matrix(tmp_path):
    workflow, manifest = tree(tmp_path)
    # Dynamic labels must resolve to a finite approved platform set, so use a
    # full custom platform label in this fixture.
    workflow.write_text(FIXTURE.replace("${{ matrix.arch }}", "${{ matrix.runner }}")
                        .replace("arch: X64", "arch: X64\n            runner: hermes-linux-x64")
                        .replace("arch: ARM64", "arch: ARM64\n            runner: hermes-linux-arm64")
                        .replace("Linux, '${{ matrix.runner }}'", "'${{ matrix.runner }}'"))
    manifest["workflows"]["ci.yml"] = topology_digest(yaml.load(workflow.read_text(), Loader=UniqueBaseLoader))
    assert check(tmp_path, manifest) == []


def test_hosted_runner_mutation_makes_policy_red(tmp_path):
    workflow, manifest = tree(tmp_path)
    workflow.write_text(FIXTURE.replace("[self-hosted, Linux, '${{ matrix.arch }}', hermes-ci]", "ubuntu-latest"))
    assert any("self-hosted" in issue for issue in check(tmp_path, manifest))


def test_removed_arm64_matrix_row_makes_coverage_red(tmp_path):
    workflow, manifest = tree(tmp_path)
    workflow.write_text(FIXTURE.replace("          - arch: ARM64\n            platform: linux/arm64\n", ""))
    assert any("matrix coverage" in issue for issue in check(tmp_path, manifest))


def test_replaced_arm64_matrix_row_makes_coverage_red(tmp_path):
    workflow, manifest = tree(tmp_path)
    workflow.write_text(FIXTURE.replace("arch: ARM64", "arch: X64")
                        .replace("platform: linux/arm64", "platform: linux/amd64"))
    assert any("matrix coverage" in issue for issue in check(tmp_path, manifest))


def test_matrix_runner_requires_every_base_combination_even_with_new_manifest(tmp_path):
    workflow, manifest = tree(tmp_path)
    text = FIXTURE.replace("Linux, '${{ matrix.arch }}'", "'${{ matrix.runner }}'")
    text = text.replace("        include:\n", "        arch: [x64, arm64]\n        include:\n")
    text = text.replace("          - arch: X64\n            platform: linux/amd64", "          - arch: x64\n            runner: hermes-linux-x64\n            platform: linux/amd64")
    text = text.replace("          - arch: ARM64\n            platform: linux/arm64", "          - arch: arm64\n            runner: hermes-linux-arm64\n            platform: linux/arm64")
    workflow.write_text(text)
    manifest["workflows"]["ci.yml"] = topology_digest(yaml.load(text, Loader=UniqueBaseLoader))
    assert check(tmp_path, manifest) == []
    text = text.replace("          - arch: arm64\n            runner: hermes-linux-arm64\n            platform: linux/arm64\n", "")
    workflow.write_text(text)
    manifest["workflows"]["ci.yml"] = topology_digest(yaml.load(text, Loader=UniqueBaseLoader))
    assert any("matrix.runner" in issue for issue in check(tmp_path, manifest))


def test_matrix_runner_cannot_route_arm64_row_to_x64_even_with_new_manifest(tmp_path):
    workflow, manifest = tree(tmp_path)
    text = FIXTURE.replace("Linux, '${{ matrix.arch }}'", "'${{ matrix.runner }}'")
    text = text.replace("          - arch: X64\n            platform: linux/amd64", "          - arch: X64\n            runner: hermes-linux-x64\n            platform: linux/amd64")
    text = text.replace("          - arch: ARM64\n            platform: linux/arm64", "          - arch: ARM64\n            runner: hermes-linux-arm64\n            platform: linux/arm64")
    workflow.write_text(text)
    manifest["workflows"]["ci.yml"] = topology_digest(yaml.load(text, Loader=UniqueBaseLoader))
    assert check(tmp_path, manifest) == []
    text = text.replace("runner: hermes-linux-arm64", "runner: hermes-linux-x64")
    workflow.write_text(text)
    manifest["workflows"]["ci.yml"] = topology_digest(yaml.load(text, Loader=UniqueBaseLoader))
    assert any("matrix.runner" in issue for issue in check(tmp_path, manifest))


def test_new_workflow_and_new_event_fail_closed(tmp_path):
    workflow, manifest = tree(tmp_path)
    (workflow.parent / "extra.yml").write_text(FIXTURE)
    assert any("workflow file set changed" in issue for issue in check(tmp_path, manifest))
    (workflow.parent / "extra.yml").unlink()
    workflow.write_text(FIXTURE.replace("  pull_request:", "  pull_request:\n  workflow_dispatch:"))
    assert any("event/job/condition" in issue for issue in check(tmp_path, manifest))


def test_external_reusable_is_rejected(tmp_path):
    workflow, manifest = tree(tmp_path)
    workflow.write_text(FIXTURE.replace("    runs-on: [self-hosted, Linux, '${{ matrix.arch }}', hermes-ci]", "    uses: owner/repo/.github/workflows/other.yml@main"))
    assert any("external or unpinned" in issue for issue in check(tmp_path, manifest))


def test_local_reusable_target_is_covered_by_topology(tmp_path):
    workflow, manifest = tree(tmp_path)
    called = workflow.parent / "called.yml"
    called.write_text(FIXTURE.replace("  pull_request:", "  workflow_call:")
                      .replace("Linux, '${{ matrix.arch }}'", "hermes-linux-x64"))
    workflow.write_text(FIXTURE.replace("    runs-on: [self-hosted, Linux, '${{ matrix.arch }}', hermes-ci]", "    uses: ./.github/workflows/called.yml"))
    manifest["workflows"] = {
        name: topology_digest(yaml.load(path.read_text(), Loader=UniqueBaseLoader))
        for name, path in (("ci.yml", workflow), ("called.yml", called))
    }
    assert check(tmp_path, manifest) == []
    workflow.write_text(workflow.read_text().replace("called.yml", "ci.yml"))
    assert any("coverage differs" in issue for issue in check(tmp_path, manifest))


def test_local_reusable_without_workflow_call_is_rejected(tmp_path):
    workflow, manifest = tree(tmp_path)
    called = workflow.parent / "called.yml"
    called.write_text(FIXTURE.replace("Linux, '${{ matrix.arch }}'", "hermes-linux-x64"))
    workflow.write_text(FIXTURE.replace("    runs-on: [self-hosted, Linux, '${{ matrix.arch }}', hermes-ci]", "    uses: ./.github/workflows/called.yml"))
    manifest["workflows"] = {
        name: topology_digest(yaml.load(path.read_text(), Loader=UniqueBaseLoader))
        for name, path in (("ci.yml", workflow), ("called.yml", called))
    }
    assert any("workflow_call" in issue for issue in check(tmp_path, manifest))


def test_local_reusable_input_is_covered_by_topology(tmp_path):
    workflow, manifest = tree(tmp_path)
    called = workflow.parent / "called.yml"
    called.write_text(FIXTURE.replace("  pull_request:", "  workflow_call:")
                      .replace("Linux, '${{ matrix.arch }}'", "hermes-linux-x64"))
    workflow.write_text(FIXTURE.replace("    runs-on: [self-hosted, Linux, '${{ matrix.arch }}', hermes-ci]",
                                        "    uses: ./.github/workflows/called.yml\n    with:\n      runner: hermes-linux-x64"))
    manifest["workflows"] = {
        name: topology_digest(yaml.load(path.read_text(), Loader=UniqueBaseLoader))
        for name, path in (("ci.yml", workflow), ("called.yml", called))
    }
    assert check(tmp_path, manifest) == []
    workflow.write_text(workflow.read_text().replace("runner: hermes-linux-x64", "runner: ubuntu-latest"))
    assert any("coverage differs" in issue for issue in check(tmp_path, manifest))


def test_conflicting_platform_labels_are_rejected(tmp_path):
    workflow, manifest = tree(tmp_path)
    workflow.write_text(FIXTURE.replace("Linux, '${{ matrix.arch }}'", "Windows, X64, hermes-linux-x64"))
    manifest["workflows"]["ci.yml"] = topology_digest(yaml.load(workflow.read_text(), Loader=UniqueBaseLoader))
    assert any("platform" in issue for issue in check(tmp_path, manifest))


def test_caller_selected_runner_requires_preallocation_allowlist(tmp_path):
    workflow, manifest = tree(tmp_path)
    text = FIXTURE.replace("  pull_request:", "  workflow_call:\n    inputs:\n      runner:\n        type: string\n        default: hermes-linux-x64")
    text = text.replace("Linux, '${{ matrix.arch }}'", "'${{ inputs.runner }}'")
    workflow.write_text(text)
    manifest["workflows"]["ci.yml"] = topology_digest(yaml.load(text, Loader=UniqueBaseLoader))
    assert any("inputs.runner" in issue for issue in check(tmp_path, manifest))


def test_caller_selected_runner_with_preallocation_allowlist(tmp_path):
    workflow, manifest = tree(tmp_path)
    text = FIXTURE.replace("  pull_request:", "  workflow_call:\n    inputs:\n      runner:\n        type: string\n        default: hermes-linux-x64")
    text = text.replace("Linux, '${{ matrix.arch }}'", "'${{ inputs.runner }}'")
    text = text.replace("  build:\n", "  build:\n    if: ${{ contains(fromJSON('[\"hermes-linux-x64\", \"hermes-macos-arm64\"]'), inputs.runner) }}\n")
    workflow.write_text(text)
    manifest["workflows"]["ci.yml"] = topology_digest(yaml.load(text, Loader=UniqueBaseLoader))
    assert check(tmp_path, manifest) == []
    workflow.write_text(text.replace("hermes-macos-arm64", "ubuntu-latest"))
    assert check(tmp_path, manifest)


def test_hosted_fallback_in_expression_is_rejected(tmp_path):
    workflow, manifest = tree(tmp_path)
    text = FIXTURE.replace("Linux, '${{ matrix.arch }}'", "\"${{ inputs.arch == 'x64' && 'hermes-linux-x64' || 'ubuntu-latest' }}\"")
    workflow.write_text(text)
    manifest["workflows"]["ci.yml"] = topology_digest(yaml.load(text, Loader=UniqueBaseLoader))
    assert any("dynamic runner label" in issue for issue in check(tmp_path, manifest))


REPO = Path(__file__).resolve().parents[2]
RELEASE_WRITE = {"contents", "packages", "id-token", "actions"}

# From the pre-migration workflow definitions at HEAD 9b1a56e15f: these
# explicit read boundaries must survive the self-hosted migration. The four
# release build jobs that used "write" are listed separately because an
# unconditional write override would weaken GitHub's low-trust default.
READ_CACHE_JOBS = (
    ("desktop-bundle-smoke.yml", "macos"),
    ("desktop-bundle-smoke.yml", "windows"),
    ("desktop-bundled-release.yml", "build-win32-x64-commit"),
    ("desktop-bundled-release.yml", "build-win32-arm64-commit"),
    ("desktop-bundled-release.yml", "build-darwin-arm64-commit"),
    ("desktop-bundled-release.yml", "build-darwin-x64-commit"),
    ("desktop-bundled-release.yml", "assemble-win32-bundle"),
    ("desktop-bundled-release.yml", "publish-channel"),
)
TRUSTED_DEFAULT_WRITE_CACHE_JOBS = (
    ("desktop-bundled-release.yml", "build-win32-x64-release"),
    ("desktop-bundled-release.yml", "build-win32-arm64-release"),
    ("desktop-bundled-release.yml", "build-darwin-arm64-release"),
    ("desktop-bundled-release.yml", "build-darwin-x64-release"),
)


def _document(path):
    return yaml.load(path.read_text(), Loader=UniqueBaseLoader)


def _repo_snapshot(tmp_path):
    shutil.copytree(REPO / ".github" / "workflows", tmp_path / ".github" / "workflows")
    manifest = json.loads((REPO / "scripts" / "ci" / "selfhosted_workflow_manifest.json").read_text())
    assert check(tmp_path, manifest) == []
    return tmp_path / ".github" / "workflows", manifest


def test_release_write_permissions_never_run_on_ci_or_build_role():
    violations = []
    for path in sorted((REPO / ".github" / "workflows").glob("*.y*ml")):
        doc = yaml.load(path.read_text(), Loader=UniqueBaseLoader)
        for name, job in doc["jobs"].items():
            runner = job.get("runs-on", [])
            if not isinstance(runner, list) or not runner or "hermes-publish" in runner:
                continue
            permissions = job.get("permissions", doc.get("permissions", {}))
            if isinstance(permissions, dict) and any(permissions.get(scope) == "write" for scope in RELEASE_WRITE):
                violations.append(f"{path.name}:{name}")
    assert violations == []


def test_permission_elevation_fails_even_with_new_manifest(tmp_path):
    workflow, manifest = tree(tmp_path)
    text = FIXTURE.replace("contents: read", "contents: write")
    text = text.replace("Linux, '${{ matrix.arch }}'", "hermes-linux-x64")
    workflow.write_text(text)
    manifest["workflows"]["ci.yml"] = topology_digest(yaml.load(text, Loader=UniqueBaseLoader))
    assert any("release-write" in issue for issue in check(tmp_path, manifest))


def test_missing_permissions_fails_even_with_new_manifest(tmp_path):
    workflow, manifest = tree(tmp_path)
    text = FIXTURE.replace("permissions:\n  contents: read\n", "")
    workflow.write_text(text)
    manifest["workflows"]["ci.yml"] = topology_digest(yaml.load(text, Loader=UniqueBaseLoader))
    assert any("explicit effective permissions" in issue for issue in check(tmp_path, manifest))


def test_publish_write_requires_declared_environment_even_with_new_manifest(tmp_path):
    workflow, manifest = tree(tmp_path)
    text = FIXTURE.replace("contents: read", "contents: write")
    text = text.replace("hermes-ci]", "hermes-publish]")
    text = text.replace("Linux, '${{ matrix.arch }}'", "hermes-linux-x64")
    workflow.write_text(text)
    manifest["workflows"]["ci.yml"] = topology_digest(yaml.load(text, Loader=UniqueBaseLoader))
    assert any("named environment" in issue for issue in check(tmp_path, manifest))
    text = text.replace("  build:\n", "  build:\n    environment: release-signing\n")
    workflow.write_text(text)
    manifest["workflows"]["ci.yml"] = topology_digest(yaml.load(text, Loader=UniqueBaseLoader))
    assert check(tmp_path, manifest) == []


def test_runner_policy_noop_mutation_fails_even_with_new_manifest(tmp_path):
    directory, manifest = _repo_snapshot(tmp_path)
    path = directory / "ci.yaml"
    text = path.read_text().replace("run: python scripts/ci/selfhosted_workflow_policy.py", "run: echo policy-bypassed")
    path.write_text(text)
    manifest["workflows"]["ci.yaml"] = topology_digest(yaml.load(text, Loader=UniqueBaseLoader))
    assert any("runner-policy" in issue for issue in check(tmp_path, manifest))


def test_aggregate_policy_result_check_noop_fails_even_with_new_manifest(tmp_path):
    directory, manifest = _repo_snapshot(tmp_path)
    path = directory / "ci.yaml"
    text = path.read_text().replace('test "$POLICY_RESULT" = success', "echo policy-bypassed")
    path.write_text(text)
    manifest["workflows"]["ci.yaml"] = topology_digest(yaml.load(text, Loader=UniqueBaseLoader))
    assert any("all-checks-pass" in issue for issue in check(tmp_path, manifest))


def test_disabled_desktop_reusable_cannot_be_reenabled_by_event_manifest_edit(tmp_path):
    directory, manifest = _repo_snapshot(tmp_path)
    path = directory / "ci.yaml"
    document = _document(path)
    document["on"]["repository_dispatch"] = ""
    document["jobs"]["e2e-desktop"] = {
        "needs": "detect",
        "if": "github.event_name == 'repository_dispatch'",
        "uses": "./.github/workflows/e2e-desktop.yml",
    }
    path.write_text(yaml.safe_dump(document, sort_keys=False))
    manifest["workflows"]["ci.yaml"] = topology_digest(_document(path))
    assert any("e2e-desktop" in issue for issue in check(tmp_path, manifest))


def test_ci_orchestrator_omits_disabled_desktop_e2e_job():
    document = _document(REPO / ".github" / "workflows" / "ci.yaml")
    assert "e2e-desktop" not in document["jobs"]


def test_ci_aggregate_omits_disabled_desktop_e2e_dependency():
    document = _document(REPO / ".github" / "workflows" / "ci.yaml")
    assert "e2e-desktop" not in document["jobs"]["all-checks-pass"]["needs"]


def test_repository_dispatch_caller_cannot_activate_disabled_desktop_job(tmp_path):
    directory, manifest = _repo_snapshot(tmp_path)
    caller = directory / "dispatch-caller.yml"
    caller.write_text(
        "name: Dispatch caller\n"
        "on:\n"
        "  repository_dispatch:\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  invoke:\n"
        "    uses: ./.github/workflows/ci.yaml\n"
    )
    manifest["workflows"][caller.name] = topology_digest(_document(caller))
    ci = _document(directory / "ci.yaml")
    assert "repository_dispatch" in _document(caller)["on"]
    assert "workflow_call" in ci["on"]
    assert check(tmp_path, manifest) == []  # manifest-updated caller is admitted
    # Called workflows use the caller's github.event_name; the old predicate
    # becomes true for this caller, so the dormant job must not exist at all.
    assert "e2e-desktop" not in ci["jobs"]


def test_reintroduced_desktop_job_fails_policy_with_refreshed_manifest(tmp_path):
    directory, manifest = _repo_snapshot(tmp_path)
    path = directory / "ci.yaml"
    ci = _document(path)
    ci["jobs"]["e2e-desktop"] = {
        "name": "Desktop E2E",
        "needs": "detect",
        "if": "github.event_name == 'repository_dispatch'",
        "uses": "./.github/workflows/e2e-desktop.yml",
    }
    needs = ci["jobs"]["all-checks-pass"]["needs"]
    if "e2e-desktop" not in needs:
        needs.append("e2e-desktop")
    path.write_text(yaml.safe_dump(ci, sort_keys=False))
    manifest["workflows"]["ci.yaml"] = topology_digest(_document(path))
    assert any("e2e-desktop" in issue for issue in check(tmp_path, manifest))


def test_aggregate_desktop_dependency_fails_policy_with_refreshed_manifest(tmp_path):
    directory, manifest = _repo_snapshot(tmp_path)
    path = directory / "ci.yaml"
    ci = _document(path)
    needs = ci["jobs"]["all-checks-pass"]["needs"]
    if "e2e-desktop" not in needs:
        needs.append("e2e-desktop")
    path.write_text(yaml.safe_dump(ci, sort_keys=False))
    manifest["workflows"]["ci.yaml"] = topology_digest(_document(path))
    assert any("e2e-desktop" in issue for issue in check(tmp_path, manifest))


def test_cache_mode_changes_topology_digest():
    original = yaml.load(FIXTURE, Loader=UniqueBaseLoader)
    restricted = yaml.load(FIXTURE, Loader=UniqueBaseLoader)
    restricted["jobs"]["build"]["cache-mode"] = "read"
    assert topology_digest(original) != topology_digest(restricted)


@pytest.mark.parametrize("workflow, job", READ_CACHE_JOBS)
def test_preexisting_read_cache_boundary_is_preserved(workflow, job):
    document = _document(REPO / ".github" / "workflows" / workflow)
    assert document["jobs"][job].get("cache-mode") == "read"


@pytest.mark.parametrize("workflow, job", READ_CACHE_JOBS)
@pytest.mark.parametrize("mutated_mode", [None, "write"])
def test_read_cache_boundary_mutation_fails_policy_with_refreshed_manifest(
    tmp_path, workflow, job, mutated_mode
):
    directory, manifest = _repo_snapshot(tmp_path)
    path = directory / workflow
    document = _document(path)
    if mutated_mode is None:
        document["jobs"][job].pop("cache-mode", None)
    else:
        document["jobs"][job]["cache-mode"] = mutated_mode
    path.write_text(yaml.safe_dump(document, sort_keys=False))
    manifest["workflows"][workflow] = topology_digest(_document(path))
    # This must be a semantic policy finding, not only a stale digest.
    assert any("cache-mode" in issue for issue in check(tmp_path, manifest))


@pytest.mark.parametrize("workflow, job", TRUSTED_DEFAULT_WRITE_CACHE_JOBS)
def test_release_build_does_not_override_low_trust_cache_default(workflow, job):
    document = _document(REPO / ".github" / "workflows" / workflow)
    assert document["jobs"][job].get("cache-mode") is None


@pytest.mark.parametrize("workflow, job", TRUSTED_DEFAULT_WRITE_CACHE_JOBS)
def test_explicit_write_cache_override_fails_policy_with_refreshed_manifest(
    tmp_path, workflow, job
):
    directory, manifest = _repo_snapshot(tmp_path)
    path = directory / workflow
    document = _document(path)
    document["jobs"][job]["cache-mode"] = "write"
    path.write_text(yaml.safe_dump(document, sort_keys=False))
    manifest["workflows"][workflow] = topology_digest(_document(path))
    assert any("cache-mode" in issue for issue in check(tmp_path, manifest))


def test_macos_runner_dynamic_fallback_fails_even_with_refreshed_manifest(tmp_path):
    directory, manifest = _repo_snapshot(tmp_path)
    path = directory / "desktop-bundle-smoke.yml"
    document = _document(path)
    runner = document["jobs"]["macos"]["runs-on"]
    reviewed = runner[1]
    assert "'hermes-macos-arm64'" in reviewed
    assert "inputs.public-base" not in reviewed
    runner[1] = reviewed.replace("'hermes-macos-arm64'", "inputs.public-base")
    path.write_text(yaml.safe_dump(document, sort_keys=False))
    manifest["workflows"][path.name] = topology_digest(_document(path))
    issues = check(tmp_path, manifest)
    assert any("desktop-bundle-smoke.yml:macos" in issue and "dynamic runner label" in issue
               for issue in issues)


def test_runner_allowlist_or_bypass_fails_even_with_refreshed_manifest(tmp_path):
    directory, manifest = _repo_snapshot(tmp_path)
    path = directory / "install-e2e-run.yml"
    document = _document(path)
    job = document["jobs"]["e2e"]
    reviewed = str(job["if"])
    guard = "contains(fromJSON('[\"hermes-linux-x64\", \"hermes-macos-arm64\"]'), inputs.runner)"
    assert guard in reviewed
    assert "github.event_name == 'workflow_dispatch' ||" not in reviewed
    job["if"] = "github.event_name == 'workflow_dispatch' || " + reviewed
    path.write_text(yaml.safe_dump(document, sort_keys=False))
    manifest["workflows"][path.name] = topology_digest(_document(path))
    issues = check(tmp_path, manifest)
    assert any("install-e2e-run.yml:e2e" in issue and "dynamic runner label" in issue
               for issue in issues)
