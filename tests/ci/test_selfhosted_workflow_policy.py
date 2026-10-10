"""Mutation controls for the repository's self-hosted runner gate."""

from pathlib import Path

import yaml

from scripts.ci.selfhosted_workflow_policy import UniqueBaseLoader, check, topology_digest


FIXTURE = """\
name: CI
on:
  pull_request:
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
