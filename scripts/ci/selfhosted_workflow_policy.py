"""Fail closed on hosted or unreviewed GitHub Actions runner routing."""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import re
from pathlib import Path

import yaml

PLATFORMS = {
    "hermes-linux-x64",
    "hermes-linux-arm64",
    "hermes-windows-x64",
    "hermes-windows-arm64",
    "hermes-macos-x64",
    "hermes-macos-arm64",
}
ROLES = {"hermes-ci", "hermes-build", "hermes-publish", "hermes-automation"}
RELEASE_WRITE_SCOPES = {"contents", "packages", "id-token", "actions", "pages", "deployments"}
OS = {"Linux", "Windows", "macOS"}
ARCH = {"X64", "ARM64"}
EXPRESSION = re.compile(r"^\$\{\{\s*(.*?)\s*\}\}$")
INPUT_RUNNER_GUARD = "contains(fromJSON('[\"hermes-linux-x64\", \"hermes-macos-arm64\"]'), inputs.runner)"
REVIEWED_INPUT_RUNNER_CONDITION = (
    "(inputs.install-method == 'installer-script' "
    "|| (inputs.install-method == 'installer-script+desktop' && inputs.tag-has-desktop)) "
    "&& (contains(fromJSON('[\"hermes-update\", \"installer-script\"]'), inputs.update-method) "
    "|| (contains(fromJSON('[\"installer-script+desktop\", \"hermes-desktop-app-update\"]'), inputs.update-method) "
    "&& inputs.tag-has-desktop)) "
    "&& " + INPUT_RUNNER_GUARD
)
REVIEWED_CONDITIONAL_RUNNERS = {
    "inputs.arch == 'x64' && 'hermes-macos-x64' || 'hermes-macos-arm64'":
        ("hermes-macos-x64", "hermes-macos-arm64"),
    "inputs.arch == 'arm64' && 'hermes-windows-arm64' || 'hermes-windows-x64'":
        ("hermes-windows-arm64", "hermes-windows-x64"),
    "inputs.bundle-arch == 'x64' && 'hermes-macos-x64' || 'hermes-macos-arm64'":
        ("hermes-macos-x64", "hermes-macos-arm64"),
    "inputs.bundle-arch == 'arm64' && 'hermes-windows-arm64' || 'hermes-windows-x64'":
        ("hermes-windows-arm64", "hermes-windows-x64"),
}


class UniqueBaseLoader(yaml.BaseLoader):
    """Keep GitHub's `on` key as a string and reject duplicate YAML keys."""

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in result:
                raise ValueError(f"duplicate YAML key: {key}")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def topology(document):
    return {
        "events": document.get("on") or {},
        "permissions": document.get("permissions"),
        "cache-mode": document.get("cache-mode"),
        "jobs": {
            name: {
                "if": job.get("if", ""),
                "needs": job.get("needs", ""),
                "matrix": (job.get("strategy") or {}).get("matrix", ""),
                "continue-on-error": job.get("continue-on-error", ""),
                "runs-on": job.get("runs-on", ""),
                "uses": job.get("uses", ""),
                "with": job.get("with", ""),
                "permissions": job.get("permissions"),
                "environment": job.get("environment"),
                "cache-mode": job.get("cache-mode"),
            }
            for name, job in (document.get("jobs") or {}).items()
        },
    }


def _environment_name(value):
    return value.get("name") if isinstance(value, dict) else value


def _check_ci_gate(document):
    """Keep the policy executable and its result fatal to the aggregate check."""
    jobs = document["jobs"]
    errors = []
    if "repository_dispatch" in document["on"]:
        errors.append("ci.yaml: direct repository_dispatch trigger requires separate review")
    if "e2e-desktop" in jobs:
        errors.append("ci.yaml:e2e-desktop: disabled orchestration job is forbidden")
    policy = jobs.get("runner-policy")
    if not isinstance(policy, dict) or policy.get("if") or policy.get("continue-on-error"):
        errors.append("ci.yaml:runner-policy: policy job must run without a bypass")
    else:
        steps = policy.get("steps") or []
        invocations = [step for step in steps if isinstance(step, dict)
                       and "selfhosted_workflow_policy.py" in str(step.get("run", ""))]
        if (len(invocations) != 1
                or invocations[0].get("run") != "python scripts/ci/selfhosted_workflow_policy.py"
                or invocations[0].get("if") or invocations[0].get("continue-on-error")):
            errors.append("ci.yaml:runner-policy: unconditional policy command required")
    aggregate = jobs.get("all-checks-pass")
    if not isinstance(aggregate, dict) or aggregate.get("continue-on-error"):
        errors.append("ci.yaml:all-checks-pass: aggregate job must be fatal")
    else:
        needs = aggregate.get("needs") or []
        if isinstance(needs, str):
            needs = [needs]
        if "e2e-desktop" in needs:
            errors.append("ci.yaml:all-checks-pass: e2e-desktop dependency is forbidden")
        steps = aggregate.get("steps") or []
        evaluate = [step for step in steps if isinstance(step, dict) and step.get("id") == "evaluate"]
        expected_run = (
            'test "$POLICY_RESULT" = success\n'
            'args=()\n'
            'if [ "$RELEASE" = true ]; then args+=(--release); fi\n'
            'printf \'%s\' "$NEEDS" | python3 scripts/ci/required_results.py "${args[@]}"\n'
        )
        if ("runner-policy" not in needs or aggregate.get("if") != "always()"
                or len(evaluate) != 1 or evaluate[0].get("if")
                or evaluate[0].get("continue-on-error")
                or (evaluate[0].get("env") or {}).get("POLICY_RESULT") != "${{ needs.runner-policy.result }}"
                or evaluate[0].get("run") != expected_run):
            errors.append("ci.yaml:all-checks-pass: policy result must be fatal to required checks")
    return errors


READ_CACHE_JOBS = {
    "desktop-bundle-smoke.yml": {"macos", "windows"},
    "desktop-bundled-release.yml": {
        "build-win32-x64-commit", "build-win32-arm64-commit",
        "build-darwin-arm64-commit", "build-darwin-x64-commit",
        "assemble-win32-bundle", "publish-channel",
    },
}
DEFAULT_CACHE_JOBS = {
    "desktop-bundled-release.yml": {
        "build-win32-x64-release", "build-win32-arm64-release",
        "build-darwin-arm64-release", "build-darwin-x64-release",
    },
}


def _check_cache_modes(filename, document):
    """Preserve reviewed read boundaries and the low-trust default on release builds."""
    if filename not in READ_CACHE_JOBS and filename not in DEFAULT_CACHE_JOBS:
        return []
    errors = []
    if document.get("cache-mode") is not None:
        errors.append(f"{filename}: workflow cache-mode override is forbidden")
    jobs = document["jobs"]
    for name in sorted(READ_CACHE_JOBS.get(filename, ())):
        if (jobs.get(name) or {}).get("cache-mode") != "read":
            errors.append(f"{filename}:{name}: cache-mode must be read")
    for name in sorted(DEFAULT_CACHE_JOBS.get(filename, ())):
        if (jobs.get(name) or {}).get("cache-mode") is not None:
            errors.append(f"{filename}:{name}: explicit cache-mode overrides low-trust default")
    return errors


def topology_digest(document):
    """Pin full triggers, job graph, matrices, and runner expressions compactly."""
    encoded = json.dumps(topology(document), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _matrix_row_matches_platform(row):
    runner = row.get("runner")
    if runner not in PLATFORMS:
        return False
    expected_by_platform = {
        "linux/amd64": "hermes-linux-x64",
        "linux/arm64": "hermes-linux-arm64",
    }
    platform = row.get("platform")
    if platform is not None and expected_by_platform.get(platform) != runner:
        return False
    target = row.get("label")
    if isinstance(target, str) and re.fullmatch(r"(win32|darwin)-(x64|arm64)", target):
        os_label, arch = target.split("-")
        expected = "hermes-" + {"win32": "windows", "darwin": "macos"}[os_label] + "-" + arch
        if runner != expected:
            return False
    arch = str(row.get("arch", "")).lower()
    if arch in {"amd64", "x64", "arm64"}:
        suffix = "-x64" if arch in {"amd64", "x64"} else "-arm64"
        if not runner.endswith(suffix):
            return False
    marker = str(row.get("marker", "")).lower()
    if marker in {"macos", "windows"} and not runner.startswith("hermes-" + marker + "-"):
        return False
    return True


def _expression_labels(value, job, document):
    match = EXPRESSION.fullmatch(value)
    if not match:
        return None
    expr = match.group(1)
    if expr == "matrix.runner":
        matrix = (job.get("strategy") or {}).get("matrix") or {}
        if isinstance(matrix, dict):
            if isinstance(matrix.get("runner"), list):
                return matrix["runner"]
            rows = matrix.get("include", [])
            if not isinstance(rows, list) or not rows or any(not isinstance(row, dict) for row in rows):
                return None
            if any(not _matrix_row_matches_platform(row) for row in rows):
                return None
            if "exclude" in matrix:
                return None  # expansion semantics need an explicit review
            axes = {name: values for name, values in matrix.items() if name != "include"}
            if axes:
                if any(not isinstance(values, list) or not values for values in axes.values()):
                    return None
                combinations = itertools.product(*axes.values())
                for index, values in enumerate(combinations):
                    if index >= 1024:
                        return None
                    base = dict(zip(axes, values))
                    matching = {
                        row.get("runner") for row in rows
                        if all(name not in row or row[name] == value for name, value in base.items())
                    }
                    if len(matching) != 1 or None in matching:
                        return None
            return [row.get("runner") for row in rows]
    if expr == "matrix.target.runner":
        matrix = (job.get("strategy") or {}).get("matrix") or {}
        if isinstance(matrix, dict):
            rows = matrix.get("target", [])
            if isinstance(rows, list) and rows and all(isinstance(row, dict) and _matrix_row_matches_platform(row) for row in rows):
                return [row["runner"] for row in rows]
    if expr == "inputs.runner":
        # A caller can override workflow_call inputs. The job must be skipped
        # before runner allocation unless its input is one of these platforms.
        condition = " ".join(str(job.get("if", "")).split())
        wrapper = EXPRESSION.fullmatch(condition)
        if wrapper:
            condition = wrapper.group(1)
        if condition not in {INPUT_RUNNER_GUARD, REVIEWED_INPUT_RUNNER_CONDITION}:
            return None
        inputs = ((document.get("on") or {}).get("workflow_call") or {}).get("inputs") or {}
        default = (inputs.get("runner") or {}).get("default")
        return [default] if default in {"hermes-linux-x64", "hermes-macos-arm64"} else None
    # Match the complete reviewed ternary: a pinned selector and two pinned
    # platform labels. Prefix or literal scanning can miss a dynamic fallback.
    return REVIEWED_CONDITIONAL_RUNNERS.get(expr)


def check(root: Path, manifest: dict) -> list[str]:
    workflow_dir = root / ".github" / "workflows"
    files = {p.name: p for p in workflow_dir.iterdir() if p.suffix in {".yml", ".yaml"}}
    expected = manifest["workflows"]
    errors = []
    if set(files) != set(expected):
        errors.append(f"workflow file set changed: missing={sorted(set(expected)-set(files))}, new={sorted(set(files)-set(expected))}")
    documents = {}
    for filename, path in sorted(files.items()):
        try:
            doc = yaml.load(path.read_text(), Loader=UniqueBaseLoader)
            if not isinstance(doc, dict) or not isinstance(doc.get("on"), dict) or not isinstance(doc.get("jobs"), dict):
                raise ValueError("on/jobs must be mappings")
            if any(not isinstance(job, dict) for job in doc["jobs"].values()):
                raise ValueError("each job must be a mapping")
        except (OSError, yaml.YAMLError, ValueError) as exc:
            errors.append(f"{filename}: invalid YAML: {exc}")
            continue
        documents[filename] = doc
        if filename in expected and topology_digest(doc) != expected[filename]:
            errors.append(f"{filename}: event/job/condition/matrix coverage differs from manifest")
    for filename, doc in sorted(documents.items()):
        if filename == "ci.yaml":
            errors.extend(_check_ci_gate(doc))
        errors.extend(_check_cache_modes(filename, doc))
        for name, job in doc["jobs"].items():
            key = f"{filename}:{name}"
            called = job.get("uses")
            if called is not None:
                if not isinstance(called, str) or not called.startswith("./.github/workflows/"):
                    errors.append(f"{key}: external or unpinned reusable workflow forbidden")
                elif called.rsplit("/", 1)[-1] not in files:
                    errors.append(f"{key}: missing local reusable {called}")
                elif called.rsplit("/", 1)[-1] in documents and "workflow_call" not in documents[called.rsplit("/", 1)[-1]]["on"]:
                    errors.append(f"{key}: local reusable lacks workflow_call event: {called}")
                if "runs-on" in job:
                    errors.append(f"{key}: callable job also declares runs-on")
                continue
            runner = job.get("runs-on")
            if not isinstance(runner, list) or not runner or runner[0] != "self-hosted":
                errors.append(f"{key}: runs-on must begin with literal self-hosted")
                continue
            if len([x for x in runner if isinstance(x, str) and x in ROLES]) != 1:
                errors.append(f"{key}: exactly one approved role label required")
            role = next((label for label in runner if isinstance(label, str) and label in ROLES), None)
            permissions = job.get("permissions", doc.get("permissions"))
            if not isinstance(permissions, dict):
                errors.append(f"{key}: explicit effective permissions mapping required")
            else:
                release_write = {scope for scope in RELEASE_WRITE_SCOPES
                                 if permissions.get(scope) == "write"}
                if release_write and role != "hermes-publish":
                    errors.append(f"{key}: release-write permissions {sorted(release_write)} require hermes-publish")
                if release_write and not _environment_name(job.get("environment")):
                    errors.append(f"{key}: release-write publisher requires a named environment")
            platforms = []
            os_labels = []
            arch_labels = []
            platform_slots = 0
            for label in runner[1:]:
                if not isinstance(label, str):
                    errors.append(f"{key}: non-string runner label")
                    continue
                if label in OS | ARCH | ROLES | PLATFORMS:
                    if label in OS:
                        os_labels.append(label)
                    elif label in ARCH:
                        arch_labels.append(label)
                    elif label in PLATFORMS:
                        platforms.append(label)
                        platform_slots += 1
                    continue
                values = _expression_labels(label, job, doc)
                if not values or any(value not in PLATFORMS for value in values):
                    errors.append(f"{key}: unresolved or unapproved dynamic runner label: {label}")
                else:
                    platforms.extend(values)
                    platform_slots += 1
            if platform_slots:
                if platform_slots != 1 or os_labels or arch_labels:
                    errors.append(f"{key}: conflicting platform labels")
            elif len(os_labels) != 1 or len(arch_labels) != 1:
                errors.append(f"{key}: exactly one OS and architecture label required")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--manifest", type=Path, default=Path(__file__).with_name("selfhosted_workflow_manifest.json"))
    args = parser.parse_args()
    problems = check(args.root, json.loads(args.manifest.read_text()))
    for problem in problems:
        print(problem)
    print(f"self-hosted workflow policy: {'FAIL' if problems else 'PASS'} ({len(problems)} violation(s))")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
