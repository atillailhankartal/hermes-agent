"""Fail closed on hosted or unreviewed GitHub Actions runner routing."""

from __future__ import annotations

import argparse
import hashlib
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
OS = {"Linux", "Windows", "macOS"}
ARCH = {"X64", "ARM64"}
MIN_WORKFLOWS = 51
MIN_JOBS = 179
REQUIRED_JOBS = {
    "ci.yaml": {"runner-policy", "all-checks-pass"},
    "stable-release.yml": {"publication", "complete"},
    "stable-release-publication.yml": {"reconcile"},
    "ci-review-comment.yml": {"comment"},
    "install-e2e-red.yml": {"track"},
    "install-e2e-macos-run.yml": {"e2e"},
    "deploy-site.yml": {"deploy-vercel", "deploy-docs"},
    "docker.yml": {"build", "publish"},
}
REQUIRED_CALLERS = {
    ("install-e2e-macos-run.yml", "e2e"): (
        "./.github/workflows/install-e2e-run.yml", "hermes-macos-arm64"
    ),
}
EXPRESSION = re.compile(r"^\$\{\{\s*(.*?)\s*\}\}$")
LITERAL = re.compile(r"'([^']*)'|\"([^\"]*)\"")


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
        "jobs": {
            name: {
                "if": job.get("if", ""),
                "needs": job.get("needs", ""),
                "matrix": (job.get("strategy") or {}).get("matrix", ""),
                "continue-on-error": job.get("continue-on-error", ""),
                "runs-on": job.get("runs-on", ""),
                "uses": job.get("uses", ""),
                "with": job.get("with", ""),
            }
            for name, job in (document.get("jobs") or {}).items()
        },
    }


def topology_digest(document):
    """Pin full triggers, job graph, matrices, and runner expressions compactly."""
    encoded = json.dumps(topology(document), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


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
            return [row.get("runner") for row in matrix.get("include", [])]
    if expr == "matrix.target.runner":
        matrix = (job.get("strategy") or {}).get("matrix") or {}
        if isinstance(matrix, dict):
            return [row.get("runner") for row in matrix.get("target", [])]
    if expr == "inputs.runner":
        inputs = ((document.get("on") or {}).get("workflow_call") or {}).get("inputs") or {}
        return [(inputs.get("runner") or {}).get("default")]
    # The only permitted conditional expressions select pinned platform labels.
    if expr.startswith("inputs.arch == 'x64'") or expr.startswith("inputs.arch == 'arm64'") or expr.startswith("inputs.bundle-arch == 'x64'") or expr.startswith("inputs.bundle-arch == 'arm64'"):
        return [a or b for a, b in LITERAL.findall(expr)][1:]
    return None


def check(root: Path, manifest: dict) -> list[str]:
    workflow_dir = root / ".github" / "workflows"
    errors = []
    if not workflow_dir.is_dir():
        return [f"workflow directory missing: {workflow_dir}"]
    files = {p.name: p for p in workflow_dir.iterdir() if p.suffix in {".yml", ".yaml"}}
    expected = manifest.get("workflows")
    if not isinstance(expected, dict):
        return ["workflow manifest must contain a workflows mapping"]
    if manifest.get("schemaVersion") != 2:
        errors.append("workflow manifest schemaVersion must be 2")
    if len(files) < MIN_WORKFLOWS or len(expected) < MIN_WORKFLOWS:
        errors.append(f"workflow inventory below pinned minimum {MIN_WORKFLOWS}: source={len(files)}, manifest={len(expected)}")
    if set(files) != set(expected):
        errors.append(f"workflow file set changed: missing={sorted(set(expected)-set(files))}, new={sorted(set(files)-set(expected))}")
    job_count = 0
    seen_jobs = {}
    job_definitions = {}
    for filename, path in sorted(files.items()):
        try:
            doc = yaml.load(path.read_text(), Loader=UniqueBaseLoader)
            if not isinstance(doc, dict) or not isinstance(doc.get("on"), dict) or not isinstance(doc.get("jobs"), dict):
                raise ValueError("on/jobs must be mappings")
        except (OSError, yaml.YAMLError, ValueError) as exc:
            errors.append(f"{filename}: invalid YAML: {exc}")
            continue
        if filename in expected and topology_digest(doc) != expected[filename]:
            errors.append(f"{filename}: event/job/condition/matrix coverage differs from manifest")
        seen_jobs[filename] = set(doc["jobs"])
        job_count += len(doc["jobs"])
        for name, job in doc["jobs"].items():
            key = f"{filename}:{name}"
            if not isinstance(job, dict):
                errors.append(f"{key}: job must be a mapping")
                continue
            job_definitions[(filename, name)] = job
            called = job.get("uses")
            if called is not None:
                if not isinstance(called, str) or called not in {f"./.github/workflows/{n}" for n in files}:
                    errors.append(f"{key}: external or unpinned reusable workflow forbidden")
                call_inputs = job.get("with") or {}
                if not isinstance(call_inputs, dict):
                    errors.append(f"{key}: reusable call inputs must be a mapping")
                elif "runner" in call_inputs:
                    runner_input = call_inputs["runner"]
                    if not isinstance(runner_input, str) or runner_input not in PLATFORMS:
                        errors.append(f"{key}: unapproved caller runner input: {runner_input}")
                if "runs-on" in job:
                    errors.append(f"{key}: callable job also declares runs-on")
                continue
            runner = job.get("runs-on")
            if not isinstance(runner, list) or not runner or runner[0] != "self-hosted":
                errors.append(f"{key}: runs-on must begin with literal self-hosted")
                continue
            if len([x for x in runner if isinstance(x, str) and x in ROLES]) != 1:
                errors.append(f"{key}: exactly one approved role label required")
            platforms = []
            for label in runner[1:]:
                if not isinstance(label, str):
                    errors.append(f"{key}: non-string runner label")
                    continue
                if label in OS | ARCH | ROLES | PLATFORMS:
                    platforms.append(label)
                    continue
                values = _expression_labels(label, job, doc)
                if not values or any(value not in PLATFORMS for value in values):
                    errors.append(f"{key}: unresolved or unapproved dynamic runner label: {label}")
                else:
                    platforms.extend(values)
            if not (set(platforms) & PLATFORMS or (set(platforms) & OS and set(platforms) & ARCH)):
                errors.append(f"{key}: OS and architecture labels required")
    if job_count < MIN_JOBS:
        errors.append(f"job inventory below pinned minimum {MIN_JOBS}: {job_count}")
    for filename, required in REQUIRED_JOBS.items():
        missing = required - seen_jobs.get(filename, set())
        if missing:
            errors.append(f"{filename}: required jobs missing: {sorted(missing)}")
    for (filename, name), (target, runner_label) in REQUIRED_CALLERS.items():
        job = job_definitions.get((filename, name))
        if job is None:
            errors.append(f"{filename}:{name}: required caller missing")
            continue
        if job.get("uses") != target:
            errors.append(f"{filename}:{name}: required caller target changed from {target}")
        call_inputs = job.get("with")
        actual_runner = call_inputs.get("runner") if isinstance(call_inputs, dict) else None
        if actual_runner != runner_label:
            errors.append(f"{filename}:{name}: required caller runner changed from {runner_label}")
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
