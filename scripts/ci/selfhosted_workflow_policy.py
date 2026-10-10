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
    files = {p.name: p for p in workflow_dir.iterdir() if p.suffix in {".yml", ".yaml"}}
    expected = manifest["workflows"]
    errors = []
    if set(files) != set(expected):
        errors.append(f"workflow file set changed: missing={sorted(set(expected)-set(files))}, new={sorted(set(files)-set(expected))}")
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
        for name, job in doc["jobs"].items():
            key = f"{filename}:{name}"
            called = job.get("uses")
            if called is not None:
                if not isinstance(called, str) or not called.startswith("./.github/workflows/"):
                    errors.append(f"{key}: external or unpinned reusable workflow forbidden")
                elif called.rsplit("/", 1)[-1] not in files:
                    errors.append(f"{key}: missing local reusable {called}")
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
