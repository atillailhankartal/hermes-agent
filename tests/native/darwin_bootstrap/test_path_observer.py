#!/usr/bin/env python3.11
"""Named dormant Darwin path observer cases; product source is separately gated."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import time


REAL_CASES = (
    "args", "alias", "fd", "raw-metadata", "ordinary-acl-enoent",
    "owner-group", "no-authority",
)
INJECTED_CASES = (
    "args", "alias", "fd", "raw-metadata", "empty-contract",
    "acl-present", "acl-errors", "symlink-intermediate", "symlink-leaf",
    "type", "owner-group", "writable", "links", "replace-before-open",
    "replace-after-open", "metadata-change", "root-change", "final-sweep",
    "cleanup-failures", "descriptor-budget", "no-authority",
)
EXPECTED_CASE_COUNT = 28
SOURCE_ROOT = Path(__file__).resolve().parents[3]
TARGETS = {
    "real": "bee_hermes_path_observer_v1_real_test",
    "injected": "bee_hermes_path_observer_v1_injected_test",
}
EXPECTED_RESULT = {
    "real": {
        "args": (2, 1), "alias": (3, 13), "fd": (2, 3),
        "raw-metadata": (3, 13), "ordinary-acl-enoent": (3, 13),
        "owner-group": (2, 6), "no-authority": (3, 13),
    },
    "injected": {
        "args": (2, 1), "alias": (1, 0), "fd": (2, 3),
        "raw-metadata": (1, 0), "empty-contract": (1, 0),
        "acl-present": (2, 12), "acl-errors": (3, 13),
        "symlink-intermediate": (2, 4), "symlink-leaf": (2, 10),
        "type": (2, 10), "owner-group": (2, 6), "writable": (2, 7),
        "links": (2, 9), "replace-before-open": (2, 10),
        "replace-after-open": (2, 10), "metadata-change": (2, 11),
        "root-change": (2, 11), "final-sweep": (2, 10),
        "cleanup-failures": (3, 15), "descriptor-budget": (2, 1),
        "no-authority": (1, 0),
    },
}
GATE_CHECKS = (
    "qualified_otool_L", "raw_binary", "compile_row_multiset_unique_core",
    "source_bytes_compile_argv", "archive_core_parity", "link_argv",
    "map_object_adapter_closure", "nm_symbol_closure", "input_stability",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def injected_fields_valid(fields: dict[str, str], case: str) -> bool:
    for key in ("open_count", "open_success_count", "close_count",
                "max_owned", "acl_get_count", "next_call_count"):
        if key not in fields or re.fullmatch(r"[0-9]+", fields[key]) is None:
            return False
    if int(fields["max_owned"]) > 17:
        return False
    if case == "descriptor-budget" and fields["max_owned"] != "17":
        return False
    if case == "replace-before-open" and (fields["next_call_count"] != "0" or
                                          fields["open_count"] != "1"):
        return False
    if case in ("symlink-intermediate",) and fields["open_count"] != "0":
        return False
    if case == "symlink-leaf" and (fields["open_count"] != "1" or
                                   fields["open_success_count"] != "0" or
                                   fields["acl_get_count"] != "1"):
        return False
    if case == "empty-contract" and fields["acl_get_count"] != "2":
        return False
    if case == "acl-present" and fields["acl_get_count"] != "1":
        return False
    return True


def parse_case_output(stdout: bytes, role: str, case: str) -> dict[str, str] | None:
    try:
        text = stdout.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return None
    if not text.endswith("\n") or len(text.splitlines()) != 1:
        return None
    fields: dict[str, str] = {}
    for token in text.strip().split(" "):
        if "=" not in token:
            return None
        key, value = token.split("=", 1)
        if not key or not value or key in fields:
            return None
        fields[key] = value
    if fields.get("case") != case or fields.get("status") != "PASS" or \
       fields.get("cleanup") != "PASS" or fields.get("authority") != "0" or \
       fields.get("ready") != "0":
        return None
    expected_cleanup = "1" if case == "cleanup-failures" else "0"
    if fields.get("cleanup_failed") != expected_cleanup:
        return None
    for key in ("outcome", "reason", "errno"):
        if key not in fields or re.fullmatch(r"-?[0-9]+", fields[key]) is None:
            return None
    if (int(fields["outcome"]), int(fields["reason"])) != EXPECTED_RESULT[role][case]:
        return None
    if role == "injected" and not injected_fields_valid(fields, case):
        return None
    if role == "real" and case in ("ordinary-acl-enoent", "no-authority",
                                   "raw-metadata", "alias") and fields["errno"] != "2":
        return None
    return fields


def admission_matches(admission: object, role: str, target: str,
                      build_root: Path, image: Path) -> bool:
    """Cross-check a fresh gate result and its one-use permit, never a stored approval."""
    try:
        receipt = admission.receipt
        permit = admission.permit
        if not admission.accepted or permit is None or not isinstance(receipt, dict):
            return False
        audit = receipt.get("audit_sha256")
        if not isinstance(audit, str) or re.fullmatch(r"[0-9a-f]{64}", audit) is None:
            return False
        unsigned = {key: value for key, value in receipt.items()
                    if key != "audit_sha256"}
        canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=True).encode("ascii")
        if hashlib.sha256(canonical).hexdigest() != audit:
            return False
        live_image_sha = sha256(image)
        artifacts = receipt.get("artifact_sha256")
        return (receipt.get("schema") == 1 and
                receipt.get("target") == target and receipt.get("role") == role and
                receipt.get("source_root") == str(SOURCE_ROOT) and
                receipt.get("build_root") == str(build_root) and
                receipt.get("gate_source_sha256") == sha256(
                    Path(__file__).with_name("verify_path_observer_binary.py")) and
                isinstance(artifacts, dict) and
                artifacts.get(f"image:{target}") == live_image_sha and
                isinstance(receipt.get("profile_sha256"), str) and
                re.fullmatch(r"[0-9a-f]{64}", receipt["profile_sha256"]) is not None and
                receipt.get("installed_authority") is False and
                receipt.get("ready") is False and
                receipt.get("nonce") == permit.nonce and
                receipt.get("expires_utc") == permit.expires_utc.isoformat() and
                receipt.get("image_sha256") == live_image_sha == permit.image_sha256 and
                tuple(receipt.get("checks", ())) == GATE_CHECKS and
                tuple(admission.evidence.get("checks", ())) == GATE_CHECKS and
                permit.role == role and permit.path == image and
                permit.consumed is False and
                re.fullmatch(r"[0-9a-f]{32}", permit.nonce) is not None)
    except (AttributeError, KeyError, OSError, TypeError, ValueError):
        return False


def execute(build_root: Path, evidence_dir: Path, admission_file: Path,
            cases: list[tuple[str, str]]) -> int:
    # Imported only for execution; --plan remains available before the gate exists.
    try:
        from verify_path_observer_binary import admit_build
    except (ImportError, AttributeError) as exc:
        print(f"ADMISSION_UNAVAILABLE: {exc}; no image process was started",
              file=sys.stderr)
        return 2
    if not build_root.is_dir() or not evidence_dir.is_dir():
        print("SETUP_FAIL build and evidence directories must already exist",
              file=sys.stderr)
        return 2
    if admission_file.parent.resolve() != evidence_dir.resolve() or \
       admission_file.exists() or admission_file.is_symlink():
        print("SETUP_FAIL admission output must be a new direct evidence child",
              file=sys.stderr)
        return 2
    records: list[dict] = []
    failed = 0
    refused = False
    for ordinal, (role, case) in enumerate(cases, 1):
        target = TARGETS[role]
        expected_image = (build_root / target).resolve()
        started = time.monotonic()
        try:
            admission = admit_build(build_root, target, source_root=SOURCE_ROOT)
        except Exception as exc:
            record = {"ordinal": ordinal, "role": role, "case": case,
                      "target": target, "admission_accepted": False,
                      "admission_reason": "ADMISSION_EXCEPTION",
                      "exception_type": type(exc).__name__,
                      "launch_attempted": False, "passed": False,
                      "admission_elapsed_seconds": time.monotonic() - started}
            records.append(record)
            failed += 1
            refused = True
            print(json.dumps(record, sort_keys=True), flush=True)
            break
        receipt = admission.receipt
        record: dict = {"ordinal": ordinal, "role": role, "case": case,
                        "target": target, "admission_accepted": admission.accepted,
                        "admission_reason": admission.reason,
                        "gate_evidence": admission.evidence, "receipt": receipt,
                        "admission_elapsed_seconds": time.monotonic() - started}
        permit = admission.permit
        if not admission_matches(admission, role, target, build_root, expected_image):
            record["passed"] = False
            record["launch_attempted"] = False
            records.append(record)
            failed += 1
            refused = True
            print(json.dumps(record, sort_keys=True), flush=True)
            break
        try:
            run = permit.run((case,), timeout=5)
        except Exception as exc:
            record.update({"launch_attempted": bool(permit.image_pids),
                           "image_pids": list(permit.image_pids),
                           "permit_consumed": permit.consumed,
                           "exception_type": type(exc).__name__, "passed": False})
            records.append(record)
            failed += 1
            refused = True
            print(json.dumps(record, sort_keys=True), flush=True)
            break
        fields = parse_case_output(run.stdout, role, case)
        passed = (run.returncode == 0 and run.stderr == b"" and fields is not None
                  and tuple(run.argv) == (str(expected_image), case)
                  and run.pid > 0 and permit.consumed and
                  permit.image_pids == (run.pid,))
        record.update({"launch_attempted": True, "pid": run.pid,
                       "argv": list(run.argv), "exit": run.returncode,
                       "stdout": run.stdout.decode("utf-8", "replace"),
                       "stderr": run.stderr.decode("utf-8", "replace"),
                       "parsed_fields": fields, "passed": passed,
                       "image_sha256": permit.image_sha256,
                       "permit_consumed": permit.consumed})
        records.append(record)
        failed += not passed
        print(json.dumps(record, sort_keys=True), flush=True)
    summary = {"expected": EXPECTED_CASE_COUNT, "executed": sum(
        bool(record.get("launch_attempted")) for record in records),
        "failed": failed, "refused": refused, "skipped": 0,
        "source_root": str(SOURCE_ROOT), "build_root": str(build_root),
        "records": records}
    with admission_file.open("x", encoding="utf-8") as output:
        json.dump(summary, output, indent=2, sort_keys=True)
        output.write("\n")
    print(f"SUMMARY executed={summary['executed']} failed={failed} "
          f"skipped=0 refused={str(refused).lower()} evidence={admission_file}")
    return 0 if summary["executed"] == EXPECTED_CASE_COUNT and failed == 0 \
        and not refused else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", action="store_true")
    parser.add_argument("--build-root", type=Path)
    parser.add_argument("--real-bin", type=Path)
    parser.add_argument("--injected-bin", type=Path)
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--admission-file", type=Path)
    args = parser.parse_args()
    cases = [("real", case) for case in REAL_CASES] + [
        ("injected", case) for case in INJECTED_CASES]
    if len(cases) != EXPECTED_CASE_COUNT or len(set(cases)) != len(cases) or \
       set(EXPECTED_RESULT["real"]) != set(REAL_CASES) or \
       set(EXPECTED_RESULT["injected"]) != set(INJECTED_CASES):
        print("CASE_INVENTORY_FAIL", file=sys.stderr)
        return 2
    if args.plan:
        for image, case in cases:
            print(f"PLAN image={image} case={case}")
        print(f"PLAN_COUNT={len(cases)}")
        return 0
    if args.build_root is None or args.evidence_dir is None or \
       args.admission_file is None:
        parser.error("execution requires --build-root, --evidence-dir, "
                     "and --admission-file")
    build_root = args.build_root.resolve()
    for role, supplied in (("real", args.real_bin),
                           ("injected", args.injected_bin)):
        if supplied is not None and supplied.resolve() != (build_root / TARGETS[role]).resolve():
            print("SETUP_FAIL explicit image path differs from target build root",
                  file=sys.stderr)
            return 2
    return execute(build_root, args.evidence_dir, args.admission_file, cases)


if __name__ == "__main__":
    raise SystemExit(main())
