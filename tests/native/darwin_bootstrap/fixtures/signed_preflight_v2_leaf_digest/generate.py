#!/usr/bin/env python3
"""Emit pinned unsigned retained-leaf fixtures for the native diagnostic tests."""

import argparse
import hashlib
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
BASE = HERE / "leaf-fixtures.json"
EXPANSIONS = HERE / "leaf-fixture-expansions.json"
REGISTRY = HERE / "leaf-registry.json"


def bytes_literal(data: bytes) -> str:
    return ",".join(f"0x{byte:02x}" for byte in data)


def checked_hex(value: str, expected: str) -> bytes:
    data = bytes.fromhex(value)
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("fixture digest does not match pinned literal")
    return data


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--emit-header", required=True, type=Path)
    args = parser.parse_args()
    base = json.loads(BASE.read_text())
    expansions = json.loads(EXPANSIONS.read_text())
    registry = json.loads(REGISTRY.read_text())
    cases = registry["cases"]
    if (registry["unique_cases"] != 38 or registry["variants_per_link"] != 133 or
            len(cases) != 38 or sum(case["variants"] for case in cases) != 133 or
            len({case["name"] for case in cases}) != 38 or
            registry["links"] != ["real", "spy"]):
        raise ValueError("literal leaf registry changed")
    if hashlib.sha256(BASE.read_bytes()).hexdigest() != expansions["base_fixture_sha256"]:
        raise ValueError("expansion base fixture hash differs")
    policy = bytes.fromhex(base["leaves"]["policy"]["hex"])
    manifest = bytes.fromhex(base["leaves"]["manifest"]["hex"])
    signature = bytes.fromhex(base["leaves"]["signature"]["hex"])
    if policy != bytes((17 * i + 3) % 256 for i in range(49)):
        raise ValueError("policy formula differs")
    if manifest != bytes((29 * i + 7) % 256 for i in range(17)):
        raise ValueError("manifest formula differs")
    if signature != bytes([0x55] * 64):
        raise ValueError("signature formula differs")
    for label, data in (("policy", policy), ("manifest", manifest), ("signature", signature)):
        record = base["leaves"][label]
        if len(data) != record["length"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
            raise ValueError(f"{label} literal digest differs")
    rows = []
    for entry in base["fixtures"] + expansions["fixtures"]:
        is_expansion = "policy_length" in entry
        policy_length = entry["policy_length"] if is_expansion else len(policy)
        manifest_length = entry["manifest_length"] if is_expansion else len(manifest)
        expected_policy = bytes((17 * i + 3) % 256 for i in range(policy_length))
        expected_manifest = bytes((29 * i + 7) % 256 for i in range(manifest_length))
        pd = entry["policy_sha256"] if is_expansion else base["leaves"]["policy"]["sha256"]
        md = entry["manifest_sha256"] if is_expansion else base["leaves"]["manifest"]["sha256"]
        if hashlib.sha256(expected_policy).hexdigest() != pd or hashlib.sha256(expected_manifest).hexdigest() != md:
            raise ValueError(f"leaf digest mismatch for {entry['id']}")
        journal = checked_hex(entry["journal_hex"], entry["journal_sha256"])
        selector = checked_hex(entry["selector_hex"], entry["selector_sha256"])
        if is_expansion:
            epoch, state, version = 6, 1, entry["version"]
        else:
            epoch, state, version = entry["epoch"], entry["key_state"], "release-7"
        if not 1 <= len(version) <= 63:
            raise ValueError("unrepresentable fixture version")
        rows.append((entry["id"], journal, selector, epoch, state, version,
                     policy_length, manifest_length, bytes.fromhex(pd), bytes.fromhex(md)))
    if len(rows) != 9 or len({row[0] for row in rows}) != 9:
        raise ValueError("fixture registry count/name changed")
    lines = ["/* Generated from pinned JSON by generate.py; do not edit. */",
             "#ifndef BH_TX_LEAF_VECTORS_H", "#define BH_TX_LEAF_VECTORS_H"]
    for i, row in enumerate(rows):
        lines.append(f"static const unsigned char leaf_journal_{i}[] = {{{bytes_literal(row[1])}}};")
        lines.append(f"static const unsigned char leaf_selector_{i}[] = {{{bytes_literal(row[2])}}};")
    lines.append("static const struct leaf_fixture_data leaf_fixture_vectors[] = {")
    for i, row in enumerate(rows):
        name, _journal, _selector, epoch, state, version, pl, ml, pd, md = row
        lines.append("  {" + ",".join((f'"{name}"', f"leaf_journal_{i}", f"sizeof(leaf_journal_{i})",
             f"leaf_selector_{i}", f"sizeof(leaf_selector_{i})", f"{epoch}u", f"{state}u",
             f'"{version}"', f"{pl}u", f"{ml}u", "{" + bytes_literal(pd) + "}",
             "{" + bytes_literal(md) + "}")) + "},")
    lines.extend(("};", "#define BH_TX_LEAF_VECTOR_COUNT 9u",
                  "static const struct leaf_case_data leaf_case_registry[] = {"))
    for case in cases:
        lines.append(f'  {{"{case["name"]}",{case["variants"]}u}},')
    lines.extend(("};", "#define BH_TX_LEAF_CASE_COUNT 38u",
                  "#define BH_TX_LEAF_VARIANTS_PER_LINK 133u", "#endif"))
    args.emit_header.parent.mkdir(parents=True, exist_ok=True)
    args.emit_header.write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
