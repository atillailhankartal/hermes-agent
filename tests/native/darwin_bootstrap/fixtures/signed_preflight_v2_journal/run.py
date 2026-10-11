#!/usr/bin/env python3
"""Compile actual C codec against pinned literal bytes; no Python outcome oracle."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
PIN = '246aeed6456b052da570f61eb4a11040a945fde8692036327ae80c1401d14e79'


def octets(value):
    return '{' + ','.join(str(b) for b in value) + '}'


def candidate(c):
    if c is None:
        return '{{0},0,0,{0},{0},{0},{0},0}'
    fields = [octets(bytes.fromhex(c['installation_id_hex'])),
              str(c['epoch']) + 'ULL', str(c['key_state'])]
    fields += [octets(bytes.fromhex(c[k + '_hex']))
               for k in ('policy_digest', 'manifest_digest', 'new_key_id')]
    fields += [octets(c['version_id'].encode('ascii')), str(len(c['version_id']))]
    return '{' + ','.join(fields) + '}'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--emit-header', type=Path)
    parser.add_argument('--sanitize', action='store_true')
    parser.add_argument('--mutations', action='store_true')
    args = parser.parse_args()
    raw = (HERE / 'golden-vectors.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == PIN, 'literal fixture SHA mismatch'
    data = json.loads(raw)
    vectors = data['vectors']
    assert len(vectors) == 54 and len({v['name'] for v in vectors}) == 54
    declarations, rows = [], []
    for i, v in enumerate(vectors):
        snapshots = []
        for key in ('journal', 'selector'):
            h = v[key + '_hex']
            if h is None:
                snapshots.append('{NULL,0,0}')
            else:
                b = bytes.fromhex(h)
                assert hashlib.sha256(b).hexdigest() == v[key + '_sha256']
                name = key + str(i)
                declarations.append('static const uint8_t ' + name + '[] = ' +
                                    octets(b if b else b'\0') + ';')
                snapshots.append('{' + name + ',' + str(len(b)) + ',1}')
        rows.append('{' + ','.join([json.dumps(v['name']), *snapshots,
                    'BH_JOURNAL_' + v['action'].upper(),
                    str(int(v['candidate'] is not None)), candidate(v['candidate']),
                    'BH_JOURNAL_' + v['external_outcome'],
                    json.dumps(v['parser_diagnosis']),
                    json.dumps(v['external_reason']), str(int(v['off']))]) + '}')
    declarations.append('static const bh_journal_parameters parameters = {' +
                        octets(bytes.fromhex(data['install_id_hex'])) + ',' +
                        octets(bytes.fromhex(data['new_key_id_hex'])) + ',' +
                        str(data['threshold_t']) + 'ULL};')
    declarations.append('static const journal_case cases[] = {\n' + ',\n'.join(rows) + '\n};')
    if args.emit_header:
        args.emit_header.write_text('\n'.join(declarations) + '\n')
        return 0
    with tempfile.TemporaryDirectory(prefix='hermes-journal-codec-') as temp:
        build = Path(temp)
        (build / 'journal_vectors.h').write_text('\n'.join(declarations) + '\n')
        command = ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic',
                   '-I' + str(ROOT / 'native/darwin_bootstrap'), '-I' + temp,
                   str(ROOT / 'native/darwin_bootstrap/signed_preflight_v2_journal_codec.c'),
                   str(ROOT / 'tests/native/darwin_bootstrap/test_signed_preflight_v2_journal_codec.c'),
                   '-o', str(build / 'test')]
        if args.sanitize:
            command[1:1] = ['-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-g']
        print('COMMAND ' + shlex.join(command), flush=True)
        subprocess.run(command, check=True)
        print('COMPILE PASS C11 -Wall -Wextra -Werror -pedantic', flush=True)
        result = subprocess.run([str(build / 'test')], check=False)
        print('SEMANTIC EXIT ' + str(result.returncode), flush=True)
        if result.returncode != 0 or not args.mutations:
            return result.returncode
        source_path = ROOT / 'native/darwin_bootstrap/signed_preflight_v2_journal_codec.c'
        source = source_path.read_text()
        mutation_cases = {
            'install': 'same_epoch_installation_changed',
            'epoch': 'same_epoch_epoch_changed',
            'state': 'same_epoch_state_changed',
            'policy': 'candidate_same_epoch_changed_policy',
            'manifest': 'same_epoch_manifest_changed',
            'version': 'same_epoch_version_changed',
            'new_key': 'same_epoch_new_key_changed',
        }
        for field, case in mutation_cases.items():
            marker = 'return "candidate_' + field + '_mismatch";'
            lines = source.splitlines(keepends=True)
            hits = [i for i, line in enumerate(lines) if marker in line and 'if (' in line]
            # Only the independent candidate function is mutated, never persisted comparisons.
            assert len(hits) == 1, (field, hits)
            lines[hits[0]] = '    /* Test-only deleted ' + field + ' comparison. */\n'
            mutant = build / ('mutant_' + field + '.c')
            mutant.write_text(''.join(lines))
            mutated_command = [str(mutant) if arg == str(source_path) else arg for arg in command]
            subprocess.run(mutated_command, check=True)
            run = subprocess.run([str(build / 'test')], capture_output=True, text=True, check=False)
            failed = [line for line in run.stdout.splitlines() if line.startswith('FAIL ')]
            assert run.returncode == 1 and len(failed) == 1, (field, run.returncode, run.stdout, run.stderr)
            assert ('Codec_When_' + case + ' ') in failed[0] and 'actual=1/' in failed[0], failed
            print('MUTATION SENSITIVE ' + field + ': ' + failed[0], flush=True)
        print('MUTATIONS executed=7 sensitive=7 skips=0', flush=True)
        return 0


if __name__ == '__main__':
    raise SystemExit(main())
