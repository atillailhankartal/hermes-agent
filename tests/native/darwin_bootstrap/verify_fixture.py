"""Disposable Darwin FD6 feasibility; does not test the installed broker."""

import errno
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(__file__).with_name("fixture.c")


def run_case(executable, slot=6, fault="none", mode="libproc-observational"):
    result = subprocess.run(
        [str(executable), str(slot), fault, mode], capture_output=True, text=True,
        timeout=15, check=False,
    )
    assert len(result.stdout.encode()) < 16384
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert not result.stderr, result.stderr
    data = json.loads(result.stdout)
    assert data["candidate_only"] is True
    assert data["mode"] == mode
    assert data["root_source_cloexec"] == 1
    assert stat.S_ISSOCK(data["path_stat"]["mode"])
    assert stat.S_ISSOCK(data["fd_stat"]["mode"])
    assert data["case"] == fault
    assert data["source_fd"] == slot
    assert data["parent_socket_closed"] is True
    assert data["child_reaped"] is True
    assert data["cleanup"] == "removed"
    assert not Path(data["directory"]).exists()
    return data


@unittest.skipUnless(sys.platform == "darwin", "UNAVAILABLE: requires actual Darwin")
class NativeFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="darwin-fd6-build-")
        cls.executable = Path(cls.build.name) / "fixture"
        result = subprocess.run(
            ["/usr/bin/xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
             "-pedantic", "-O1", str(SOURCE), "-o", str(cls.executable)],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if result.returncode or result.stderr:
            cls.build.cleanup()
            raise AssertionError(result.stderr)
        cls.probe = Path(cls.build.name) / "socket-state-probe"
        probe_result = subprocess.run(
            ["/usr/bin/xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
             "-pedantic", "-O1", str(SOURCE.with_name("socket_state_probe.c")),
             "-o", str(cls.probe)], capture_output=True, text=True, timeout=30,
            check=False,
        )
        if probe_result.returncode or probe_result.stderr:
            cls.build.cleanup()
            raise AssertionError(probe_result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def test_collision_and_cloexec_transitions(self):
        for slot in (3, 4, 5, 6, 17, 129):
            with self.subTest(slot=slot):
                data = run_case(self.executable, slot)
                self.assertTrue(data["ready"])
                self.assertEqual(data["bind_denial_errno"], errno.EACCES)
                self.assertEqual(data["client_peer_uid"], os.geteuid())
                self.assertEqual(data["server_peer_uid"], os.geteuid())
                self.assertEqual(data["expected_uid"], os.geteuid())
                stages = data["stages"]
                self.assertEqual([r["phase"] for r in stages], [1, 2, 3, 4])
                self.assertEqual([r["open_mask"] for r in stages], [127, 127, 95, 95])
                self.assertEqual([r["cloexec_mask"] for r in stages], [0, 32, 0, 88])
                self.assertTrue(all(r["unexpected_fds"] == 0 for r in stages))
                self.assertTrue(all(r["acceptconn"] == 0 for r in stages))
                self.assertTrue(all(r["path_matches"] == 1 for r in stages))
                self.assertEqual(data["status_bytes"], 0)
                self.assertEqual(data["exit_code"], 0)

    def test_failure_does_not_become_ready(self):
        for fault in ("spawn", "exec", "early-exit", "bad-close", "leak", "prelisten"):
            with self.subTest(fault=fault):
                data = run_case(self.executable, fault=fault)
                self.assertFalse(data["ready"])
                if fault == "spawn":
                    self.assertEqual(data["spawn_error"], errno.ENOENT)
                    self.assertEqual(data["child_pid"], -1)
                elif fault == "exec":
                    self.assertEqual(data["status_bytes"], 4)
                    self.assertEqual(data["exec_error"], errno.ENOENT)
                elif fault == "early-exit":
                    self.assertEqual(data["status_bytes"], 0)
                    self.assertEqual(data["exit_code"], 23)
                else:
                    self.assertEqual(data["exit_code"], 40)
                    stage = data["stages"][0]
                    if fault == "prelisten":
                        self.assertEqual(stage["acceptconn"], 1)
                    elif fault == "leak":
                        self.assertEqual(stage["unexpected_fds"], 1)
                    else:
                        self.assertEqual(stage["open_mask"], 63)

    def test_replaced_inode_is_preserved(self):
        data = run_case(self.executable, fault="replace")
        self.assertTrue(data["replacement_preserved"])
        self.assertTrue(data["ready"])

    def test_independent_libproc_bound_and_listening_control(self):
        result = subprocess.run([str(self.probe)], capture_output=True, text=True,
                                timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertLess(len(result.stdout.encode()), 16384)
        rows = json.loads(result.stdout)["observations"]
        self.assertEqual([row["acceptconn"] for row in rows], [0, 1])
        for row in rows:
            self.assertEqual(row["proc_bytes"], row["expected_bytes"])
            self.assertEqual(row["proc_errno"], 0)
            self.assertEqual(row["getsockopt_errno"], errno.ENOPROTOOPT)

    def test_original_getsockopt_contract_fails_closed(self):
        data = run_case(self.executable, mode="strict")
        self.assertFalse(data["ready"])
        self.assertEqual(data["exit_code"], 40)
        self.assertEqual(data["stages"][0]["getsockopt_errno"], errno.ENOPROTOOPT)
        self.assertEqual(data["stages"][0]["acceptconn"], -1)

    def test_privileged_controls_unavailable(self):
        data = run_case(self.executable)
        self.assertEqual(data["cross_uid_root_bind"], "UNAVAILABLE")
        self.assertEqual(data["root_listen_credential_negative"], "UNAVAILABLE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
