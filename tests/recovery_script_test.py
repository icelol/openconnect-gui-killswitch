#!/usr/bin/env python3
"""Exercise administrator recovery with sandbox files and fake system commands.

The shipped script is copied and its fixed installed paths and system mutators
are replaced before execution. No sudo, launchd or live PF operation is possible.
"""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == "darwin", "requires macOS plutil")
class RecoveryScriptTest(unittest.TestCase):
    def run_recovery(self, state, boot, *, release_failure=False, clear_failure=False):
        sandbox = tempfile.TemporaryDirectory(prefix="ocgui-recovery-test-")
        self.addCleanup(sandbox.cleanup)
        base = pathlib.Path(sandbox.name)
        support = base / "support"
        runtime = base / "runtime"
        support.mkdir()
        runtime.mkdir()
        (runtime / "state.json").write_text(state)
        (support / "boot.json").write_text(boot)
        calls = base / "calls.jsonl"
        stub = base / "fake-system"
        stub.write_text("#!/usr/bin/env python3\n" +
            "import json,sys\n" +
            f"with open({str(calls)!r},'a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')\n" +
            f"sys.exit(1 if ({release_failure!r} and '-X' in sys.argv) or " +
            f"({clear_failure!r} and '-f' in sys.argv) else 0)\n")
        stub.chmod(0o700)
        script = (ROOT / "scripts/recover-killswitch.sh").read_text()
        marker = 'if [ "$(id -u)" != 0 ]; then'
        self.assertEqual(script.count(marker), 1)
        script = script.replace(marker, "if false; then")
        script = script.replace("/Library/Application Support/OpenConnect-GUI-KillSwitch", str(support))
        script = script.replace("/var/run/openconnect-gui-killswitch", str(runtime))
        script = script.replace("/Library/LaunchDaemons/net.openconnect-vpn.killswitch.service.plist", str(base / "absent-daemon"))
        for command in ("/bin/launchctl", "/usr/bin/killall", "/sbin/pfctl"):
            script = script.replace(command, str(stub))
        copied = base / "recover.sh"
        copied.write_text(script)
        result = subprocess.run(["/bin/sh", str(copied)], capture_output=True, text=True, timeout=5)
        recorded = [json.loads(line) for line in calls.read_text().splitlines()]
        # Every firewall mutation has the exact owned anchor or a saved token.
        for args in recorded:
            self.assertNotIn("-d", args)
            self.assertNotIn("-F", args)
            if "-f" in args:
                self.assertEqual(args[:2], ["-a", "com.apple/000.openconnect-gui-killswitch"])
        return result, support, runtime, recorded

    def test_corrupt_files_do_not_prevent_off(self):
        result, support, runtime, calls = self.run_recovery('{"token":', '{"enabled":')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads((support / "boot.json").read_text())["enabled"])
        self.assertTrue(list(support.glob("boot.json.corrupt.*")))
        self.assertTrue(list(runtime.glob("state.json.corrupt.*")))
        self.assertFalse(any("-X" in args for args in calls))

    def test_invalid_schema_or_token_is_never_released(self):
        for state in ('{"schema":9,"token":"123"}', '{"schema":1,"token":"invalid"}'):
            with self.subTest(state=state):
                result, _, runtime, calls = self.run_recovery(state, '{}')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(list(runtime.glob("state.json.corrupt.*")))
                self.assertFalse(any("-X" in args for args in calls))

    def test_valid_reference_is_released(self):
        result, _, runtime, calls = self.run_recovery('{"schema":1,"token":"123"}', '{}')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(["-X", "123"], calls)
        self.assertFalse((runtime / "state.json").exists())

    def test_reference_failure_preserves_journal(self):
        result, support, runtime, _ = self.run_recovery('{"schema":1,"token":"123"}', '{}', release_failure=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((runtime / "state.json").exists())
        self.assertFalse(json.loads((support / "boot.json").read_text())["enabled"])

    def test_failed_rule_removal_never_releases_reference(self):
        result, _, runtime, calls = self.run_recovery('{"schema":1,"token":"123"}', '{}', clear_failure=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((runtime / "state.json").exists())
        self.assertFalse(any("-X" in args for args in calls))


if __name__ == "__main__":
    unittest.main()
