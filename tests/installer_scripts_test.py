#!/usr/bin/env python3
"""Sandbox installer scripts: no real launchd, process, PF or system-path writes."""
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

class InstallerScriptsTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="ocgui-installer-fixture-")
        self.addCleanup(self.directory.cleanup)
        self.base = pathlib.Path(self.directory.name)
        self.calls = self.base / "calls.txt"
        self.env = dict(os.environ, TEST_OS="27.2.1", TEST_ARCH="arm64", FAIL="")
        self.stub = self.base / "command"
        self.stub.write_text("""#!/bin/sh
printf '%s\\n' "$*" >> 'CALLS'
case "$1" in
 sw_vers) printf '%s\\n' "$TEST_OS" ;;
 uname) printf '%s\\n' "$TEST_ARCH" ;;
 stat) printf '501\\n' ;;
 id) printf 'fixtureuser\\n' ;;
 dscl) printf 'NFSHomeDirectory: HOME\\n' ;;
 plist) case "$3" in *CFBundleIdentifier*) echo net.openconnect-vpn.gui.killswitch.boot ;; *) echo 1.2.2 ;; esac ;;
 launchctl) if [ "$FAIL" = service-bootstrap ] && [ "$2" = bootstrap ] && [ "$3" = system ]; then exit 5; fi ;;
 binary)
  if [ "$2" = --check-storage ] && [ "$FAIL" = storage ]; then exit 42; fi
  if [ "$2" = --prepare-boot ] && [ "$FAIL" = boot ]; then exit 33; fi
  if [ "$2" = --boot-guard ] && [ "$FAIL" = boot ]; then exit 34; fi
  if [ "$2" = --service-ready ] && [ "$FAIL" = ready ]; then exit 1; fi
  ;;
esac
exit 0
""".replace("CALLS", str(self.calls)).replace("HOME", str(self.base / "home")))
        self.stub.chmod(0o700)

    def replace_command(self, script, command, kind):
        return script.replace(command, str(self.stub) + " " + kind)

    def execute(self, script, name):
        path = self.base / name
        path.write_text(script)
        result = subprocess.run(["/bin/sh", str(path)], env=self.env,
                                capture_output=True, text=True, timeout=10)
        calls = self.calls.read_text() if self.calls.exists() else ""
        return result, calls

    def preinstall(self, version="27.2.1", arch="arm64", requirements=True):
        self.env.update(TEST_OS=version, TEST_ARCH=arch)
        if requirements:
            (self.base / "requirements.conf").write_text(
                "OCGUI_MINIMUM_MACOS='27.0'\nOCGUI_PAYLOAD_ARCHS='arm64'\n")
        script = (ROOT / "scripts/installer/preinstall").read_text()
        for command, kind in (("/usr/bin/sw_vers", "sw_vers"), ("/usr/bin/uname", "uname"),
                              ("/bin/launchctl", "launchctl"), ("/usr/bin/killall", "killall")):
            script = self.replace_command(script, command, kind)
        return self.execute(script, "preinstall")

    def postinstall(self, fail="", boot_exists=True):
        self.env["FAIL"] = fail
        support = self.base / "support"
        support.mkdir()
        (support / "VERSION").write_text("1.2.2\n")
        if boot_exists:
            (support / "boot.json").write_text('{"schema":1,')
        (self.base / "home/Library/LaunchAgents").mkdir(parents=True)
        script = (ROOT / "scripts/installer/postinstall").read_text()
        script = script.replace("/Library/Application Support/OpenConnect-GUI-KillSwitch", str(support))
        script = script.replace("/Library/PrivilegedHelperTools/OpenConnect-KillSwitch", str(self.base / "helper"))
        script = script.replace("/Library/LaunchDaemons", str(self.base / "daemons"))
        binary = str(self.base / "helper/Runtime.app/Contents/MacOS/OpenConnect-GUI-KillSwitch")
        # The variable must remain one executable path, not shell command text.
        helper = pathlib.Path(binary)
        helper.parent.mkdir(parents=True)
        helper.write_text("#!/bin/sh\nexec '" + str(self.stub) + "' binary \"$@\"\n")
        helper.chmod(0o700)
        for command, kind in (("/usr/bin/stat", "stat"), ("/usr/bin/id", "id"),
                              ("/usr/bin/dscl", "dscl"), ("/usr/libexec/PlistBuddy", "plist"),
                              ("/usr/sbin/chown", "chown"), ("/usr/bin/install", "install"),
                              ("/bin/launchctl", "launchctl"), ("/bin/rm", "rm")):
            script = self.replace_command(script, command, kind)
        return self.execute(script, "postinstall")

    def test_supported_mac_reaches_stop_only_after_preflight(self):
        for version in ("27.0", "27.2.1", "28.0"):
            with self.subTest(version=version):
                result, calls = self.preinstall(version)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("OPENCONNECT_INSTALL_PREFLIGHT", result.stdout)
                self.assertIn("launchctl bootout system/net.openconnect", calls)

    def test_old_os_never_stops_working_client(self):
        result, calls = self.preinstall("26.9")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("macOS 27.0 or later", result.stderr)
        self.assertNotIn("launchctl", calls)
        self.assertNotIn("killall", calls)

    def test_wrong_architecture_never_stops_working_client(self):
        result, calls = self.preinstall(arch="x86_64")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("x86_64", result.stderr)
        self.assertNotIn("launchctl", calls)

    def test_missing_requirements_never_stops_client(self):
        result, calls = self.preinstall(requirements=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("launchctl", calls)

    def test_existing_bad_boot_keeps_authenticated_recovery_available(self):
        result, calls = self.postinstall("boot")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("needs recovery", result.stderr)
        self.assertIn("binary --service-ready", calls)
        self.assertEqual((self.base / "support/boot.json").read_text(), '{"schema":1,')

    def test_failure_to_create_fresh_boot_remains_fatal(self):
        result, calls = self.postinstall("boot", boot_exists=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stage=boot-configuration", result.stderr)
        self.assertNotIn("launchctl bootstrap system", calls)

    def test_diagnostic_names_failing_storage_step(self):
        result, calls = self.postinstall("storage")
        self.assertEqual(result.returncode, 42)
        self.assertIn("stage=protected-storage", result.stderr)
        self.assertNotIn("launchctl bootstrap system", calls)

    def test_diagnostic_names_failing_service_bootstrap(self):
        result, _ = self.postinstall("service-bootstrap")
        self.assertEqual(result.returncode, 5)
        self.assertIn("stage=service-bootstrap", result.stderr)

    def test_normal_install_confirms_service_ready(self):
        result, calls = self.postinstall()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("binary --service-ready", calls)

if __name__ == "__main__":
    unittest.main()
