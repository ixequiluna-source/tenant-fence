import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class CliTests(unittest.TestCase):
    def test_executable_demo(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, "-m", "tenant_fence", "demo", "--out", directory],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                json.loads(result.stdout)["verdicts"],
                ["FAIL", "FAIL", "FAIL", "PASS", "INCONCLUSIVE"],
            )

    def test_invalid_input_replaces_stale_success(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "report.json").write_text('[{"verdict":"PASS"}]')
            args = [
                "check",
                "--base-url",
                "http://127.0.0.1:8000",
                "--manifest",
                "missing",
            ]
            result = subprocess.run(
                [sys.executable, "-m", "tenant_fence", *args, "--out", directory],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(
                json.loads((target / "report.json").read_text())[0]["verdict"],
                "INCONCLUSIVE",
            )
            self.assertNotIn("Traceback", result.stderr)
