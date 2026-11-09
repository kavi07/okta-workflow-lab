import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from workflow_lab import load_inventory, normalize_event, valid_event

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


class LabTests(unittest.TestCase):
    def setUp(self):
        self.cases = json.loads((EXAMPLES / "cases.json").read_text(encoding="utf-8"))
        self.xml = (EXAMPLES / "event-4725.xml").read_text(encoding="utf-8")

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, "workflow_lab.py", *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_normalize_uses_target_sid_and_lowercase_hostname(self):
        actual = normalize_event(self.xml)
        self.assertEqual(actual, self.cases[0]["input"])
        self.assertNotIn("lab.employee", json.dumps(actual))

    def test_normalize_rejects_non_security_or_non_4725_event(self):
        for xml in (self.xml.replace("Security</Channel>", "System</Channel>"),
                    self.xml.replace(">4725<", ">4722<")):
            with self.subTest(xml=xml):
                with self.assertRaises(ValueError):
                    normalize_event(xml)

    def test_normalize_rejects_dtd_and_duplicate_sid(self):
        for xml in (
            '<!DOCTYPE Event [<!ENTITY example "value">]>' + self.xml,
            self.xml.replace("</EventData>", '<Data Name="TargetSid">duplicate</Data></EventData>'),
        ):
            with self.subTest(xml=xml):
                with self.assertRaises(ValueError):
                    normalize_event(xml)

    def test_inventory_rejects_duplicate_mapping(self):
        data = json.loads((EXAMPLES / "inventory.json").read_text(encoding="utf-8"))
        data["identities"][1]["okta_user_id"] = data["identities"][0]["okta_user_id"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inventory.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "only once"):
                load_inventory(path)

    def test_documented_pattern_matches_offline_validation_for_fixtures(self):
        guide = (ROOT / "docs" / "workflows.md").read_text(encoding="utf-8")
        pattern = guide.split("```regex\n", 1)[1].split("\n```", 1)[0]
        for case in self.cases:
            event = case["input"]
            compact = json.dumps(event, separators=(",", ":"), sort_keys=True)
            with self.subTest(case=case["name"]):
                actual = (
                    isinstance(event, dict) and len(event) == 4
                    and re.fullmatch(pattern, compact) is not None
                )
                self.assertEqual(actual, valid_event(event))

    def test_request_wraps_input_as_text(self):
        result = self.run_cli("request", "examples/cases.json", "active")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(json.loads(result.stdout)["payload"]), self.cases[0]["input"])

    def test_check_distinguishes_pass_mismatch_and_invalid_json(self):
        result = self.run_cli("check", "examples/cases.json", "active", "examples/active-response.json")
        self.assertEqual(result.returncode, 0, result.stderr)
        with tempfile.TemporaryDirectory() as directory:
            response = Path(directory) / "response.json"
            actual = dict(self.cases[0]["expected"], okta_user_id="extra-field")
            response.write_text(json.dumps(actual), encoding="utf-8")
            result = self.run_cli("check", "examples/cases.json", "active", str(response))
            self.assertEqual(result.returncode, 1)
            self.assertNotIn("extra-field", result.stdout + result.stderr)
            response.write_text('{"decision":"first","decision":"second"}', encoding="utf-8")
            result = self.run_cli("check", "examples/cases.json", "active", str(response))
            self.assertEqual(result.returncode, 2)
            self.assertIn("duplicate key", result.stderr)


if __name__ == "__main__":
    unittest.main()
