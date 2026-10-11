#!/usr/bin/env python3
"""Exercise the XML validator with valid and invalid language packs.

Run with python3 Tests/test_xmlvalidate.py. Requires Bash, GNU grep and fxparser
on PATH (npm install fast-xml-parser@4.5.2 -g, as in the Validate XML workflow).
"""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / ".github/workflows/xmlvalidate.sh"
KEYS = ("FIRST", "SECOND", "THIRD")


class XmlValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which("fxparser") is None:
            raise RuntimeError("Install fast-xml-parser@4.5.2 and put fxparser on PATH")

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="vc-xml-validation-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "VeraCrypt test"
        self.common = self.write_language("src/Common/Language.xml")

    def write_language(self, relative_path, keys=KEYS, lang="en", text=r"First\nSecond &amp; third"):
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        entries = "".join(
            f'    <entry lang="{lang}" key="{key}">{text}</entry>\n'
            for key in keys
        )
        path.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<VeraCrypt>\n  <localization prog-version="DEBUG">\n'
            + entries + '  </localization>\n</VeraCrypt>\n',
            encoding="utf-8",
        )
        return path

    def run_validator(self):
        return subprocess.run(
            ["bash", str(VALIDATOR), str(self.root)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
        )

    def assert_overall_failure(self, result):
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("Overall Result: One or more files failed validation.", result.stdout)

    def test_complete_translations_and_english_fallbacks_pass(self):
        fallback = self.write_language("Translations/Language.ar.xml")
        translated = self.write_language("Translations/Language.nl.xml", lang="nl")

        result = self.run_validator()

        self.assertEqual(result.returncode, 0, result.stdout)
        for path in (self.common, fallback, translated):
            self.assertIn(f"{path} PASSED all checks.", result.stdout)
        self.assertIn("Overall Result: All processed files passed all checks successfully.", result.stdout)

    def test_reports_every_missing_key_and_continues_to_later_files(self):
        arabic = self.write_language("Translations/Language.ar.xml", keys=("FIRST",))
        french = self.write_language("Translations/Language.fr.xml", keys=("FIRST", "SECOND"))
        dutch = self.write_language("Translations/Language.nl.xml", lang="nl")

        result = self.run_validator()

        self.assert_overall_failure(result)
        for path, key in ((arabic, "SECOND"), (arabic, "THIRD"), (french, "THIRD")):
            self.assertIn(f"Key '{key}' (from {self.common}) not found in {path}", result.stdout)
        self.assertIn("2 key(s) missing.", result.stdout)
        self.assertIn("1 key(s) missing.", result.stdout)
        for path in (arabic, french):
            self.assertIn(f"{path} FAILED one or more checks.", result.stdout)
        self.assertIn(f"{dutch} PASSED all checks.", result.stdout)

    def test_malformed_xml_reports_parser_error_and_continues(self):
        arabic = self.write_language("Translations/Language.ar.xml")
        arabic.write_text(
            arabic.read_text(encoding="utf-8").replace("</VeraCrypt>", "</Broken>"),
            encoding="utf-8",
        )
        dutch = self.write_language("Translations/Language.nl.xml", lang="nl")

        result = self.run_validator()

        self.assert_overall_failure(result)
        self.assertIn(f"XML Validation Failed for {arabic} (fxparser exit code: 1)", result.stdout)
        self.assertIn("InvalidTag", result.stdout)
        self.assertIn(f"{arabic} FAILED one or more checks.", result.stdout)
        self.assertIn(f"{dutch} PASSED all checks.", result.stdout)

    def test_invalid_escape_reports_error_and_continues(self):
        arabic = self.write_language("Translations/Language.ar.xml", text=r"Invalid\q")
        dutch = self.write_language("Translations/Language.nl.xml", lang="nl")

        result = self.run_validator()

        self.assert_overall_failure(result)
        self.assertIn(f"File '{arabic}' contains potentially invalid backslash escape sequences.", result.stdout)
        self.assertIn(f"{arabic} FAILED one or more checks.", result.stdout)
        self.assertIn(f"{dutch} PASSED all checks.", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
