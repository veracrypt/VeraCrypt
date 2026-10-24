#!/usr/bin/env python3
"""Regression tests for translation formatting; requires only Python 3."""

import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / ".github/workflows/validate_translation_formats.py"
SPEC = importlib.util.spec_from_file_location("translation_formats", VALIDATOR)
FORMATS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FORMATS)


class FormatGrammarTests(unittest.TestCase):
    def test_windows_narrow_and_wide_strings_are_distinct(self):
        self.assertEqual(FORMATS.printf_arguments("%hs %s %ls %ws %S"), (
            "narrow-string", "wide-string", "wide-string", "wide-string", "narrow-string",
        ))

    def test_portable_printf_rejects_windows_only_modifiers(self):
        for text in ("%ws", "%wS", "%wc", "%wC", "%I32d", "%I64d", "%Id"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                FORMATS.printf_arguments(text, portable=True)
        self.assertEqual(FORMATS.printf_arguments("%s %ls %%ws", portable=True), (
            "wide-string", "wide-string",
        ))

    def test_printf_percent_escapes_and_numeric_fields(self):
        self.assertEqual(FORMATS.printf_arguments("%%%.2f 0x%.8X %I64d"), (
            "double:f", "uint32", "int64",
        ))
        self.assertEqual(FORMATS.printf_arguments("%*.*s"), ("int32", "int32", "wide-string"))
        self.assertEqual(FORMATS.printf_arguments("100%% complete"), ())

    def test_windows_integer_widths_and_signedness(self):
        self.assertEqual(FORMATS.printf_arguments("%ld %lu %I64u %zu"), (
            "int32", "uint32", "uint64", "uintptr",
        ))

    def test_invalid_and_writing_printf_conversions_are_rejected(self):
        for text in ("0x%).8X", "%복구", "%", "%n", "%Ls", "%wf", "%1$s"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                FORMATS.printf_arguments(text)

    def test_formatter_allows_reordering_repetition_and_escaped_braces(self):
        self.assertEqual(FORMATS.formatter_arguments("{1} {0} {1} {{0}}"), {0, 1})
        self.assertEqual(FORMATS.formatter_arguments("{{0}}"), set())
        self.assertEqual(FORMATS.formatter_arguments("%s %d %c"), {0, 1, 2})

    def test_formatter_does_not_accept_windows_modifiers(self):
        self.assertEqual(FORMATS.formatter_arguments("%hs %I64d"), set())

    def test_formatter_rejects_malformed_and_out_of_grammar_fields(self):
        for text in ("{", "}", "{10}", "{x}", "{0", "{0x}"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                FORMATS.formatter_arguments(text)


class CatalogueTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="vc-translation-formats-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        common = self.root / "src/Common/Language.xml"
        common.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / "src/Common/Language.xml", common)
        _, self.reference = FORMATS.read_catalogue(common)

    def write_translation(self, language="tr", changes=None):
        entries = dict(self.reference)
        entries.update(changes or {})
        root = ET.Element("VeraCrypt")
        localization = ET.SubElement(root, "localization", {"prog-version": "DEBUG"})
        ET.SubElement(localization, "language", {"langid": language})
        for key, text in entries.items():
            entry = ET.SubElement(localization, "entry", {"lang": language, "key": key})
            entry.text = text
        path = self.root / f"Translations/Language.{language}.xml"
        path.parent.mkdir(exist_ok=True)
        ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)
        return path

    def run_validator(self):
        return subprocess.run(
            [sys.executable, str(VALIDATOR), str(self.root)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10,
        )

    def write_raw_translation(self, key, text):
        # Insert source XML after serialization so entities reach the validator
        # unchanged, rather than having ElementTree escape their ampersands.
        path = self.write_translation(changes={key: "RAW_ENTRY_TEXT"})
        path.write_text(
            path.read_text(encoding="utf-8").replace("RAW_ENTRY_TEXT", text),
            encoding="utf-8",
        )
        return path

    def assert_rejected(self, language, key, value):
        path = self.write_translation(language, {key: value})
        result = self.run_validator()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn(f"{path}: {key}:", result.stdout)

    def test_english_fallback_and_localized_percent_position_pass(self):
        self.write_translation(changes={"SYSTEM_DRIVE_ENCRYPTING": "zifratzen - %%%.2f eginda"})
        result = self.run_validator()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("Format validation passed: 2 catalogues", result.stdout)

    def test_korean_rescue_disk_invalid_conversion_is_rejected(self):
        self.assert_rejected("ko", "RESCUE_DISK_BURN_INFO", "%s\\n\\n%복구 디스크")

    def test_korean_target_identity_cannot_be_omitted(self):
        self.assert_rejected("ko", "NONSYS_INPLACE_ENC_CONFIRM", "선택한 %s의 암호화")

    def test_hebrew_drive_annotation_cannot_be_omitted(self):
        self.assert_rejected("he", "OVERWRITEPROMPT_DEVICE_HIDDEN_OS_PARTITION", "partition '%s'")
        self.assert_rejected("he", "OVERWRITEPROMPT_DEVICE", "selected %s '%s'")

    def test_extra_overwrite_argument_and_integer_keyfile_are_rejected(self):
        self.assert_rejected("tr", "OVERWRITEPROMPT_DEVICE_HIDDEN_OS_PARTITION", "%s '%s'%s")
        self.assert_rejected("tr", "KEYFILE_ALREADY_EXISTS", "'%is'")

    def test_incorrect_windows_string_width_is_rejected(self):
        self.assert_rejected("ar", "CAPI_RAND", "%s 0x%.8X")
        self.assert_rejected("ro", "THREE_LAYER_CASCADE_HELP", "%s %d %hs %d %s %d")

    def test_wx_messages_reject_windows_only_string_modifiers(self):
        for key in ("KEYFILE_ALREADY_EXISTS", "ENTER_TOKEN_PASSWORD",
                    "OVERWRITEPROMPT_DEVICE", "CONFIRM_VOL_HEADER_RESTORE"):
            with self.subTest(key=key):
                self.assert_rejected("tr", key, self.reference[key].replace("%s", "%ws"))

    def test_windows_modifiers_and_portable_wx_modifiers_pass(self):
        self.write_translation(changes={
            "CANNOT_WRITE_FILE_X": self.reference["CANNOT_WRITE_FILE_X"].replace("%s", "%ws"),
            "OVERWRITEPROMPT_DEVICE": self.reference["OVERWRITEPROMPT_DEVICE"].replace("%s", "%ls"),
        })
        result = self.run_validator()
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_numeric_xml_entities_cannot_supply_placeholders(self):
        for key, text in (
            ("LINUX_NOT_FAT_HINT", "Platform &#123;0&#125;"),
            ("LINUX_NOT_FAT_HINT", "Platform &#x7B;0&#x7D;"),
            ("LINUX_NOT_FAT_HINT", "Platform {&#48;}"),
            ("LINUX_NOT_FAT_HINT", "Platform &#37;s"),
            ("KEYFILE_ALREADY_EXISTS", "File &#x25;s"),
            ("KEYFILE_ALREADY_EXISTS", "File %&#115;"),
        ):
            with self.subTest(key=key, text=text):
                path = self.write_raw_translation(key, text)
                result = self.run_validator()
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn(str(path), result.stdout)
                self.assertIn("unsupported numeric XML entity", result.stdout)

    def test_numeric_xml_entities_in_reference_are_rejected(self):
        path = self.root / "src/Common/Language.xml"
        path.write_text(
            path.read_text(encoding="utf-8").replace("%s", "&#37;s"),
            encoding="utf-8",
        )
        result = self.run_validator()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn(str(path), result.stdout)
        self.assertIn("unsupported numeric XML entity", result.stdout)

    def test_custom_xml_entities_cannot_supply_placeholders(self):
        path = self.write_raw_translation("LINUX_NOT_FAT_HINT", "Platform &argument;")
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "<VeraCrypt>", '<!DOCTYPE VeraCrypt [<!ENTITY argument "{0}">]><VeraCrypt>',
            ),
            encoding="utf-8",
        )
        result = self.run_validator()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn(str(path), result.stdout)
        self.assertIn("unsupported XML document type", result.stdout)

    def test_literal_placeholders_with_named_entities_and_utf8_pass(self):
        self.write_raw_translation(
            "LINUX_NOT_FAT_HINT", '"{0}" &lt;é&gt; &amp; café',
        )
        result = self.run_validator()
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_quote_entities_are_rejected_in_unformatted_entries(self):
        key = "IDC_FAVORITE_DISABLE_HOTKEY"
        for entity in ("&apos;", "&quot;"):
            with self.subTest(entity=entity):
                path = self.write_raw_translation(key, "café\\n" + entity + "Favorites" + entity)
                result = self.run_validator()
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn(f"{path}:", result.stdout)
                self.assertIn(f"{key}: unsupported XML entity {entity!r}", result.stdout)
                self.assertIn("at line ", result.stdout)

    def test_repeated_entity_escaping_is_rejected(self):
        key = "IDT_SYS_DEVICE"
        for entity in ("&amp;apos;", "&amp;quot;", "&amp;lt;", "&amp;gt;",
                       "&amp;amp;", "&amp;amp;quot;"):
            with self.subTest(entity=entity):
                path = self.write_raw_translation(key, "עברית " + entity)
                result = self.run_validator()
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn(f"{path}:", result.stdout)
                self.assertIn(f"{key}: repeatedly escaped XML entity {entity!r}", result.stdout)

    def test_quote_entities_in_reference_are_rejected(self):
        path = self.root / "src/Common/Language.xml"
        path.write_text(
            path.read_text(encoding="utf-8").replace("Beginner's Tutorial", "Beginner&apos;s Tutorial"),
            encoding="utf-8",
        )
        result = self.run_validator()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn(f"{path}:", result.stdout)
        self.assertIn("unsupported XML entity '&apos;'", result.stdout)

    def test_entity_check_only_inspects_entry_text(self):
        path = self.write_translation(changes={"LINUX_NOT_FAT_HINT": '"{0}" <é> & café'})
        xml = path.read_text(encoding="utf-8").replace(
            '<language langid="tr"', '<language name="&quot;Quoted&quot;" langid="tr"',
        ).replace(
            "<localization", "<!-- Examples: &apos; &amp;quot; -->\n<localization", 1,
        )
        path.write_text(xml, encoding="utf-8")
        result = self.run_validator()
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_entity_diagnostic_tracks_source_lines_after_utf8_text(self):
        xml = '<localization>\n<entry key="MESSAGE">café\n&apos;</entry></localization>'
        with self.assertRaisesRegex(ValueError, "MESSAGE: unsupported XML entity '&apos;' at line 3;"):
            FORMATS.check_entry_entities(xml)

    def test_escaped_numeric_entity_text_does_not_supply_placeholders(self):
        key = "LINUX_NOT_FAT_HINT"
        path = self.write_raw_translation(key, "Platform &amp;#123;0&amp;#125;")
        result = self.run_validator()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn(f"{path}: {key}: StringFormatter references []", result.stdout)

    def test_both_basque_percent_escape_errors_are_rejected(self):
        self.assert_rejected("eu", "SYSTEM_DRIVE_ENCRYPTING", "%%.2f% eginda")
        self.assert_rejected("eu", "SYSTEM_DRIVE_PARTIALLY_ENCRYPTED", "%%.2f% zifratuta")

    def test_unreferenced_and_out_of_range_formatter_arguments_are_rejected(self):
        self.assert_rejected("th", "LINUX_NOT_FAT_HINT", "No platform argument")
        self.assert_rejected("th", "LINUX_NOT_FAT_HINT", "Platform {1}")
        self.assert_rejected("tr", "PASSWORD_UTF8_TOO_LONG", "Maximum 64 bytes")

    def test_messages_shown_without_formatting_cannot_gain_placeholders(self):
        self.assert_rejected("tr", "LEGACY_PASSWORD_UTF8_TOO_LONG", "Maximum %d bytes")
        self.assert_rejected("tr", "UNMOUNT_LOCK_FAILED", "Force unmount {0}?")

    def test_recorded_omissions_allow_only_the_recorded_argument_prefix(self):
        self.write_translation("ko", {"RESCUE_DISK_BURN_INFO_NO_CHECK": "Image: %s"})
        result = self.run_validator()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("1 recorded omissions", result.stdout)
        self.assert_rejected("ko", "RESCUE_DISK_BURN_INFO_NO_CHECK", "No image path")
        self.assert_rejected("ko", "RESCUE_DISK_BURN_INFO_NO_CHECK", "Image: %hs")

    def test_missing_key_and_malformed_xml_fail(self):
        path = self.write_translation()
        tree = ET.parse(path)
        parent = tree.getroot().find("localization")
        parent.remove(next(entry for entry in parent.findall("entry") if entry.attrib["key"] == "CAPI_RAND"))
        tree.write(path, encoding="utf-8")
        result = self.run_validator()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("CAPI_RAND: missing formatted message", result.stdout)
        path.write_text("<VeraCrypt>", encoding="utf-8")
        result = self.run_validator()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn(str(path), result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
