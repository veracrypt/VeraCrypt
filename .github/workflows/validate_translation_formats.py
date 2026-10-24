#!/usr/bin/env python3
"""Validate translation text and format contracts without platform-specific libraries.

Run with: python3 .github/workflows/validate_translation_formats.py [repo-root]

The key lists describe the formatting engines used by the callers. Keep them in
sync when adding formatted messages; guessing from '%' alone would misinterpret
ordinary text such as '5% larger'. Windows wide printf and wxString::Format use
the English argument types, while Main/StringFormatter.cpp has its own grammar
and requires every supplied argument to be referenced. This checks catalogues,
not C++ argument types or the reachability of their callers.
"""

import argparse
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET
from xml.parsers import expat


# These wxString::Format callers pass wide strings, as on Windows, but their
# conversions must also be portable to the macOS/Linux formatting backends.
WX_PRINTF_KEYS = {
    "KEYFILE_ALREADY_EXISTS", "ENTER_TOKEN_PASSWORD", "OVERWRITEPROMPT_DEVICE",
    "CONFIRM_VOL_HEADER_RESTORE",
}

# StringCbPrintfW/StringCchPrintf and the translated wxString::Format messages.
PRINTF_KEYS = set("""
AFTER_FORMAT_DRIVE_LETTER_WARN CANNOT_WRITE_FILE_X CANT_CREATE_FOLDER CAPI_RAND
CD_BURNER_NOT_PRESENT_WILL_STORE_ISO_INFO CHECKING_FS CONFIRM_VOL_HEADER_BAK
CREATE_FAILED DAMAGE_TO_HIDDEN_VOLUME_PREVENTED
ENTER_PASSWORD_FOR ENTER_PASSWORD_FOR_LABEL ERR_UNKNOWN
EXPANDER_ERROR_MAX_FILE_SIZE_EXCEEDED EXPANDER_ERROR_MAX_VC_VOLUME_SIZE_EXCEEDED
EXPANDER_ERROR_VOLUME_SIZE_TOO_LARGE EXPANDER_ERROR_VOLUME_SIZE_TOO_SMALL
EXPANDER_FREE_SPACE EXPANDER_HELP_DEVICE EXPANDER_HELP_FILE FORMATEX_API_FAILED
HIDVOL_HOST_FILLING_HELP HIDVOL_HOST_FILLING_HELP_SYSENC INCONSISTENCY_RESOLVED
INIT_RAND INSTALL_OF_FAILED LANG_PACK_VERSION MORE_INFO_ABOUT
MOUNTED_CONTAINER_FORCED_READ_ONLY MOUNTED_DEVICE_FORCED_READ_ONLY
MOUNTED_DEVICE_FORCED_READ_ONLY_WRITE_PROTECTION MOUNTED_VOLUME_DIRTY
NONSYS_INPLACE_DEC_CONFIRM NONSYS_INPLACE_ENC_CONFIRM NUMBER_OF_THREADS
OVERWRITEPROMPT OVERWRITEPROMPT_DEVICE_HIDDEN_OS_PARTITION
PARTIAL_SYSENC_MOUNT_READONLY PASSWORD_MAXLENGTH_REACHED
PASSWORD_OR_KEYFILE_OR_MODE_WRONG PASSWORD_OR_KEYFILE_WRONG
PASSWORD_OR_KEYFILE_WRONG_AUTOMOUNT PASSWORD_OR_MODE_WRONG PASSWORD_PASTED_TRUNCATED
PASSWORD_UTF8_TOO_LONG PASSWORD_WRONG PASSWORD_WRONG_AUTOMOUNT
PROCESSED_PORTION_X_PERCENT READONLYPROMPT REPAIRING_FS RESCUE_DISK_BURN_INFO
RESCUE_DISK_BURN_INFO_NO_CHECK RESCUE_DISK_CHECK_FAILED RESCUE_DISK_EFI_EXTRACT_INFO
RESCUE_DISK_EFI_EXTRACT_INFO_NO_CHECK RESCUE_DISK_EFI_NON_WIZARD_CREATION
RESCUE_DISK_NON_WIZARD_CREATION_BURN RESCUE_DISK_NON_WIZARD_CREATION_WIN_ISOBURN
SELECTED_PARTITION_ALREADY_INPLACE_ENC SELECTED_PARTITION_NOT_INPLACE_ENC
SKIPPED_BAD_SECTOR_COUNT SYSTEM_DRIVE_DECRYPTING SYSTEM_DRIVE_ENCRYPTING
SYSTEM_DRIVE_PARTIALLY_ENCRYPTED SYSTEM_PARTITION_DECRYPTING
SYSTEM_PARTITION_ENCRYPTING SYSTEM_PARTITION_PARTIALLY_ENCRYPTED
SYS_ENCRYPTION_PRETEST_INFO THREE_LAYER_CASCADE_HELP TWO_LAYER_CASCADE_HELP
UNEXPECTED_STATE UNINSTALL_OF_FAILED UNINSTALL_OK
VOLUME_MOUNTED_AS_DRIVE_LETTER_X_UNMOUNTED ZEROED_BAD_SECTOR_COUNT
""".split()) | WX_PRINTF_KEYS

# Tcformat.c::PrintFreeSpace selects these keys indirectly through nResourceString.
for _prefix in ("DEVICE_FREE_", "DISK_FREE_", "MAX_HIDVOL_SIZE_"):
    PRINTF_KEYS.update(_prefix + unit for unit in ("BYTES", "KB", "MB", "GB", "TB"))

STRING_FORMATTER_ARGUMENTS = {
    "CHECKING_FS": 1,
    "DAMAGE_TO_HIDDEN_VOLUME_PREVENTED": 1,
    "DISK_FREE": 1,
    "ENTER_PASSWORD_FOR": 1,
    "FORMAT_STAGE_CREATING_FILESYSTEM": 1,
    "LEGACY_PASSWORD_UTF8_TOO_LONG": 0,
    "LINUX_COMMAND_GET_ERROR": 2,
    "LINUX_CROSS_SUPPORT_ONLY": 1,
    "LINUX_EMERGENCY_UNMOUNTED": 1,
    "LINUX_EMERGENCY_UNMOUNT_WARNING": 1,
    "LINUX_EX2MSG_PASSWORDTOOLONG": 1,
    "LINUX_FREE_SPACE_ON_DRIVE": 2,
    "LINUX_MAX_HIDDEN_SIZE": 1,
    "LINUX_MOUNTET_HINT": 1,
    "LINUX_NOT_FAT_HINT": 1,
    "LINUX_OUTER_VOL_IS_MOUNTED": 1,
    "LINUX_REQUESTER_BACKED_VOLUME": 1,
    "LINUX_SYSTEM_ENC_PW_LENGTH_NOTE": 1,
    "LINUX_VOL_MOUNTED": 1,
    "LINUX_VOL_UNMOUNTED": 1,
    "LINUX_WARNING_FORMAT_DESTROY_FS": 1,
    "MACOSX_APFS_SYNTHESIZED_DEVICE": 2,
    "MACOSX_APFS_SYSTEM_STORE": 1,
    "MACOSX_DEVICE_NOT_WRITABLE": 1,
    "MACOSX_DEVICE_SYSTEM_PARTITION": 1,
    "MORE_INFO_ABOUT": 1,
    "PASSWORD_UTF8_TOO_LONG": 1,
    "REPAIRING_FS": 1,
    "THREE_LAYER_CASCADE_HELP": 6,
    "TWO_LAYER_CASCADE_HELP": 4,
    "UNMOUNT_LOCK_FAILED": 0,
    "VOLUME_ALREADY_MOUNTED": 1,
    "VOLUME_HOST_IN_USE": 1,
}

# Existing omissions awaiting translation work. printf safely ignores unused
# trailing values; StringFormatter does not. Each exception records exactly how
# many initial arguments are retained. Never exempt malformed or mistyped fields,
# or missing target identities in confirmation messages.
KNOWN_OMISSIONS = {
    (language, "INIT_RAND"): 0
    for language in "ar be bg ca cs el eu ja my pt-br ro sk uk uz vi zh-cn zh-hk zh-tw".split()
}
KNOWN_OMISSIONS.update({
    ("ko", "RESCUE_DISK_BURN_INFO_NO_CHECK"): 1,
    ("ko", "RESCUE_DISK_EFI_EXTRACT_INFO_NO_CHECK"): 1,
    ("uk", "RESCUE_DISK_BURN_INFO"): 1,
    ("uk", "RESCUE_DISK_BURN_INFO_NO_CHECK"): 1,
})
for _prefix in ("DEVICE_FREE_", "DISK_FREE_"):
    KNOWN_OMISSIONS.update({
        ("th", _prefix + unit): 0 for unit in ("BYTES", "KB", "MB", "GB", "TB")
    })

PRINTF_FIELD = re.compile(
    r"%[-+ #0]*(\*|[0-9]+)?(?:\.(\*|[0-9]*))?"
    r"(I64|I32|I|hh|ll|h|l|w|z|t|j|L)?([diouxXfFeEgGaAcCsSpn])"
)

# Windows leaves quote entities undecoded. Repeated escaping leaves entity text
# visible instead of the intended punctuation.
ENTRY_ENTITY = re.compile(rb"&(?:apos|quot);|&amp;(?:amp;)*(?:lt|gt|amp|apos|quot);")


def printf_arguments(text, *, portable=False):
    """Return Windows argument types, optionally rejecting nonportable modifiers."""
    arguments = []
    position = 0
    while position < len(text):
        if text[position] != "%":
            position += 1
            continue
        if text.startswith("%%", position):
            position += 2
            continue
        field = PRINTF_FIELD.match(text, position)
        if field is None:
            raise ValueError(f"invalid printf conversion at {text[position:position + 16]!r}")
        width, precision, length, conversion = field.groups()
        length = length or ""
        if portable and length in ("w", "I", "I32", "I64"):
            raise ValueError(f"nonportable wxString::Format conversion {field.group()!r}")
        arguments.extend("int32" for value in (width, precision) if value == "*")
        if conversion in "sScC" and length in ("", "h", "l", "w"):
            if conversion in "cC":
                argument = "int32"  # Character arguments undergo integer promotion.
            else:
                narrow = length == "h" or (not length and conversion == "S")
                argument = "narrow-string" if narrow else "wide-string"
        elif conversion in "diouxX" and length in ("", "h", "hh", "l", "ll", "I32", "I64", "I", "z", "t", "j"):
            bits = "64" if length in ("ll", "I64", "j") else (
                "ptr" if length in ("I", "z", "t") else "32"
            )
            argument = ("int" if conversion in "di" else "uint") + bits
        elif conversion in "fFeEgGaA" and length in ("", "l", "L"):
            # Distinguish fixed-point from scientific/general notation, too.
            # Otherwise Basque '%%.2f% eginda' would look like a valid double
            # argument: it prints a literal '%.2f' and consumes '% e'. MSVC long
            # double has the same representation as double.
            argument = "double:" + conversion.lower()
        elif conversion == "p" and not length:
            argument = "pointer"
        else:
            raise ValueError(f"unsupported printf conversion {field.group()!r}")
        arguments.append(argument)
        position = field.end()
    return tuple(arguments)


def formatter_arguments(text):
    """Return the referenced indices using Main/StringFormatter.cpp's grammar."""
    for conversion in ("%s", "%d", "%c"):
        text = text.replace(conversion, "{}")
    index = 0
    while "{}" in text:
        text = text.replace("{}", "{" + str(index) + "}", 1)
        index += 1

    referenced = set()
    position = 0
    while position < len(text):
        if text.startswith(("{{", "}}"), position):
            position += 2
        elif text[position] == "{":
            field = re.match(r"\{([0-9])\}", text[position:])
            if field is None:
                raise ValueError(f"invalid StringFormatter field at {text[position:position + 16]!r}")
            referenced.add(int(field.group(1)))
            position += 3
        elif text[position] == "}":
            raise ValueError("unescaped closing brace in StringFormatter text")
        else:
            position += 1
    return referenced


def check_entry_entities(xml):
    """Inspect the source entity spelling, restricted to actual entry text."""
    raw = xml.encode("utf-8")
    parser = expat.ParserCreate()
    # Expat reports each entity at its source byte offset. Buffering character
    # data would combine it with adjacent text and lose that position.
    parser.buffer_text = False
    entry_key = None

    def start(name, attributes):
        nonlocal entry_key
        if name == "entry":
            entry_key = attributes.get("key", "?")

    def end(name):
        nonlocal entry_key
        if name == "entry":
            entry_key = None

    def text(value):
        if entry_key is None:
            return
        entity = ENTRY_ENTITY.match(raw, parser.CurrentByteIndex)
        if entity is not None:
            spelling = entity.group().decode("ascii")
            problem = "repeatedly escaped" if spelling.startswith("&amp;") else "unsupported"
            raise ValueError(
                f"{entry_key}: {problem} XML entity {spelling!r} "
                f"at line {parser.CurrentLineNumber}; use literal punctuation "
                "and escape XML characters only once"
            )

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = text
    parser.Parse(raw, True)


def read_catalogue(path):
    xml = path.read_text(encoding="utf-8")
    # VeraCrypt's XML readers do not expand numeric or custom entities. Reject
    # them before ElementTree can turn them into otherwise missing format fields.
    if "<!DOCTYPE" in xml:
        raise ValueError("unsupported XML document type; use literal characters instead of custom entities")
    entity = re.search(r"&#(?:[0-9]+|x[0-9a-fA-F]+);", xml)
    if entity is not None:
        line = xml.count("\n", 0, entity.start()) + 1
        raise ValueError(
            f"unsupported numeric XML entity {entity.group()!r} at line {line}; "
            "use literal UTF-8 characters"
        )
    root = ET.fromstring(xml)
    check_entry_entities(xml)
    entries = {}
    for entry in root.iter("entry"):
        key = entry.attrib["key"]
        if key in entries:
            raise ValueError(f"duplicate key {key}")
        entries[key] = entry.text or ""
    language = root.find(".//language")
    if language is None:
        raise ValueError("missing language declaration")
    return language.attrib["langid"], entries


def check_catalogue(language, entries, reference):
    errors = []
    omissions = 0
    for key in sorted(PRINTF_KEYS | STRING_FORMATTER_ARGUMENTS.keys()):
        if key not in entries:
            errors.append(f"{key}: missing formatted message")
            continue
        try:
            if key in PRINTF_KEYS:
                expected = printf_arguments(reference[key], portable=key in WX_PRINTF_KEYS)
                actual = printf_arguments(entries[key], portable=key in WX_PRINTF_KEYS)
                if actual != expected:
                    retained = KNOWN_OMISSIONS.get((language, key))
                    if retained is not None and actual == expected[:retained] and len(actual) == retained:
                        omissions += 1
                    else:
                        errors.append(f"{key}: printf arguments {actual}, expected {expected}")
            if key in STRING_FORMATTER_ARGUMENTS:
                expected_indices = set(range(STRING_FORMATTER_ARGUMENTS[key]))
                actual_indices = formatter_arguments(entries[key])
                if actual_indices != expected_indices:
                    errors.append(
                        f"{key}: StringFormatter references {sorted(actual_indices)}, "
                        f"expected {sorted(expected_indices)}"
                    )
        except (KeyError, ValueError) as error:
            errors.append(f"{key}: {error}")
    return errors, omissions


def validate(root):
    reference_path = root / "src/Common/Language.xml"
    try:
        _, reference = read_catalogue(reference_path)
    except (OSError, ET.ParseError, KeyError, ValueError) as error:
        print(f"{reference_path}: {error}", file=sys.stderr)
        return 1
    paths = [reference_path] + sorted((root / "Translations").glob("Language.*.xml"))
    errors = []
    omissions = 0
    for path in paths:
        try:
            language, entries = read_catalogue(path)
            problems, allowed = check_catalogue(language, entries, reference)
            errors.extend(f"{path}: {problem}" for problem in problems)
            omissions += allowed
        except (OSError, ET.ParseError, KeyError, ValueError) as error:
            errors.append(f"{path}: {error}")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(
        f"Format validation passed: {len(paths)} catalogues, {len(PRINTF_KEYS)} printf "
        f"and {len(STRING_FORMATTER_ARGUMENTS)} StringFormatter contracts; "
        f"{omissions} recorded omissions."
    )
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, nargs="?", default=Path(__file__).resolve().parents[2])
    sys.exit(validate(parser.parse_args().root))
