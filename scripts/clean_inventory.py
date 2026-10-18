#!/usr/bin/env python3
"""CRISP - Clean & Standardize stage.

Turns a raw FortiManager device-tree CSV export into a flat list of typed device
records that the (separate) vulnerability matching program can iterate over.

The raw export is not tabular data: hierarchy is encoded as leading spaces in the
first column, "FSW"/"FAP" rows are group labels rather than devices, blank spacer
rows separate sites, child devices carry no hostname of their own, and firmware
versions arrive in three mutually incompatible formats.  This script resolves all
of that into one record per real device.

Outputs (written to the output directory):
    inventory_clean.json  - one record per device, ready for matching / the DB
    needs_review.csv      - devices the cleaner could not fully resolve
    clean_report.txt      - row accounting, flag tallies and validation warnings

Usage:
    python3 scripts/clean_inventory.py
    python3 scripts/clean_inventory.py <input.csv> -o <outdir>
"""

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = PROJECT_ROOT / "inputs" / "Firewall Inventory Example.csv"
DEFAULT_OUTDIR = PROJECT_ROOT / "outputs"

# Cell values that mean "no value".  "'-" is a LibreOffice/Excel artifact: a
# literal dash that the spreadsheet escaped with a leading apostrophe.
NULL_CELLS = {"", "-", "--", "'-", "'--", "n/a", "N/A", "null", "NULL", "none", "None"}

# Group-label rows and the device type they introduce.
GROUP_LABELS = {"FSW": "switch", "FAP": "ap"}

# Columns that are empty in the reference export.  They are dropped from the
# output, but the cleaner checks they really are empty so a future export that
# starts populating one of them gets reported instead of silently discarded.
DROPPABLE_COLUMNS = [
    "Auto-link Status",
    "HA Status",
    "Firmware Template",
    "Provisioning Templates",
    "Company/Organization (Device)",
    "Contact Email (Device)",
    "Contact Phone Number (Device)",
    "Address (Device)",
]

# --- Firmware string formats -------------------------------------------------
# FortiGate:   "FortiGate 7.6.7,build3704 (GA) (Mature)"
#              "FortiGate 7.2.10,build1706 (GA) (Mature),Critical Vulnerability"
RE_FW_FORTIGATE = re.compile(
    r"^FortiGate\s+(?P<version>\d+(?:\.\d+)*)\s*,\s*build(?P<build>\d+)(?P<rest>.*)$",
    re.IGNORECASE,
)
# FortiSwitch: "S248EF-v7.6.4-build1114,250821 (GA)"
RE_FW_SWITCH = re.compile(
    r"^(?P<code>[A-Za-z0-9]+)-v(?P<version>\d+(?:\.\d+)*)-build(?P<build>\d+)"
    r"\s*,\s*(?P<relday>\d{6})\s*(?:\((?P<release>[^)]*)\))?\s*$"
)
# FortiAP:     "FP431F-v7.4.5-build0734"   (no release date)
RE_FW_AP = re.compile(
    r"^(?P<code>FP[A-Za-z0-9]+)-v(?P<version>\d+(?:\.\d+)*)-build(?P<build>\d+)\s*$"
)

RE_PLACEHOLDER_NAME = re.compile(r"^\[serial-named\s+.*#\d+\]$")
RE_SITE_CODE = re.compile(r"^SG-([A-Za-z0-9]+)-")
RE_UPGRADE = re.compile(r"(?P<version>\d+(?:\.\d+)*)\s*-\s*b(?P<build>\d+)", re.IGNORECASE)
RE_AP_COUNT = re.compile(r"FortiAPs\s*\(\s*(\d+)\s*\)", re.IGNORECASE)
RE_SW_COUNT = re.compile(r"FortiSwitches\s*\(\s*(\d+)\s*\)", re.IGNORECASE)

FLAG_REASONS = {
    "missing_firmware": "no firmware version in the export - cannot be matched",
    "unparsed_firmware": "firmware string did not match a known Fortinet format",
    "missing_platform": "no platform/model in the export",
    "placeholder_name": "device name is a serial-number placeholder, not a real name",
    "imprecise_version": "version has fewer than 3 components (branch, not exact release)",
    "orphan_device": "child device appeared before any parent firewall row",
    "unknown_device_type": "could not tell whether this is a switch or an access point",
    "missing_hostname": "no hostname in the export; fell back to the device name",
    "unknown_os_family": "could not determine the OS family from platform or firmware",
}


def clean_cell(value):
    """Strip a raw cell and collapse every spelling of "empty" to None."""
    if value is None:
        return None
    text = value.strip()
    return None if text in NULL_CELLS else text


def split_version(version):
    """"7.6.4" -> ([7, 6, 4], False); "6.4" -> ([6, 4, 0], True).

    The list is always three ints so the matcher can compare tuples directly.
    The bool says the source was imprecise (a branch such as 6.4, not 6.4.0).
    """
    parts = [int(p) for p in version.split(".") if p != ""]
    imprecise = len(parts) < 3
    parts = (parts + [0, 0, 0])[:3]
    return parts, imprecise


def parse_release_day(yymmdd):
    """FortiSwitch build dates are YYMMDD: "250821" -> "2025-08-21"."""
    try:
        parsed = date(2000 + int(yymmdd[0:2]), int(yymmdd[2:4]), int(yymmdd[4:6]))
    except ValueError:
        return None
    return parsed.isoformat()


def parse_firmware(raw):
    """Parse any of the three firmware formats into a common dict."""
    out = {
        "version": None,
        "version_parts": None,
        "build": None,
        "release_date": None,
        "release_type": None,
        "vendor_flagged_critical": False,
        "firmware_code": None,
        "os_hint": None,
        "flags": [],
    }
    if raw is None:
        out["flags"].append("missing_firmware")
        return out

    match = RE_FW_FORTIGATE.match(raw)
    if match:
        rest = match.group("rest") or ""
        tokens = re.findall(r"\(([^)]*)\)", rest)
        out["release_type"] = tokens[0].strip() if tokens else None
        out["vendor_flagged_critical"] = "critical vulnerability" in rest.lower()
        out["os_hint"] = "fortios"
    else:
        match = RE_FW_SWITCH.match(raw)
        if match:
            out["release_date"] = parse_release_day(match.group("relday"))
            release = match.group("release")
            out["release_type"] = release.strip() if release else None
            out["firmware_code"] = match.group("code")
            # Switch firmware codes are S<model> (S248EF) or FS<model> (FS2F48).
            out["os_hint"] = "fortiap" if match.group("code").upper().startswith("FP") else "fortiswitchos"
        else:
            match = RE_FW_AP.match(raw)
            if match:
                out["firmware_code"] = match.group("code")
                out["os_hint"] = "fortiap"

    if not match:
        out["flags"].append("unparsed_firmware")
        return out

    out["version"] = match.group("version")
    out["build"] = match.group("build")  # string: "0734" must keep its leading zero
    parts, imprecise = split_version(out["version"])
    out["version_parts"] = parts
    if imprecise:
        out["flags"].append("imprecise_version")
    return out


def os_family_for(platform, device_type, os_hint):
    """Prefer the platform/model string, fall back to firmware shape, then type."""
    if platform:
        upper = platform.upper()
        if upper.startswith("FORTIGATE"):
            return "fortios"
        if upper.startswith("FORTISWITCH") or upper.startswith("FS"):
            return "fortiswitchos"
        if upper.startswith("FP") or upper.startswith("FORTIAP"):
            return "fortiap"
    if os_hint:
        return os_hint
    return {"firewall": "fortios", "switch": "fortiswitchos", "ap": "fortiap"}.get(device_type)


def parse_upgrade_status(raw):
    """"Available for upgrade: 7.4.12-b2902" -> ("7.4.12", "2902")."""
    if raw is None:
        return None, None
    match = RE_UPGRADE.search(raw)
    if not match:
        return None, None
    return match.group("version"), match.group("build")


def parse_controller_counter(raw):
    """"FortiAPs(4), FortiSwitches(6)" -> (6, 4)  (switches, aps)."""
    if raw is None:
        return None, None
    aps = RE_AP_COUNT.search(raw)
    switches = RE_SW_COUNT.search(raw)
    return (
        int(switches.group(1)) if switches else None,
        int(aps.group(1)) if aps else None,
    )


def site_code_for(*names):
    for name in names:
        if not name:
            continue
        match = RE_SITE_CODE.match(name)
        if match:
            return match.group(1).upper()
    return None


def clean_inventory(input_path):
    """Read the raw export and return (records, stats)."""
    with open(input_path, newline="", encoding="utf-8-sig") as handle:
        raw_rows = list(csv.reader(handle))

    if not raw_rows:
        raise SystemExit(f"{input_path}: file is empty")

    # The header row is itself indented in the export, so strip every name.
    header = [name.strip() for name in raw_rows[0]]
    index = {name: i for i, name in enumerate(header)}

    def cell(row, column):
        i = index.get(column)
        if i is None or i >= len(row):
            return None
        return clean_cell(row[i])

    records = []
    stats = {
        "input": str(input_path),
        "columns": header,
        "rows_total": len(raw_rows),
        "blank_rows": 0,
        "group_label_rows": 0,
        "vendor_flagged_critical": 0,
        "upgrade_available": 0,
        "unexpected_populated_columns": {},
        "warnings": [],
    }
    # column -> values found, for the "should be empty" check
    populated = defaultdict(set)

    current_firewall = None  # the record dict of the firewall we are inside
    current_group = None  # "switch" or "ap", set by an FSW/FAP label row
    children = defaultdict(Counter)  # firewall record id -> device_type counts

    for lineno, row in enumerate(raw_rows[1:], start=2):
        if not any((c or "").strip() for c in row):
            stats["blank_rows"] += 1
            continue

        name_raw = row[0] if row else ""
        indent = len(name_raw) - len(name_raw.lstrip(" \t"))
        name = clean_cell(name_raw)
        platform = cell(row, "Platform")
        firmware_raw = cell(row, "Firmware Version")

        # Group labels: "FSW"/"FAP" with no platform and no firmware.  Testing the
        # firmware cell as well as the indent means a re-exported file with
        # different indentation still classifies correctly.
        if name in GROUP_LABELS and platform is None and firmware_raw is None:
            current_group = GROUP_LABELS[name]
            stats["group_label_rows"] += 1
            continue

        for column in DROPPABLE_COLUMNS:
            value = cell(row, column)
            if value is not None:
                populated[column].add(value)

        flags = []

        if indent == 0:
            device_type = "firewall"
            current_group = None
        elif current_group is not None:
            device_type = current_group
        else:
            device_type = "unknown"
            flags.append("unknown_device_type")

        if device_type == "firewall":
            host_name = cell(row, "Host Name")
            if host_name is None:
                host_name = name
                flags.append("missing_hostname")
        else:
            # notes.txt: a child device inherits its parent firewall's hostname.
            if current_firewall is None:
                host_name = None
                flags.append("orphan_device")
            else:
                host_name = current_firewall["host_name"]

        if platform is None:
            flags.append("missing_platform")

        firmware = parse_firmware(firmware_raw)
        flags.extend(firmware["flags"])

        family = os_family_for(platform, device_type, firmware["os_hint"])
        if family is None:
            flags.append("unknown_os_family")

        upgrade_version, _upgrade_build = parse_upgrade_status(cell(row, "Upgrade Status"))
        # Counted here rather than off the records: the trimmed record schema no longer
        # carries either value, and both describe the input file, like the rest of the report.
        if firmware["vendor_flagged_critical"]:
            stats["vendor_flagged_critical"] += 1
        if upgrade_version is not None:
            stats["upgrade_available"] += 1
        switch_count, ap_count = (
            parse_controller_counter(cell(row, "Controller Counter"))
            if device_type == "firewall"
            else (None, None)
        )

        if name and RE_PLACEHOLDER_NAME.match(name):
            flags.append("placeholder_name")

        record = {
            "host_name": host_name,
            "device_name": name,
            "device_type": device_type,
            "platform": platform,
            "vendor": "Fortinet",
            "os_family": family,
            "firmware_raw": firmware_raw,
            "version": firmware["version"],
            "build": firmware["build"],
            "reported_switch_count": switch_count,
            "reported_ap_count": ap_count,
            "flags": sorted(set(flags)),
            "source_row": lineno,
        }
        records.append(record)

        if device_type == "firewall":
            current_firewall = record
        elif current_firewall is not None:
            children[id(current_firewall)][device_type] += 1

    stats["unexpected_populated_columns"] = {
        column: sorted(values) for column, values in populated.items()
    }

    # --- Validation ---------------------------------------------------------
    # The firewall's own Controller Counter is an independent statement of how
    # many switches and APs sit under it.  If our indentation walk disagrees,
    # the tree was misread - this is the cleaner's self-test.
    for record in records:
        if record["device_type"] != "firewall":
            continue
        counts = children[id(record)]
        for kind, column in (("switch", "reported_switch_count"), ("ap", "reported_ap_count")):
            expected = record[column]
            actual = counts[kind]
            if expected is not None and expected != actual:
                stats["warnings"].append(
                    f"{record['host_name']}: export reports {expected} {kind}(s) "
                    f"but {actual} were parsed under it (row {record['source_row']})"
                )

    # (host_name, device_name) is the device identity now that device_key is gone.
    # The "or \"\"" keeps sorting safe: an orphan_device record has host_name None,
    # which is not comparable to str.
    key_counts = Counter((r["host_name"], r["device_name"]) for r in records)
    for (host, name), count in sorted(key_counts.items(), key=lambda kv: (kv[0][0] or "", kv[0][1] or "")):
        if count > 1:
            stats["warnings"].append(
                f"duplicate device {name!r} under host {host!r} appears {count} times"
            )

    for column, values in stats["unexpected_populated_columns"].items():
        stats["warnings"].append(
            f"column {column!r} was expected to be empty but holds {len(values)} "
            f"value(s) (e.g. {values[0]!r}); it is still dropped from the output"
        )

    accounted = len(records) + stats["blank_rows"] + stats["group_label_rows"] + 1
    if accounted != stats["rows_total"]:
        stats["warnings"].append(
            f"row accounting does not balance: {stats['rows_total']} rows read but "
            f"{accounted} accounted for (1 header + {stats['blank_rows']} blank + "
            f"{stats['group_label_rows']} group labels + {len(records)} devices)"
        )
    stats["rows_accounted"] = accounted

    return records, stats


def write_outputs(records, stats, outdir):
    outdir.mkdir(parents=True, exist_ok=True)
    json_path = outdir / "inventory_clean.json"
    review_path = outdir / "needs_review.csv"
    report_path = outdir / "clean_report.txt"

    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(records, handle, indent=2, ensure_ascii=False)
        handle.write("\n")

    review_rows = [r for r in records if r["flags"]]
    with open(review_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "source_row",
                "host_name",
                "device_name",
                "device_type",
                "platform",
                "firmware_raw",
                "flags",
                "reason",
            ]
        )
        for r in review_rows:
            writer.writerow(
                [
                    r["source_row"],
                    r["host_name"] or "",
                    r["device_name"] or "",
                    r["device_type"],
                    r["platform"] or "",
                    r["firmware_raw"] or "",
                    ";".join(r["flags"]),
                    "; ".join(FLAG_REASONS.get(f, f) for f in r["flags"]),
                ]
            )

    type_counts = Counter(r["device_type"] for r in records)
    flag_counts = Counter(f for r in records for f in r["flags"])
    matchable = [r for r in records if r["version"]]
    software = Counter((r["os_family"], r["version"]) for r in matchable)

    lines = []
    lines.append("CRISP inventory cleaning report")
    lines.append("=" * 64)
    lines.append(f"input : {stats['input']}")
    lines.append(f"output: {outdir}")
    lines.append("")
    lines.append("Row accounting")
    lines.append("-" * 64)
    lines.append(f"  rows in file         : {stats['rows_total']}")
    lines.append("  header rows          : 1")
    lines.append(f"  blank spacer rows    : {stats['blank_rows']} (dropped)")
    lines.append(f"  FSW/FAP group labels : {stats['group_label_rows']} (consumed, not devices)")
    lines.append(f"  device records       : {len(records)}")
    lines.append(f"  accounted for        : {stats['rows_accounted']}")
    lines.append("")
    lines.append("Devices by type")
    lines.append("-" * 64)
    for device_type, count in sorted(type_counts.items()):
        lines.append(f"  {device_type:<10} {count}")
    lines.append("")
    lines.append("Matching readiness")
    lines.append("-" * 64)
    lines.append(f"  with a parsed version : {len(matchable)}")
    lines.append(f"  needing review        : {len(review_rows)} -> needs_review.csv")
    lines.append(f"  vendor-flagged critical: {stats['vendor_flagged_critical']}")
    lines.append(f"  upgrade available      : {stats['upgrade_available']}")
    lines.append("")
    lines.append("Flags")
    lines.append("-" * 64)
    if flag_counts:
        for flag, count in sorted(flag_counts.items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"  {flag:<22} {count:>3}  {FLAG_REASONS.get(flag, '')}")
    else:
        lines.append("  none")
    lines.append("")
    lines.append("Dropped columns (empty in this export)")
    lines.append("-" * 64)
    for column in DROPPABLE_COLUMNS:
        note = "" if column not in stats["unexpected_populated_columns"] else "  <-- NOT EMPTY, see warnings"
        lines.append(f"  {column}{note}")
    lines.append("")
    lines.append("Distinct software the matcher will see")
    lines.append("-" * 64)
    for (family, version), count in sorted(software.items(), key=lambda kv: (kv[0][0] or "", kv[0][1])):
        lines.append(f"  {family:<16} {version:<10} {count:>3} device(s)")
    lines.append("")
    lines.append("Validation warnings")
    lines.append("-" * 64)
    if stats["warnings"]:
        for warning in stats["warnings"]:
            lines.append(f"  ! {warning}")
    else:
        lines.append("  none - every firewall's reported switch/AP counts matched the")
        lines.append("  devices parsed beneath it, and row accounting balances.")
    lines.append("")

    report = "\n".join(lines)
    with open(report_path, "w", encoding="utf-8") as handle:
        handle.write(report)

    return report, json_path, review_path, report_path


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Clean and standardize a FortiManager inventory CSV export."
    )
    parser.add_argument(
        "input", nargs="?", default=str(DEFAULT_INPUT), help=f"input CSV (default: {DEFAULT_INPUT})"
    )
    parser.add_argument(
        "-o", "--outdir", default=str(DEFAULT_OUTDIR), help=f"output directory (default: {DEFAULT_OUTDIR})"
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="do not print the report")
    args = parser.parse_args(argv)

    input_path = Path(args.input).expanduser()
    if not input_path.is_file():
        parser.error(f"input file not found: {input_path}")

    records, stats = clean_inventory(input_path)
    report, json_path, review_path, report_path = write_outputs(
        records, stats, Path(args.outdir).expanduser()
    )

    if not args.quiet:
        print(report)
    print(f"wrote {json_path}")
    print(f"wrote {review_path}")
    print(f"wrote {report_path}")
    return 1 if stats["warnings"] else 0


if __name__ == "__main__":
    sys.exit(main())
