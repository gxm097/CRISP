import argparse
import csv
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import psycopg
from psycopg.rows import dict_row


ROOT = Path(__file__).resolve().parents[2]
OUTPUT_FILE = ROOT / "outputs" / "correlationReport.txt"
CSV_OUTPUT_FILE = ROOT / "outputs" / "correlationReport.csv"
JSON_OUTPUT_FILE = ROOT / "outputs" / "correlationReport.json"
DSN = "postgresql://postgres:crisppassword@localhost:5432/crisp"


parser = argparse.ArgumentParser(description="Build a text report from database correlations")
parser.add_argument("--assessment", type=int, help="Assessment ID to report")
parser.add_argument("--organization", type=int, required=True, help="Organization ID allowed to view this report")
parser.add_argument("--generated-by", type=int, required=True, help="User Account ID that generated the report")
args = parser.parse_args()

if not DSN:
    raise RuntimeError("CRISP_DSN environment variable is required")


with psycopg.connect(DSN) as connection:
    with connection.cursor(row_factory=dict_row) as cursor:
        if args.assessment:
            assessment_id = args.assessment
        else:
            cursor.execute("""
                SELECT AssessmentID
                FROM Assessment
                ORDER BY AssessmentID DESC
                LIMIT 1
            """)
            row = cursor.fetchone()
            if row is None:
                raise Exception("No assessments were found in the database")
            assessment_id = row["assessmentid"]

        cursor.execute("""
            SELECT a.AssessmentID,
                   a.AssessmentStart,
                   a.AssessmentEnd,
                   a.Status,
                   o.OrganizationID,
                   o.OrganizationName
            FROM Assessment a
            JOIN Organization o ON o.OrganizationID = a.OrganizationID
            WHERE a.AssessmentID = %s
        """, (assessment_id,))
        assessment = cursor.fetchone()

        if assessment is None:
            raise Exception("Assessment ID " + str(assessment_id) + " was not found")

        if args.organization is not None:
            if assessment["organizationid"] != args.organization:
                raise PermissionError("Organization is not authorized to access this assessment")

            cursor.execute("""
                SELECT 1
                FROM user_account
                WHERE user_id = %s AND organization_id = %s
            """, (args.generated_by, args.organization))
            if cursor.fetchone() is None:
                raise PermissionError("Generated-by user is not authorized for this organization")

        cursor.execute("""
            SELECT COUNT(*) AS count
            FROM AssessmentAsset
            WHERE AssessmentID = %s
        """, (assessment_id,))
        assessed_asset_count = cursor.fetchone()["count"]

        cursor.execute("""
            SELECT COUNT(*) AS count
            FROM Correlation
            WHERE AssessmentID = %s
        """, (assessment_id,))
        correlation_count = cursor.fetchone()["count"]

        cursor.execute("""
            SELECT COUNT(DISTINCT VulnerabilityID) AS count
            FROM Correlation
            WHERE AssessmentID = %s
        """, (assessment_id,))
        vulnerability_count = cursor.fetchone()["count"]

        cursor.execute("""
            SELECT
                c.CorrelationID,
                c.CorrelationType,
                aa.AssetSnapshotVersion,
                aa.EvaluationStatus,
                a.AssetID,
                a.AssetName,
                a.Hostname,
                a.Vendor,
                a.Product,
                a.Version,
                a.Build,
                a.Description AS AssetDescription,
                a.Status AS AssetStatus,
                a.PublicFacing,
                a.AssetCreatedDate,
                a.AssetLastUpdated,
                t.AssetTypeName,
                v.VulnerabilityID,
                v.CVE,
                v.Title,
                v.Description,
                v.CVSSScore,
                v.Severity,
                v.ExploitStatus,
                v.KEVFlag,
                v.FirstPublished,
                v.LastUpdated,
                ar.Determination,
                f.Priority,
                f.FindingStatus,
                fv.VerifiedAt
            FROM Correlation c
            JOIN AssessmentAsset aa
              ON aa.AssessmentID = c.AssessmentID
             AND aa.AssetID = c.AssetID
            JOIN InventoryAsset a ON a.AssetID = c.AssetID
            JOIN AssetType t ON t.AssetTypeID = a.AssetTypeID
            JOIN Vulnerability v ON v.VulnerabilityID = c.VulnerabilityID
            LEFT JOIN AnalystResult ar
              ON ar.CorrelationID = c.CorrelationID
            LEFT JOIN Finding f
              ON f.AssetID = c.AssetID
             AND f.VulnerabilityID = c.VulnerabilityID
            LEFT JOIN FindingVerification fv
              ON fv.FindingID = f.FindingID
             AND fv.AssessmentID = c.AssessmentID
            WHERE c.AssessmentID = %s
            ORDER BY
                CASE WHEN v.Severity IS NULL THEN 6
                     WHEN UPPER(v.Severity) = 'CRITICAL' THEN 1
                     WHEN UPPER(v.Severity) = 'HIGH' THEN 2
                     WHEN UPPER(v.Severity) = 'MEDIUM' THEN 3
                     WHEN UPPER(v.Severity) = 'LOW' THEN 4
                     ELSE 5
                END,
                v.CVE,
                a.AssetName
        """, (assessment_id,))
        findings = cursor.fetchall()

        cursor.execute("""
            SELECT VulnerabilityID,
                   VersionStart,
                   VersionEnd,
                   VersionStartKey,
                   VersionEndKey
            FROM VulnerabilityAffectedVersion
            ORDER BY VulnerabilityID, AffectedVersionID
        """)
        affected_rows = cursor.fetchall()

        cursor.execute("""
            SELECT r.SourceURL,
                   r.RetrievedAt,
                   r.Status,
                   r.QueryText,
                   r.RawContent,
                   r.AssetID,
                   s.SourceName
            FROM ResearchResult r
            JOIN VulnerabilitySource s ON s.SourceID = r.SourceID
            WHERE r.AssessmentID = %s
              AND r.SourceURL IS NOT NULL
            ORDER BY r.RetrievedAt
        """, (assessment_id,))
        research_sources = cursor.fetchall()


def version_key(version):
    if not version:
        return None
    parts = []
    for part in str(version).split("."):
        if not part.isdigit():
            return None
        parts.append(int(part))
    return parts or None


def compare_versions(left, right):
    length = max(len(left), len(right))
    left_padded = left + [0] * (length - len(left))
    right_padded = right + [0] * (length - len(right))
    return (left_padded > right_padded) - (left_padded < right_padded)


def in_affected_range(asset_version, start_key, end_key, start_text, end_text):
    installed = version_key(asset_version)
    if installed is None:
        return "Unknown"

    if start_key:
        if compare_versions(installed, start_key) < 0:
            return "No"
    elif start_text:
        start_installed = version_key(start_text)
        if start_installed is not None and compare_versions(installed, start_installed) < 0:
            return "No"

    if end_key:
        if compare_versions(installed, end_key) > 0:
            return "No"
    elif end_text:
        end_installed = version_key(end_text)
        if end_installed is not None and compare_versions(installed, end_installed) > 0:
            return "No"

    if start_key or end_key or start_text or end_text:
        return "Yes"
    return "Unknown"


affected_versions = {}
for row in affected_rows:
    vulnerability_id = row["vulnerabilityid"]
    affected_versions.setdefault(vulnerability_id, []).append(row)

severity_counts = {
    "CRITICAL": 0,
    "HIGH": 0,
    "MEDIUM": 0,
    "LOW": 0,
    "UNKNOWN": 0,
}

kev_count = 0
public_exploit_count = 0
public_facing_count = 0
for finding in findings:
    severity = (finding["severity"] or "UNKNOWN").upper()
    if severity not in severity_counts:
        severity_counts["UNKNOWN"] += 1
    else:
        severity_counts[severity] += 1
    if finding["kevflag"]:
        kev_count += 1
    if finding["exploitstatus"] in ("Known Exploited", "Public Exploit"):
        public_exploit_count += 1
    if finding["publicfacing"]:
        public_facing_count += 1

sources_by_asset_cve = {}
for source in research_sources:
    cves = []
    if source["rawcontent"]:
        try:
            raw = json.loads(source["rawcontent"])
            cves = [cve.get("cve_id") for cve in raw.get("cves", [])
                    if cve.get("cve_id")]
        except (json.JSONDecodeError, AttributeError):
            cves = []

    if not cves:
        cves = ["Unknown CVE"]

    for cve in cves:
        key = (source["assetid"], cve)
        sources_by_asset_cve.setdefault(key, set()).add(
            str(source["sourcename"] or "Unknown source")
            + " - " + str(source["sourceurl"])
            + " (" + str(source["status"] or "Unknown status")
            + ", retrieved " + str(source["retrievedat"] or "unknown time") + ")"
        )

partial_data = []
report_findings = []
for finding in findings:
    rows = affected_versions.get(finding["vulnerabilityid"], [])
    range_results = []
    for row in rows:
        start_text = row["versionstart"]
        end_text = row["versionend"]
        range_results.append(in_affected_range(
            finding["assetsnapshotversion"] or finding["version"],
            row["versionstartkey"],
            row["versionendkey"],
            start_text,
            end_text,
        ))

    if range_results:
        if "Yes" in range_results:
            affected_result = "Yes"
        elif "Unknown" in range_results:
            affected_result = "Unknown"
        else:
            affected_result = "No"
    else:
        affected_result = "Unknown"

    finding_data = {
        "asset_id": finding["assetid"],
        "asset_name": finding["assetname"],
        "hostname": finding["hostname"],
        "asset_type": finding["assettypename"],
        "vendor": finding["vendor"],
        "product": finding["product"],
        "installed_version": finding["assetsnapshotversion"] or finding["version"],
        "public_facing": bool(finding["publicfacing"]),
        "cve": finding["cve"],
        "title": finding["title"],
        "severity": finding["severity"] or "UNKNOWN",
        "cvss_score": finding["cvssscore"],
        "exploit_status": finding["exploitstatus"],
        "kev": bool(finding["kevflag"]),
        "finding_priority": finding["priority"],
        "finding_status": finding["findingstatus"],
        "correlation_type": finding["correlationtype"],
        "analyst_determination": finding["determination"],
        "verified_at": finding["verifiedat"],
        "affected_range_result": affected_result,
        "affected_versions": rows,
    }
    report_findings.append(finding_data)

    if affected_result == "Unknown":
        partial_data.append(str(finding["assetname"]) + " / " + str(finding["cve"] or "Unknown CVE") + " - affected range or installed version unavailable")

lines = []
lines.append("CRISP Correlation Report")
lines.append("========================")
lines.append("Generated At: " + datetime.now(timezone.utc).isoformat())
lines.append("Organization: " + str(assessment["organizationname"]))
lines.append("Assessment ID: " + str(assessment["assessmentid"]))
lines.append("Assessment Start: " + str(assessment["assessmentstart"] or "Not set"))
lines.append("Assessment End: " + str(assessment["assessmentend"] or "Not set"))
lines.append("Assessment Status: " + str(assessment["status"] or "Not set"))
lines.append("")

lines.append("Summary")
lines.append("-------")
lines.append("Assets assessed: " + str(assessed_asset_count))
lines.append("Asset/CVE correlations: " + str(correlation_count))
lines.append("Unique vulnerabilities: " + str(vulnerability_count))
lines.append("Critical findings: " + str(severity_counts["CRITICAL"]))
lines.append("High findings: " + str(severity_counts["HIGH"]))
lines.append("Medium findings: " + str(severity_counts["MEDIUM"]))
lines.append("Low findings: " + str(severity_counts["LOW"]))
lines.append("Unknown severity findings: " + str(severity_counts["UNKNOWN"]))
lines.append("Known Exploited Vulnerability matches: " + str(kev_count))
lines.append("Public exploit matches: " + str(public_exploit_count))
lines.append("Correlations on public-facing assets: " + str(public_facing_count))
lines.append("")

lines.append("Partial or Missing Data")
lines.append("-----------------------")
if partial_data:
    lines.extend(partial_data)
else:
    lines.append("No partial data was identified.")
lines.append("")

lines.append("Asset and Vulnerability Details")
lines.append("--------------------------------")
if not findings:
    lines.append("No correlations were found for this assessment.")
else:
    for finding in findings:
        finding_data = next(item for item in report_findings
                            if item["asset_id"] == finding["assetid"]
                            and item["cve"] == finding["cve"])
        lines.append("Asset: " + str(finding["assetname"]))
        lines.append("Hostname: " + str(finding["hostname"] or "Not listed"))
        lines.append("Asset Type: " + str(finding["assettypename"] or "Not listed"))
        lines.append("Vendor: " + str(finding["vendor"] or "Not listed"))
        lines.append("Product: " + str(finding["product"] or "Not listed"))
        lines.append("Version: " + str(finding["assetsnapshotversion"] or finding["version"] or "Not listed"))
        lines.append("Public Facing: " + ("Yes" if finding["publicfacing"] else "No"))
        lines.append("CVE: " + str(finding["cve"] or "Not listed"))
        lines.append("Title: " + str(finding["title"] or "Not listed"))
        lines.append("Severity: " + str(finding["severity"] or "UNKNOWN"))
        lines.append("CVSS Score: " + str(finding["cvssscore"] if finding["cvssscore"] is not None else "Not listed"))
        lines.append("Exploit Status: " + str(finding["exploitstatus"] or "None"))
        lines.append("Known Exploited: " + ("Yes" if finding["kevflag"] else "No"))
        lines.append("Finding Priority: " + str(finding["priority"] or "Not set"))
        lines.append("Finding Status: " + str(finding["findingstatus"] or "Not set"))
        lines.append("Correlation Type: " + str(finding["correlationtype"] or "Not set"))
        lines.append("Analyst Determination: " + str(finding["determination"] or "Not recorded"))
        lines.append("Verified At: " + str(finding["verifiedat"] or "Not recorded"))

        rows = affected_versions.get(finding["vulnerabilityid"], [])
        if rows:
            ranges = []
            for row in rows:
                ranges.append((row["versionstart"] or "No start listed") + " to " + (row["versionend"] or "No end listed"))
            lines.append("Affected Versions: " + "; ".join(ranges))
        else:
            lines.append("Affected Versions: Not listed")
        lines.append("Installed Version In Affected Range: " + finding_data["affected_range_result"])

        lines.append("Research Sources:")
        sources = sources_by_asset_cve.get((finding["assetid"], finding["cve"]), set())
        if sources:
            for source in sorted(sources):
                lines.append("  " + source)
        else:
            lines.append("  No research source found for this asset and CVE.")

        lines.append("Description: " + str(finding["description"] or "Not listed"))
        lines.append("")

lines.append("Research Sources")
lines.append("----------------")
if not research_sources:
    lines.append("No research source URLs were found for this assessment.")
else:
    source_pairs = set()
    for (asset_id, cve), sources in sources_by_asset_cve.items():
        for source in sources:
            source_pairs.add((str(asset_id or "Unknown asset"), cve, source))
    for asset_id, cve, source in sorted(source_pairs):
        lines.append("Asset " + asset_id + " / " + cve + " - " + source)

OUTPUT_FILE.parent.mkdir(exist_ok=True)
report_text = "\n".join(lines) + "\n"
OUTPUT_FILE.write_text(report_text, encoding="utf-8")

csv_fields = [
    "asset_id", "asset_name", "hostname", "asset_type", "vendor", "product",
    "installed_version", "public_facing", "cve", "title", "severity",
    "cvss_score", "exploit_status", "kev", "finding_priority", "finding_status",
    "correlation_type", "analyst_determination", "verified_at",
    "affected_range_result",
]
with CSV_OUTPUT_FILE.open("w", newline="", encoding="utf-8") as csv_file:
    writer = csv.DictWriter(csv_file, fieldnames=csv_fields, extrasaction="ignore")
    writer.writeheader()
    for finding in report_findings:
        csv_finding = dict(finding)
        csv_finding["public_facing"] = "Yes" if finding["public_facing"] else "No"
        csv_finding["kev"] = "Yes" if finding["kev"] else "No"
        if finding["verified_at"] is not None:
            csv_finding["verified_at"] = str(finding["verified_at"])
        writer.writerow(csv_finding)

json_report = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "organization": assessment["organizationname"],
    "assessment_id": assessment["assessmentid"],
    "assessment_start": str(assessment["assessmentstart"] or ""),
    "assessment_end": str(assessment["assessmentend"] or ""),
    "assessment_status": assessment["status"],
    "summary": {
        "assets_assessed": assessed_asset_count,
        "asset_cve_correlations": correlation_count,
        "unique_vulnerabilities": vulnerability_count,
        "critical_findings": severity_counts["CRITICAL"],
        "high_findings": severity_counts["HIGH"],
        "medium_findings": severity_counts["MEDIUM"],
        "low_findings": severity_counts["LOW"],
        "unknown_severity_findings": severity_counts["UNKNOWN"],
        "kev_matches": kev_count,
        "public_exploit_matches": public_exploit_count,
        "public_facing_correlations": public_facing_count,
    },
    "partial_data": partial_data,
    "findings": report_findings,
}
JSON_OUTPUT_FILE.write_text(json.dumps(json_report, indent=2, default=str) + "\n", encoding="utf-8")

organization_id = assessment["organizationid"]

with psycopg.connect(DSN) as report_connection:
    with report_connection.cursor() as report_cursor:
        report_cursor.execute("""
            INSERT INTO Report
                (OrganizationID, GeneratedByUserID, ReportType, PeriodStart, PeriodEnd)
            VALUES (%s, %s, %s, %s, %s)
        """, (
            organization_id,
            args.generated_by,
            "Correlation Report",
            assessment["assessmentstart"],
            assessment["assessmentend"],
        ))

    report_connection.commit()

print("Assessment:", assessment_id)
print("Assets assessed:", assessed_asset_count)
print("Correlations:", correlation_count)
print("Report written to:", OUTPUT_FILE)
print("CSV written to:", CSV_OUTPUT_FILE)
print("JSON written to:", JSON_OUTPUT_FILE)
