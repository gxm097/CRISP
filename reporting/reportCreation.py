import psycopg
from psycopg.rows import dict_row
from pathlib import Path
from datetime import datetime


ROOT = Path(__file__).resolve().parents[1]

OUTPUT_FILE = ROOT / "outputs" / "assessmentReport.md"

DSN = "postgresql://postgres:crisppassword@localhost:5432/crisp"

def getLatestAssessment():
    with psycopg.connect(DSN) as connection:
        with connection.cursor(row_factory=dict_row) as cursor:

            cursor.execute("""
                SELECT
                    AssessmentID AS "assessmentid",
                    OrganizationID AS "organizationID",
                    AssessmentStart AS "assessmentStart",
                    AssessmentEnd AS "assessmentEnd",
                    Status AS "status"
                FROM Assessment
                ORDER BY AssessmentID DESC
                LIMIT 1;
            """)

            return cursor.fetchone()

def getAssetCount(assessmentID):
    with psycopg.connect(DSN) as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT COUNT(*)
                FROM AssessmentAsset
                WHERE AssessmentID = %s;
            """, (assessmentID,))

            row = cursor.fetchone()

    return row[0]

def getAssessmentAssets(assessmentID):
    with psycopg.connect(DSN) as connection:
        with connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute("""
                SELECT *
                FROM AssessmentAsset
                WHERE AssessmentID = %s;
            """, (assessmentID,))

            return cursor.fetchall()

def getFindings(assessmentID):
    with psycopg.connect(DSN) as connection:
        with connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute("""
                SELECT DISTINCT f.*
                FROM Finding f
                JOIN Correlation c
                    ON c.AssetID = f.AssetID
                    AND c.VulnerabilityID = f.VulnerabilityID
                WHERE c.AssessmentID = %s;
            """, (assessmentID,))

            return cursor.fetchall()

def getAsset(assetID):
    with psycopg.connect(DSN) as connection:
        with connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute("""
                SELECT *
                FROM InventoryAsset
                WHERE AssetID = %s;
            """, (assetID,))

            return cursor.fetchone()

def getVulnerability(vulnerabilityID):
    with psycopg.connect(DSN) as connection:
        with connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute("""
                SELECT *
                FROM Vulnerability
                WHERE VulnerabilityID = %s;
            """, (vulnerabilityID,))

            return cursor.fetchone()

def getAffectedVersions(vulnerabilityID):
    with psycopg.connect(DSN) as connection:
        with connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute("""
                SELECT *
                FROM VulnerabilityAffectedVersion
                WHERE VulnerabilityID = %s;
            """, (vulnerabilityID,))

            return cursor.fetchall()

def getAnalysisResult(correlationID):
    with psycopg.connect(DSN) as connection:
        with connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute("""
                SELECT *
                FROM AnalystResult
                WHERE CorrelationID = %s;
            """, (correlationID,))

            return cursor.fetchone()

def getResearchResults(assessmentID):
    with psycopg.connect(DSN) as connection:
        with connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute("""
                SELECT *
                FROM ResearchResult
                WHERE AssessmentID = %s;
            """, (assessmentID,))

            return cursor.fetchall()

def getFurtherReview():
    with psycopg.connect(DSN) as connection:
        with connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute("""
                SELECT *
                FROM FurtherReview;
            """)

            return cursor.fetchall()

def getCorrelation(assessmentID, assetID, vulnerabilityID):
    with psycopg.connect(DSN) as connection:
        with connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute("""
                SELECT *
                FROM Correlation
                WHERE AssessmentID = %s
                  AND AssetID = %s
                  AND VulnerabilityID = %s;
            """, (
                assessmentID,
                assetID,
                vulnerabilityID
            ))

            return cursor.fetchone()


assesment = getLatestAssessment()
assessmentID = assesment["assessmentid"]
findings = getFindings(assessmentID)
assetCount = getAssetCount(assessmentID)

lines = []

# Report header
lines.append("# CRISP Assessment Report")
lines.append("")
lines.append("Generated: " + str(datetime.now()))
lines.append("")
lines.append("Assessment ID: " + str(assessmentID))
lines.append("Assessment Start: " + str(assesment["assessmentStart"]))
lines.append("Assessment End: " + str(assesment["assessmentEnd"]))
lines.append("Assessment Status: " + str(assesment["status"]))
lines.append("")

# Summary
lines.append("## Assessment Summary")
lines.append("")
lines.append("Assets Evaluated: " + str(assetCount))
lines.append("Verified Findings: " + str(len(findings)))
lines.append("")

# Findings
lines.append("## Verified Vulnerability Findings")
lines.append("")

for finding in findings:

    assetID = finding["assetid"]
    vulnerabilityID = finding["vulnerabilityid"]

    asset = getAsset(assetID)
    vulnerability = getVulnerability(vulnerabilityID)
    affectedVersions = getAffectedVersions(vulnerabilityID)

    correlation = getCorrelation(
        assessmentID,
        assetID,
        vulnerabilityID
    )

    analysis = getAnalysisResult(
        correlation["correlationid"]
    )

    lines.append("### " + str(vulnerability["cve"]))
    lines.append("")

    lines.append("**Asset:** " + str(asset["assetname"]))
    lines.append("")
    lines.append("**Vendor:** " + str(asset["vendor"]))
    lines.append("")
    lines.append("**Product:** " + str(asset["product"]))
    lines.append("")
    lines.append("**Installed Version:** " + str(asset["version"]))
    lines.append("")

    lines.append("**Title:** " + str(vulnerability["title"]))
    lines.append("")
    lines.append("**Severity:** " + str(vulnerability["severity"]))
    lines.append("")
    lines.append("**CVSS Score:** " + str(vulnerability["cvssscore"]))
    lines.append("")
    lines.append("**Exploit Status:** " + str(vulnerability["exploitstatus"]))
    lines.append("")
    lines.append("**CISA KEV:** " + str(vulnerability["kevflag"]))
    lines.append("")
    lines.append("**Priority:** " + str(finding["priority"]))
    lines.append("")

    lines.append("**Description:**")
    lines.append("")
    lines.append(str(vulnerability["description"]))
    lines.append("")

    lines.append("**Affected Versions:**")
    lines.append("")

    if affectedVersions:
        for version in affectedVersions:
            lines.append(
                "- "
                + str(version["versionstart"])
                + " to "
                + str(version["versionend"])
            )
    else:
        lines.append("- No affected-version information available")

    lines.append("")

    lines.append("**Supporting Evidence:**")
    lines.append("")

    for evidence in analysis["supportingevidence"] or []:
        lines.append("- " + evidence)

    lines.append("")

    lines.append("**Recommendations:**")
    lines.append("")

    for recommendation in analysis["recommendations"] or []:
        lines.append("- " + recommendation)

    lines.append("")
    lines.append("---")
    lines.append("")


OUTPUT_FILE.parent.mkdir(exist_ok=True)

OUTPUT_FILE.write_text(
    "\n".join(lines) + "\n",
    encoding="utf-8"
)

print("Report created:", OUTPUT_FILE)