import json
import psycopg
from psycopg.rows import dict_row

DSN = psycopg.connect(
    host = "localhost",
    dbname = "crisp",
    user = "postgres",
    password = "crisppassword"
)

def getAnalysisResult():
    with DSN.cursor(row_factory=dict_row) as cursor:
        cursor.execute("""
            SELECT
                AnalysisResultID AS "analysisID",
                CorrelationID AS "correlationID",
                VulnerabilityStatus AS "vulnerabilityStatus",
                Confidence AS "confidence",
                SupportingEvidence AS "supportingEvidence",
                MissingInformation AS "missingInformation",
                Recommendations AS "recommendations"
            FROM AnalystResult
            ORDER BY AnalysisResultID DESC;
        """)

        rows = cursor.fetchall()
    return rows

def getAssetID(correlationID):
    with DSN.cursor(row_factory=dict_row) as cursor:
            cursor.execute("""
                SELECT
                    AssetID AS "assetID"
                FROM Correlation WHERE CorrelationID = %s;
            """, (correlationID, ))
    
            row = cursor.fetchone()
    return row["assetID"]

def getVulnerabilityID(correlationID):
    with DSN.cursor(row_factory=dict_row) as cursor:
            cursor.execute("""
                SELECT
                    VulnerabilityID AS "vulnerabilityID"
                FROM Correlation WHERE CorrelationID = %s;
            """, (correlationID, ))
    
            row = cursor.fetchone()
    return row["vulnerabilityID"]

def getAssetInfo(assetID):
    with DSN.cursor() as cursor:
    
            cursor.execute("""
                SELECT
                    AssetTypeID,
                    AssetName,
                    Vendor,
                    Product,
                    Version,
                    Build,
                    Hostname,
                    Description,
                    PublicFacing,
                    Status
                FROM InventoryAsset
                WHERE assetID = %s;
            """, (assetID,))
    
            row = cursor.fetchone()
    
    return row

def getVulnerabilityInfo(VulnerabilityID):
    with DSN.cursor() as cursor:
    
            cursor.execute("""
                SELECT *
                FROM Vulnerability
                WHERE VulnerabilityID = %s;
            """, (VulnerabilityID,))
    
            row = cursor.fetchone()
    
    return row     


def getAffectedVersions(vulnerabilityID):
    with DSN.cursor(row_factory=dict_row) as cursor:

            cursor.execute("""
                SELECT
                    VersionStart AS "start",
                    VersionEnd AS "end"
                FROM VulnerabilityAffectedVersion
                WHERE VulnerabilityID = %s;
            """, (vulnerabilityID,))
    
            row = cursor.fetchone()
    
    if row is None:
        return None, None
    return row["start"], row["end"]

def qaCheck(analysis, asset, vulnerability, affectedVersionStart, affectedVersionEnd):

    if analysis["vulnerabilityStatus"] == "unknown":
        return "Further Review"

    if asset is None or vulnerability is None:
        return "Further Review"

    if analysis["confidence"] == "LOW":
        return "Further Review"

    if not analysis["supportingEvidence"]:
        return "Rejected"

    if analysis["vulnerabilityStatus"] == "vulnerable":
        return "Verified"

    if analysis["vulnerabilityStatus"] == "not_vulnerable":
        return "Verified"

    return "Further Review"

def getPriorityScore(vulnerabilityID):
    with DSN.cursor() as cursor:
            cursor.execute("""
                SELECT
                    CVSSScore
                FROM Vulnerability
                WHERE VulnerabilityID = %s;
            """, (vulnerabilityID,))
            row = cursor.fetchone()
    
    if row is None:
        return None
    return row

def saveFurtherReview(analysisResultID, reason):
    with DSN.cursor() as cursor:
        cursor.execute("""
            INSERT INTO QAFurtherReview
                (AnalysisResultID, Reason)
            VALUES (%s, %s)

            ON CONFLICT (AnalysisResultID)
            DO UPDATE SET
                Reason = EXCLUDED.Reason;
        """, (
            analysisResultID,
            reason
        ))

    DSN.commit()

def saveVerifiedFinding(organizationID, assetID, vulnerabilityID, priority):

    with DSN.cursor() as cursor:
        cursor.execute("""
            INSERT INTO Finding
            (
                OrganizationID,
                AssetID,
                VulnerabilityID,
                Priority,
                FindingStatus,
                FirstDetected,
                LastVerified
            )
            VALUES
            (
                %s,
                %s,
                %s,
                %s,
                'Open',
                CURRENT_TIMESTAMP,
                CURRENT_TIMESTAMP
            );
        """, (
            organizationID,
            assetID,
            vulnerabilityID,
            priority
        ))

    DSN.commit()

analysisResult = getAnalysisResult()
organizationID = 1
for analysis in analysisResult:
    correlationID = analysis["correlationID"]
    assetID = getAssetID(correlationID)
    asset = getAssetInfo(assetID)
    vulnerabilityID = getVulnerabilityID(correlationID)
    vulnerability = getVulnerabilityInfo(vulnerabilityID)
    affectedVersionStart, affectedVersionEnd = getAffectedVersions(vulnerabilityID)

    verdict = qaCheck(analysis, asset, vulnerability, affectedVersionStart, affectedVersionEnd)
    print("asset: ", assetID, "\n   verdict: ", verdict)

    if verdict == "Further Review":
        reason = analysis["supportingEvidence"]
        analysisID = analysis["analysisID"]
        #saveFurtherReview(analysisID, reason)
    elif verdict == "Verified":
         priority = getPriorityScore(vulnerabilityID)
         saveVerifiedFinding(organizationID, assetID, vulnerabilityID, priority)
