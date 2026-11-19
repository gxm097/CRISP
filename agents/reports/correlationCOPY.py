
import psycopg
from psycopg.rows import dict_row

DSN = "postgresql://postgres:crisppassword@localhost:5432/crisp"
ORGANIZATION = 1
ASSESSMENT = 0       # 0 = newest assessment in the database

FILENAME_PRODUCTS = ["ContractsReport", "software export"]


assessmentSql = """
SELECT o.OrganizationName AS "organizationName"
FROM Assessment a
JOIN Organization o ON o.OrganizationID = a.OrganizationID
WHERE a.AssessmentID = %s
  AND a.OrganizationID = %s
"""

assetSql = """
SELECT AssetID AS "AssetID",
       AssetName AS "assetName",
       Version AS "version",
       CASE WHEN Product LIKE 'FortiGate%%'   THEN 'FortiOS'
            WHEN Product LIKE 'FortiSwitch%%' THEN 'FortiSwitchOS'
            WHEN Product LIKE 'FP%%'          THEN 'FortiAP firmware'
            ELSE Product END AS "product"
FROM InventoryAsset
WHERE OrganizationID = %s
ORDER BY AssetID
"""

vulnerabilitySql = """
SELECT VulnerabilityID AS "VulnerabilityID",
       CVE AS "cve",
       Severity AS "severity",
       Product AS "product"
FROM Vulnerability
WHERE Product IS NOT NULL
ORDER BY VulnerabilityID
"""

affectedSql = """
SELECT VulnerabilityID AS "VulnerabilityID",
       VersionStart AS "versionStart",
       VersionEnd AS "versionEnd",
       VersionStartKey AS "versionStartKey",
       VersionEndKey AS "versionEndKey"
FROM VulnerabilityAffectedVersion
ORDER BY VulnerabilityID, AffectedVersionID
"""


def isFilenameProduct(product):
    return any(str(product or "").startswith(name) for name in FILENAME_PRODUCTS)


def getProduct(product, assetName):
    if isFilenameProduct(product):
        return assetName
    return product


def getKey(product):
    return str(product or "").strip().lower()


def versionKey(version):
    # "7.2.10" becomes [7, 2, 10]
    if not version:
        return None
    parts = []
    for part in str(version).split("."):
        if not part.isdigit():
            return None
        parts.append(int(part))
    return parts or None


def compareVersions(left, right):
    if left < right:
        return -1
    elif left > right:
        return 1
    else:
        return 0


def inAffectedRange(assetVersion, startKey, endKey, startText, endText):
    installed = versionKey(assetVersion)
    if installed is None:
        return "Unknown"

    if startKey:
        if compareVersions(installed, startKey) < 0:
            return "No"
    elif startText:
        startInstalled = versionKey(startText)
        if startInstalled is not None and compareVersions(installed, startInstalled) < 0:
            return "No"

    if endKey:
        if compareVersions(installed, endKey) > 0:
            return "No"
    elif endText:
        endInstalled = versionKey(endText)
        if endInstalled is not None and compareVersions(installed, endInstalled) > 0:
            return "No"

    if startKey or endKey or startText or endText:
        return "Yes"
    return "Unknown"


def hasRange(affected):
    if affected["versionStart"]:
        return True
    if affected["versionEnd"]:
        return True
    if affected["versionStartKey"]:
        return True
    if affected["versionEndKey"]:
        return True

    return False


def getVerdict(results):
    if "Yes" in results:
        return "Yes"
    if "Unknown" in results:
        return "Unknown"
    return "No"


with psycopg.connect(DSN) as connection:
    with connection.cursor(row_factory=dict_row) as cursor:
        if ASSESSMENT:
            assessment = ASSESSMENT
        else:
            cursor.execute("""
                SELECT AssessmentID AS "assessmentId"
                FROM Assessment
                ORDER BY AssessmentID DESC
                LIMIT 1
            """)
            row = cursor.fetchone()
            if row is None:
                raise Exception("No assessments were found in the database")
            assessment = row["assessmentId"]

        cursor.execute(assessmentSql, (assessment, ORGANIZATION))
        row = cursor.fetchone()
        if row is None:
            raise Exception("Assessment " + str(assessment)
                            + " does not belong to organization " + str(ORGANIZATION))
        organizationName = row["organizationName"]

        cursor.execute(assetSql, (ORGANIZATION,))
        assets = cursor.fetchall()

        cursor.execute(vulnerabilitySql)
        vulnerabilities = cursor.fetchall()

        cursor.execute(affectedSql)
        affectedRows = cursor.fetchall()


vulnerabilitiesByProduct = {}
for vulnerability in vulnerabilities:
    key = getKey(vulnerability["product"])
    vulnerabilitiesByProduct.setdefault(key, []).append(vulnerability)

affectedByVulnerability = {}
for affected in affectedRows:
    if hasRange(affected):
        affectedByVulnerability.setdefault(affected["VulnerabilityID"], []).append(affected)


verdictCounts = {"Yes": 0, "No": 0, "Unknown": 0}
productCounts = {}
evaluatedAssets = {}
correlations = []
pairsChecked = 0

for asset in assets:
    product = getProduct(asset["product"], asset["assetName"])
    matches = vulnerabilitiesByProduct.get(getKey(product), [])
    if not matches:
        continue

    evaluatedAssets[asset["AssetID"]] = asset["version"]

    for vulnerability in matches:
        pairsChecked = pairsChecked + 1

        results = []
        matchedRange = None
        for affected in affectedByVulnerability.get(vulnerability["VulnerabilityID"], []):
            result = inAffectedRange(asset["version"], affected["versionStartKey"], affected["versionEndKey"],
                                     affected["versionStart"],
                                     affected["versionEnd"])
            results.append(result)
            if result == "Yes" and matchedRange is None:
                matchedRange = affected

        verdict = getVerdict(results)
        verdictCounts[verdict] = verdictCounts[verdict] + 1
        productCounts.setdefault(product, {"Yes": 0, "No": 0, "Unknown": 0})
        productCounts[product][verdict] = productCounts[product][verdict] + 1

        # A "No" sits outside every affected range, so there is nothing to record.
        if verdict == "Yes":
            correlations.append({"AssetID": asset["AssetID"],
                                 "assetName": asset["assetName"],
                                 "product": product,
                                 "version": asset["version"],
                                 "VulnerabilityID": vulnerability["VulnerabilityID"],
                                 "cve": vulnerability["cve"],
                                 "severity": vulnerability["severity"],
                                 "vulnerable": True,
                                 "correlationType": "Version In Range",
                                 "matchedRange": matchedRange})
        elif verdict == "Unknown":
            correlations.append({"AssetID": asset["AssetID"],
                                 "assetName": asset["assetName"],
                                 "product": product,
                                 "version": asset["version"],
                                 "VulnerabilityID": vulnerability["VulnerabilityID"],
                                 "cve": vulnerability["cve"],
                                 "severity": vulnerability["severity"],
                                 "vulnerable": False,
                                 "correlationType": "Version Unknown",
                                 "matchedRange": None})


with psycopg.connect(DSN) as writeConnection:
    with writeConnection.cursor() as writeCursor:
        for AssetID in sorted(evaluatedAssets):
            writeCursor.execute("""
                INSERT INTO AssessmentAsset
                    (AssessmentID, AssetID, AssetSnapshotVersion, EvaluationStatus)
                VALUES (%s, %s, %s, 'Evaluated')
                ON CONFLICT (AssessmentID, AssetID) DO UPDATE SET
                    AssetSnapshotVersion = EXCLUDED.AssetSnapshotVersion,
                    EvaluationStatus = EXCLUDED.EvaluationStatus
                """, (assessment, AssetID, evaluatedAssets[AssetID]))

        for correlation in correlations:
            writeCursor.execute("""
                INSERT INTO Correlation
                    (AssessmentID, AssetID, VulnerabilityID, PotentiallyVulnerable, CorrelationType)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (AssessmentID, AssetID, VulnerabilityID) DO UPDATE SET
                    PotentiallyVulnerable = EXCLUDED.PotentiallyVulnerable,
                    CorrelationType = EXCLUDED.CorrelationType
                """, (assessment,
                      correlation["AssetID"],
                      correlation["VulnerabilityID"],
                      correlation["vulnerable"],
                      correlation["correlationType"]))

    writeConnection.commit()


print("assessment             =", assessment)
print("organization           =", organizationName)
print("assets evaluated       =", len(evaluatedAssets))
print("pairs checked          =", pairsChecked)
print("potentially vulnerable =", verdictCounts["Yes"])
print("not in affected range  =", verdictCounts["No"])
print("unknown version        =", verdictCounts["Unknown"])
print("correlations written   =", len(correlations))
print("")

for product in sorted(productCounts):
    counts = productCounts[product]
    print(str(product), "- vulnerable", counts["Yes"],
          "- not affected", counts["No"],
          "- unknown", counts["Unknown"])
print("\n")

for correlation in correlations:
    if not correlation["vulnerable"]:
        continue
    if correlation["matchedRange"] is not None:
        affected = (str(correlation["matchedRange"]["versionStart"] or "no start")
                    + " to " + str(correlation["matchedRange"]["versionEnd"] or "no end"))
    print(str(correlation["assetName"]),
          "|", str(correlation["product"]),
          "|", str(correlation["version"] or "no version"),
          "|", str(correlation["cve"] or "unknown cve"),
          "|", str(correlation["severity"] or "UNKNOWN"),
          "| affected", affected)
