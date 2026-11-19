
import json
import psycopg
from psycopg.rows import dict_row
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parents[2]
outputFile = ROOT / "tmp" / "researchSummary.json"

DSN = "postgresql://postgres:crisppassword@localhost:5432/crisp"

TOP = 10             # how many targets to mark research = true
MAX_PER_PRODUCT = 3 

TYPE_SCORE = {"Firewall": 40, "VPN Endpoint": 35, "Switch": 25,
              "Access Point": 20, "SaaS": 10}

VENDORS = {"FortiClient": "Fortinet",
           "Google Chrome": "Google",
           "GoToAssist Customer 4.8.0.1702": "GoTo",
           "Parallels Client-64 bit": "Parallels"}

FILENAME_PRODUCTS = ["ContractsReport", "software export"]


sql = """
SELECT t.AssetTypeName AS "assetType",
       CASE WHEN a.Product LIKE 'FortiGate%'   THEN 'FortiOS'
            WHEN a.Product LIKE 'FortiSwitch%' THEN 'FortiSwitchOS'
            WHEN a.Product LIKE 'FP%'          THEN 'FortiAP firmware'
            ELSE a.Product END AS "product",
       a.Version AS "version",
       MIN(a.AssetName) AS "sampleName",
       COUNT(*) AS "assetCount",
       BOOL_OR(a.PublicFacing) AS "publicFacing"
FROM InventoryAsset a
JOIN AssetType t ON t.AssetTypeID = a.AssetTypeID
WHERE a.OrganizationID = 1
GROUP BY 1, 2, 3
ORDER BY "assetCount" DESC
"""


def isFilenameProduct(product):
    return any(product.startswith(name) for name in FILENAME_PRODUCTS)


def getProduct(product, sampleName):
    if isFilenameProduct(product):
        return sampleName
    return product


def getVersion(product, version):
    if isFilenameProduct(product):
        return None
    if version and any(c.isdigit() for c in version):
        return version
    return None


def getVendor(assetType, product):
    if assetType != "SaaS":
        return "Fortinet"
    return VENDORS.get(product)


def getScore(assetType, assetCount, publicFacing, version):
    score = TYPE_SCORE.get(assetType, 10)
    if publicFacing:
        score += 30
    if version:
        score += 10
    if assetCount > 10:
        score += 5
    return score


with psycopg.connect(DSN) as connection:
    connection.read_only = True
    with connection.cursor(row_factory=dict_row) as cursor:
        cursor.execute(sql)
        rows = cursor.fetchall()
        cursor.execute("SELECT COUNT(*) AS n FROM InventoryAsset")
        totalAssets = cursor.fetchone()["n"]

targets = []
for row in rows:
    product = getProduct(row["product"], row["sampleName"])
    if not product:
        continue

    version = getVersion(row["product"], row["version"])

    targets.append({
        "vendor": getVendor(row["assetType"], row["product"]),
        "product": product,
        "version": version,
        "assetType": row["assetType"],
        "assetCount": row["assetCount"],
        "publicFacing": row["publicFacing"],
        "score": getScore(row["assetType"], row["assetCount"],
                          row["publicFacing"], version),
        "research": False,
    })

targets.sort(key=lambda t: (-t["score"], -t["assetCount"], str(t["product"])))

# Mark the top ones for research. Network gear skips the per product cap because
# there are only 16 firmware targets and every version is a real exposure.
counts = {}
researchCount = 0
for target in targets:
    if researchCount >= TOP:
        break
    if target["assetType"] == "SaaS" and MAX_PER_PRODUCT:
        key = target["product"]
        counts[key] = counts.get(key, 0) + 1
        if counts[key] > MAX_PER_PRODUCT:
            continue
    target["research"] = True
    researchCount += 1

summary = {
    "generated": datetime.now().isoformat(timespec="seconds"),
    "totalAssets": totalAssets,
    "targetCount": len(targets),
    "researchCount": researchCount,
    "targets": targets,
}

outputFile.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

print("assets in database =", totalAssets)
print("targets found      =", len(targets))
print("marked to research =", researchCount)
print("done, output file = ", outputFile)
