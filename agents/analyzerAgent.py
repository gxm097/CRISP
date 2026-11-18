import json
import os
import anthropic
import psycopg
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
apiKeyFile = ROOT / ".env" / "claudeApiKey"
apiKey = apiKeyFile.read_text(encoding="utf-8").strip()

outputFile = ROOT / "outputs" / "analyzeResults.md"

DSN = psycopg.connect(
    host = "localhost",
    dbname = "crisp",
    user = "postgres",
    password = "crisppassword"
)

trustedDomains = [
    "nvd.nist.gov",
    "cve.org",
    "cisa.gov",
]

ORGANIZATION = 1
SOURCENAME = "NVD"

MODEL = "claude-opus-5-5"

systemPrompt = """You are the CRISP Analyzer Agent for a cybersecurity vulnerability assessment platform.

Your responsibility is to evaluate a potiential vulnerable candidate from a correlation engine between an organization's inventory 
asset and collected vulnerability intelligence.

You determine whether the available evidence supports that the vulnerability applies to the asset.

You do NOT independently verify or finalize vulnerabilities. Final verification is performed by the CRISP Quality Assurance Agent.


Rules:
1. Use only the inventory information, vulnerability intelligence, correlation data, and supporting evidence provided to you.
2. Do not search for additional information unless explicitly provided with an approved research tool.
3. Never invent, assume, or infer missing technical facts that are not supported by the provided evidence.
4. Evaluate the following when available:
    * Vendor
    * Product or service
    * Platform or hardware model
    * Installed software or firmware version
    * Published affected version or version range
    * CVE identifier
    * CVSS score and severity
    * Known exploitation information
    * CISA KEV status
    * Public-facing status
    * Supporting source evidence
5. Pay particular attention to version applicability. A matching vendor and product alone does not prove that a vulnerability 
   applies when version information contradicts the match.
6. If evidence is incomplete, conflicting, or insufficient, do not represent the vulnerability as confirmed.
7. Assign exactly one vulnerbility determination:
    vunerable:
    The available evidence supports that the vulnerability applies to the asset.

    unknown:
    The product or platform appears related, but missing, incomplete, or conflicting information prevents a reliable determination.

    not_Vulnerable:
    The available evidence establishes that the vulnerability does not apply to the asset.
8. Clearly identify the evidence supporting your determination.
9. Clearly identify any missing or conflicting information that affects confidence in the determination.
10. Do not modify, scan, probe, exploit, patch, reconfigure, or otherwise interact with the monitored asset. CRISP is a read-only 
    vulnerability assessment platform.

return a structured json matching the json schema and a markdown file of the summary and remendation that need to be taken
"""

jsonSchema = {
    "vulnerabilityStatus": "vulnerable",
    "confidence": "HIGH",
    "reasoningSummary": "the installed version is whithin the vulnerable version range",
    "supportingEvidence": [],
    "missingInformation": [],
    "remendation": []

}

client = anthropic.Anthropic(api_key=apiKey)

def callClaude(messages):
    return client.messages.create(
        model=MODEL,
        max_tokens=16000,
        system=systemPrompt,
        messages=messages,
        thinking={"type": "adaptive"},
        output_config={
            "effort": "low",
            "format": {
                "type": "json_schema",
                "schema": jsonSchema
            },
        },
    )

def getPotentialCorrelations():
    with DSN.cursor() as cursor:

        cursor.execute("""
        SELECT
            CorrelationID,
            AssessmentID,
            AssetID,
            VulnerabilityID,
            PotentiallyVulnerable
        FROM Correlation
        WHERE PotentiallyVulnerable = TRUE;
        """)

        rows = cursor.fetchall()
    return rows

def getVulnerability(vulnerabilityID):
    with DSN.cursor() as cursor:

        cursor.execute("""
            SELECT
                VulnerabilityID,
                CVE,
                Title,
                Description,
                CVSSScore,
                Severity,
                ExploitStatus,
                KEVFlag,
                FirstPublished,
                LastUpdated
            FROM Vulnerability
            WHERE VulnerabilityID = %s;
        """, (vulnerabilityID,))

        row = cursor.fetchone()

    return row

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

def getAffectedVersion(vulnerabilityID):
    with DSN.cursor() as cursor:
        
            cursor.execute("""
                SELECT
                    VersionStart,
                    VersionEnd
                FROM VulnerabilityAffectedVersion
                WHERE vulnerabilityID = %s;
            """, (vulnerabilityID,))
        
            row = cursor.fetchone()
        
    return row

def prepareAnalysisMessage(vulnerability, asset, affectedVersion):
    AssetTypeID = asset[0]
    AssetName = asset[1]
    Vendor = asset[2]
    Product = asset[3]
    Version = asset[4]
    Build = asset[5]
    Hostname = asset[6]
    Description = asset[7]
    PublicFacing = asset[8]
    Status = asset[9]

    cve = vulnerability[1]
    title = vulnerability[2]
    vulnDescription = vulnerability[3]
    cvssScore = vulnerability[4]
    severity = vulnerability[5]
    affectedVersionStart = affectedVersion[0]
    affectedVersionEnd = affectedVersion[1]
    exploitStatus = vulnerability[6]



    assetMessage = f"""
        Asset Name: {AssetName}
        Vendor: {Vendor}
        Product: {Product}
        Version: {Version}
        Build: {Build}
        Host Name: {Hostname}
        Description: {Description}
        """

    vulnerabilityMessage = f"""
        CVE: {cve}
        Title: {title}
        Description: {vulnDescription}
        CVSS Score: {cvssScore}
        Severity: {severity}
        affected Version Start: {affectedVersionStart}
        affected Version End: {affectedVersionEnd}
        Exploit Status: {exploitStatus}
        """

    return assetMessage, vulnerabilityMessage

def buildQuery(assetMessage, VulnerabilityMessage):
    return ("Anayze this asset and vulnerability to determine if the asset is truly vulnerable: \nasset: " + 
            assetMessage + "\nVulnerability: " + vulnerabilityMessage)


correlations = getPotentialCorrelations()
for correlations in correlations:
     assetID = int(correlations[2])
     vulnerability = getVulnerability(assetID)
     asset = getAssetInfo(assetID)
     affectedVersions = getAffectedVersion(vulnerability[0])

     assetMessage, vulnerabilityMessage = prepareAnalysisMessage(vulnerability, asset, affectedVersions)
     query = buildQuery(assetMessage, vulnerabilityMessage)

     print(query)
