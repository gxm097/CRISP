import json
import os
import anthropic
import psycopg
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
apiKeyFile = ROOT / ".env" / "claudeApiKey"
apiKey = apiKeyFile.read_text(encoding="utf-8").strip()
summaryFile = ROOT / "tmp" / "researchSummary.json"
outputFile = ROOT / "outputs" / "researchResults.json"

LIMIT = 0  # 0 = every marked target, set to 1 to test with one api call

DSN = "postgresql://postgres:crisppassword@localhost:5432/crisp"
ORGANIZATION = 1
SOURCENAME = "NVD"  # must match a SourceName row in VulnerabilitySource

MODEL = "claude-opus-5-5"

trustedDomains = [
    "nvd.nist.gov",
    "cve.org",
    "cisa.gov",
]

# What CRISP was researching
CVE_SCHEMA = {
     "type": "object",
    "properties": {
        "query": {
            "type": "object",
            "properties": {
                "vendor": {"type": ["string", "null"]},
                "product": {"type": "string"},
                "version": {"type": ["string", "null"]},
            },
            "required": ["vendor", "product", "version"],
            "additionalProperties": False,
        },

        "cves": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {

                    "cve_id": {
                        "type": "string",
                        "description": "Example: CVE-2024-21762",
                    },

                    "title": {"type": "string"},

                    "description": {"type": ["string", "null"]},

                    "vendor": {
                        "type": ["string", "null"],
                    },

                    "product": {
                        "type": ["string", "null"],
                    },

                    "platform": {
                        "type": ["string", "null"],
                    },

                    "affected_versions": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "version_start": {
                                    "type": ["string", "null"]
                                },
                                "version_end": {
                                    "type": ["string", "null"]
                                },
                            },
                            "required": [
                                "version_start",
                                "version_end",
                            ],
                            "additionalProperties": False,
                        },
                    },

                    "fixed_versions": {
                        "type": "array",
                        "items": {"type": "string"},
                    },

                    "cvss": {
                        "type": "object",
                        "properties": {
                            "version": {
                                "type": ["string", "null"]
                            },
                            "score": {
                                "type": ["number", "null"]
                            },
                            "severity": {
                                "type": "string",
                                "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"],
                            },
                            "vector": {
                                "type": ["string", "null"]
                            },
                        },
                        "required": [
                            "version",
                            "score",
                            "severity",
                            "vector",
                        ],
                        "additionalProperties": False,
                    },

                    "known_exploited": {
                        "type": ["boolean", "null"],
                    },

                    "kev": {
                        "type": ["boolean", "null"],
                    },

                    "public_exploit": {
                        "type": ["boolean", "null"],
                    },

                    "published_date": {
                        "type": ["string", "null"],
                    },

                    "sources": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "source_url": {
                                    "type": "string"
                                }
                            },
                            "required": ["source_url"],
                            "additionalProperties": False,
                        },
                    },

                    "confidence": {
                        "type": "string",
                        "enum": ["HIGH", "MEDIUM", "LOW"],
                    },
                },

                "required": [
                    "cve_id",
                    "title",
                    "description",
                    "vendor",
                    "product",
                    "platform",
                    "affected_versions",
                    "fixed_versions",
                    "cvss",
                    "known_exploited",
                    "kev",
                    "public_exploit",
                    "published_date",
                    "sources",
                    "confidence",
                ],

                "additionalProperties": False,
            },
        },
    },

    "required": ["query", "cves"],
    "additionalProperties": False,
}


systemPrompt = """You are a vulnerability research anlayst for a vulnerability assesment platform

given a product and version, find the CVEs that affect that specific version is any

Rules:
* Only report a CVE if you found it on one of the sources you searched. Never
  recall one from memory.
* Only report a CVE if the version in question falls inside its affected range.
  If a CVE affects 7.0.x and you were asked about 7.2.4, leave it out.
* Copy the source URL you actually read into source_url.
* If you find nothing, return an empty cves list. An empty list is a valid and
  useful answer
"""


client = anthropic.Anthropic(api_key=apiKey)


def callClaude(messages):
    return client.messages.create(
        model=MODEL,
        max_tokens=16000,
        system=systemPrompt,
        messages=messages,
        thinking={"type": "adaptive"},
        output_config={
            "effort": "medium",
            "format": {
                "type": "json_schema",
                "schema": CVE_SCHEMA
            },
        },
        tools=[
            {
                "type": "web_search_20260209",
                "name": "web_search",
                "max_uses": 8,
                "allowed_domains": trustedDomains,
            }
        ],
    )


def checkSearchErrors(content):
    for block in content:
        if getattr(block, "type", None) == "web_search_tool_result":
            if not isinstance(block.content, list):
                print("WARNING: web search failed")


def buildQuery(vendor, product, version):
    subject = vendor + " " + product if vendor else product
    if version:
        return "find the CVEs affecting " + subject + " version " + version
    return ("find the CVEs affecting " + subject + ". No version is known, so "
            "report CVEs for the product and give the affected ranges.")


def research(vendor, product, version, maxContinuations=5):
    userQuery = buildQuery(vendor, product, version)

    response = callClaude([{"role": "user", "content": userQuery}])

    continuations = 0
    while response.stop_reason == "pause_turn" and continuations < maxContinuations:
        checkSearchErrors(response.content)
        continuations += 1
        response = callClaude([
            {"role": "user", "content": userQuery},
            {"role": "assistant", "content": response.content},
        ])

    checkSearchErrors(response.content)

    text = next(block.text for block in response.content if block.type == "text")
    return json.loads(text)


def getScore(cvss):
    score = cvss["score"]
    if score is None or score < 0 or score > 10:
        return None
    return score


def versionKey(version):
    # "7.2.10" becomes [7, 2, 10]
    if not version:
        return None
    parts = []
    for part in version.split("."):
        if not part.isdigit():
            break
        parts.append(int(part))
    return parts or None


def getExploitStatus(cve):
    if cve["kev"] or cve["known_exploited"]:
        return "Known Exploited"
    if cve["public_exploit"]:
        return "Public Exploit"
    return "None"


def saveTarget(cursor, assessment, source, target, result):
    for cve in result["cves"]:
        cursor.execute("""
            INSERT INTO Vulnerability
                (CVE, Title, Description, Vendor, Product, CVSSScore, Severity,
                ExploitStatus, KEVFlag, FirstPublished, LastUpdated)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
            ON CONFLICT (CVE) DO UPDATE SET
                Title = EXCLUDED.Title,
                Description = EXCLUDED.Description,
                Vendor = EXCLUDED.Vendor,
                Product = EXCLUDED.Product,
                CVSSScore = EXCLUDED.CVSSScore,
                Severity = EXCLUDED.Severity,
                ExploitStatus = EXCLUDED.ExploitStatus,
                KEVFlag = EXCLUDED.KEVFlag,
                LastUpdated = CURRENT_TIMESTAMP
            RETURNING VulnerabilityID
        """,
        (
            cve["cve_id"],
            cve["title"],
            cve["description"],
            target["vendor"],
            target["product"],
            getScore(cve["cvss"]),
            cve["cvss"]["severity"].capitalize(),
            getExploitStatus(cve),
            bool(cve["kev"]),
            cve["published_date"]
        ))
        vulnerability = cursor.fetchone()[0]


        cursor.execute("""
            DELETE FROM VulnerabilityAffectedVersion WHERE VulnerabilityID = %s
            """, (vulnerability,))

        for affected in cve["affected_versions"]:
            cursor.execute("""
                INSERT INTO VulnerabilityAffectedVersion
                    (VulnerabilityID, VersionStart, VersionEnd,
                     VersionStartKey, VersionEndKey)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (vulnerability,
                 affected["version_start"],
                 affected["version_end"],
                 versionKey(affected["version_start"]),
                 versionKey(affected["version_end"])))

    urls = [source_["source_url"] for cve in result["cves"]
            for source_ in cve["sources"]]
    cursor.execute("""
        INSERT INTO ResearchResult
            (AssessmentID, SourceID, QueryText, Status, RawContent, SourceURL)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (assessment, source,
         buildQuery(target["vendor"], target["product"], target["version"]),
         "Completed",
         json.dumps(result),
         urls[0] if urls else None))



summary = json.loads(summaryFile.read_text(encoding="utf-8"))
targets = [target for target in summary["targets"] if target["research"]]
if LIMIT:
    targets = targets[:LIMIT]

outputFile.parent.mkdir(exist_ok=True)

connection = psycopg.connect(DSN)
cursor = connection.cursor()

cursor.execute("SELECT SourceID FROM VulnerabilitySource WHERE SourceName = %s",
               (SOURCENAME,))
source = cursor.fetchone()[0]


cursor.execute("""
    INSERT INTO Assessment (OrganizationID, AssessmentStart, TriggerType, Status)
    VALUES (%s, CURRENT_TIMESTAMP, 'Manual', 'Running')
    RETURNING AssessmentID
    """, (ORGANIZATION,))
assessment = cursor.fetchone()[0]
connection.commit()
print("assessment id =", assessment)

results = []
for number, target in enumerate(targets, start=1):
    print(number, "of", len(targets), "-", target["product"], target["version"])

    result = research(target["vendor"], target["product"], target["version"])
    result["assetCount"] = target["assetCount"]
    result["assetType"] = target["assetType"]
    results.append(result)

    print("   found", len(result["cves"]), "CVE(s)")

    outputFile.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    saveTarget(cursor, assessment, source, target, result)
    connection.commit()

cursor.execute("""
    UPDATE Assessment
    SET AssessmentEnd = CURRENT_TIMESTAMP, Status = 'Completed'
    WHERE AssessmentID = %s
    """, (assessment,))
connection.commit()
connection.close()

total = sum(len(result["cves"]) for result in results)
print("researched", len(results), "target(s),", total, "CVE(s) total")
print("saved to database, assessment id =", assessment)
print("done, output file = ", outputFile)
