import json
import os
import anthropic

APIKEY = os.environ.get("ANTHROPIC_API_KEY")

MODEL = "claude-opus-5-5"

trustedDomains = [
    "nvd.nist.gov",
    "cve.org",
    "cisa.gov",
]

CVE_SCHEMA = {
     "type": "object",
    "properties": {

        # What CRISP was researching
        "query": {
            "type": "object",
            "properties": {
                "vendor": {"type": "string"},
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



client = anthropic.Anthropic(api_key=APIKEY)


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



def research(product: str, version: str, maxContinuations: int = 2) -> dict:
    userQuery = f"find the CVEs affecting {product} version {version}"

    MESSAGES = [{"role": "user", "content": userQuery}]

    response = callClaude(MESSAGES)

    continuations = 0
    while response.stopReason == "pause_turn" and continuations < maxContinuations:
        checkSearchErrors(response.content)
        continuations += 1
        messages = [
            {
                "role": "user",
                "content": userQuery
            },
            {
                "role": "assistant",
                "content": response.content
            }
        ]

        response = callClaude(messages)

        if response.stop_reason == "pause_turn":
            raise RuntimeError("Research did not finish")
        checkSearchErrors(response.content)

        text = next(
            block.text
            for block in response.content
            if block.typ == "text"
        )
    return json.loads(text)


if __name__ == "__main__":
    if APIKEY == "sk-ant-PLACEHOLDER":
        raise SystemExit(
            "No API key set. Edit API_KEY in this file, or run:\n"
            '    export ANTHROPIC_API_KEY="sk-ant-..."'
        )

    PRODUCT, VERSION = "FortiOS", "7.2.4"

    print(f"Researching {PRODUCT} {VERSION} ...")
    result = research(PRODUCT, VERSION)

    cves = result["cves"]
    print(f"\nFound {len(cves)} CVE(s) affecting {PRODUCT} {VERSION}:\n")
    for cve in cves:
        score = cve["cvss_score"]
        score = f"{score}" if score is not None else "n/a"
        print(f"  {cve['cve_id']}  [{cve['severity']} / CVSS {score}]")
        print(f"    {cve['summary']}")
        print(f"    affects: {cve['affected_versions']}")
        print(f"    source:  {cve['source_url']}\n")


