"""
CRISP — example Research Agent.

Takes a product and version, searches trusted CVE sources, and returns a
structured list of CVEs affecting that version.

This is a standalone example of the "Research Agent" box in the CRISP design.
It is not wired to the database, the correlation engine, or the UI.

Setup:
    pip install anthropic
    export ANTHROPIC_API_KEY="sk-ant-..."     # or edit API_KEY below
    python example_agent.py
"""

import json
import os

import anthropic

# TODO: paste your real key here, or set ANTHROPIC_API_KEY in your environment.
# The environment variable wins if it is set.
API_KEY = os.environ.get("ANTHROPIC_API_KEY", "sk-ant-PLACEHOLDER")

MODEL = "claude-opus-5-5"

# The "trusted website config" from the UI notes maps onto this list. The agent
# is only allowed to search these domains, so it can't wander onto a blog and
# report a rumour as a finding.
TRUSTED_DOMAINS = [
    "nvd.nist.gov",
    "cve.org",
    "cisa.gov",
]

# Constrains the model's final answer to exactly this shape, so the result is
# usable as data instead of prose we'd have to parse.
CVE_SCHEMA = {
    "type": "object",
    "properties": {
        "product": {"type": "string"},
        "version": {"type": "string"},
        "cves": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "cve_id": {
                        "type": "string",
                        "description": "e.g. CVE-2024-21762",
                    },
                    "summary": {
                        "type": "string",
                        "description": "One or two sentences on what the flaw is.",
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"],
                    },
                    "cvss_score": {
                        "type": ["number", "null"],
                        "description": "CVSS base score, or null if not published.",
                    },
                    "affected_versions": {
                        "type": "string",
                        "description": "Version range as stated by the source.",
                    },
                    "source_url": {
                        "type": "string",
                        "description": "The advisory page this came from.",
                    },
                },
                "required": [
                    "cve_id",
                    "summary",
                    "severity",
                    "cvss_score",
                    "affected_versions",
                    "source_url",
                ],
                "additionalProperties": False,
            },
        },
    },
    "required": ["product", "version", "cves"],
    "additionalProperties": False,
}

SYSTEM_PROMPT = """You are the Research Agent for CRISP, a vulnerability assessment platform.

Given a product and version, find the CVEs that affect that specific version.

Rules:
- Only report a CVE if you found it on one of the sources you searched. Never
  recall one from memory.
- Only report a CVE if the version in question falls inside its affected range.
  If a CVE affects 7.0.x and you were asked about 7.2.4, leave it out.
- Copy the source URL you actually read into source_url.
- If you find nothing, return an empty cves list. An empty list is a valid and
  useful answer; a fabricated CVE is not.
"""

client = anthropic.Anthropic(api_key=API_KEY)


def _report_search_errors(content_blocks):
    """Server-side tool failures come back as HTTP 200, not an exception.

    A successful web_search_tool_result has a list in .content; a failed one has
    a single error object instead. Check before trusting the results.
    """
    for block in content_blocks:
        if getattr(block, "type", None) != "web_search_tool_result":
            continue
        result = block.content
        if isinstance(result, list):
            continue
        code = getattr(result, "error_code", None) or "unknown_error"
        print(f"  [warning] a web search failed: {code}")


def research(product: str, version: str, max_continuations: int = 5) -> dict:
    """Research CVEs affecting a product version. Returns the parsed result."""
    user_query = f"Find the CVEs affecting {product} version {version}."

    messages = [{"role": "user", "content": user_query}]

    response = client.messages.create(
        model=MODEL,
        max_tokens=16000,
        system=SYSTEM_PROMPT,
        messages=messages,
        thinking={"type": "adaptive"},
        output_config={
            "effort": "medium",
            "format": {"type": "json_schema", "schema": CVE_SCHEMA},
        },
        tools=[
            {
                "type": "web_search_20260209",
                "name": "web_search",
                "max_uses": 8,
                "allowed_domains": TRUSTED_DOMAINS,
            }
        ],
    )

    # The server runs its own search loop and pauses after ~10 iterations. Send
    # the conversation back and it picks up where it left off. Don't add a
    # "continue" message -- the API detects the paused turn on its own.
    continuations = 0
    while response.stop_reason == "pause_turn" and continuations < max_continuations:
        _report_search_errors(response.content)
        continuations += 1
        messages = [
            {"role": "user", "content": user_query},
            {"role": "assistant", "content": response.content},
        ]
        response = client.messages.create(
            model=MODEL,
            max_tokens=16000,
            system=SYSTEM_PROMPT,
            messages=messages,
            thinking={"type": "adaptive"},
            output_config={
                "effort": "medium",
                "format": {"type": "json_schema", "schema": CVE_SCHEMA},
            },
            tools=[
                {
                    "type": "web_search_20260209",
                    "name": "web_search",
                    "max_uses": 8,
                    "allowed_domains": TRUSTED_DOMAINS,
                }
            ],
        )

    _report_search_errors(response.content)

    # output_config.format guarantees a text block holding valid JSON.
    text = next(b.text for b in response.content if b.type == "text")
    data = json.loads(text)

    usage = response.usage
    print(
        f"  [usage] input={usage.input_tokens} output={usage.output_tokens} "
        f"searches={getattr(usage, 'server_tool_use', None)}"
    )

    return data


if __name__ == "__main__":
    if API_KEY == "sk-ant-PLACEHOLDER":
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
