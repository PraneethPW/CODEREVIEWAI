from __future__ import annotations

from collections import Counter
from typing import Iterable


OWASP_EDITION = "2025"
OWASP_DISCLAIMER = (
    "OWASP Top 10 category mapping is based on supported static rules. "
    "Zero findings means no matching rule evidence; it does not prove a category is absent."
)

OWASP_TOP_10 = (
    {
        "category_id": "A01:2025",
        "category_name": "Broken Access Control",
        "summary": "Authorization boundaries and access to files, records, or privileged operations.",
        "reference_url": "https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/",
    },
    {
        "category_id": "A02:2025",
        "category_name": "Security Misconfiguration",
        "summary": "Unsafe defaults, debug modes, permissive policies, and weakened platform controls.",
        "reference_url": "https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/",
    },
    {
        "category_id": "A03:2025",
        "category_name": "Software Supply Chain Failures",
        "summary": "Risk introduced through dependencies, build inputs, and untrusted software sources.",
        "reference_url": "https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/",
    },
    {
        "category_id": "A04:2025",
        "category_name": "Cryptographic Failures",
        "summary": "Weak or incorrectly applied cryptography that fails to protect sensitive data.",
        "reference_url": "https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/",
    },
    {
        "category_id": "A05:2025",
        "category_name": "Injection",
        "summary": "Untrusted data reaching an interpreter, query, command, or browser execution sink.",
        "reference_url": "https://owasp.org/Top10/2025/A05_2025-Injection/",
    },
    {
        "category_id": "A06:2025",
        "category_name": "Insecure Design",
        "summary": "Missing or ineffective security controls at the architecture and threat-model level.",
        "reference_url": "https://owasp.org/Top10/2025/A06_2025-Insecure_Design/",
    },
    {
        "category_id": "A07:2025",
        "category_name": "Authentication Failures",
        "summary": "Weak identity, credential, token, and session handling controls.",
        "reference_url": "https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/",
    },
    {
        "category_id": "A08:2025",
        "category_name": "Software or Data Integrity Failures",
        "summary": "Code or data is trusted without a sufficient integrity boundary.",
        "reference_url": "https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/",
    },
    {
        "category_id": "A09:2025",
        "category_name": "Security Logging and Alerting Failures",
        "summary": "Security-relevant events are exposed, omitted, or handled without adequate signals.",
        "reference_url": "https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/",
    },
    {
        "category_id": "A10:2025",
        "category_name": "Mishandling of Exceptional Conditions",
        "summary": "Errors, abnormal states, or resource limits are handled unsafely or silently ignored.",
        "reference_url": "https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/",
    },
)

_CATEGORY_BY_ID = {item["category_id"]: item for item in OWASP_TOP_10}

# A rule maps only when its detector produces direct source evidence for the category.
# Syntax, maintainability, and generic quality rules intentionally remain unmapped.
RULE_OWASP: dict[str, tuple[str, tuple[str, ...]]] = {
    "GEN-PATH-TRAVERSAL": ("A01:2025", ("CWE-22",)),
    "PY-DEBUG-ENABLED": ("A02:2025", ("CWE-489",)),
    "GEN-TLS-VERIFY-DISABLED": ("A02:2025", ("CWE-295",)),
    "JS-CORS-WILDCARD-CREDENTIALS": ("A02:2025", ("CWE-942",)),
    "JSON-UNPINNED-DEPENDENCY": ("A03:2025", ("CWE-829",)),
    "YAML-FLOATING-ACTION": ("A03:2025", ("CWE-829",)),
    "GEN-WEAK-HASH": ("A04:2025", ("CWE-328",)),
    "PY-UNSAFE-EVAL": ("A05:2025", ("CWE-95",)),
    "JS-UNSAFE-EVAL": ("A05:2025", ("CWE-95",)),
    "PY-SHELL-TRUE": ("A05:2025", ("CWE-78",)),
    "PY-SQL-CONCAT": ("A05:2025", ("CWE-89",)),
    "JAVA-SQL-CONCAT": ("A05:2025", ("CWE-89",)),
    "JS-DOM-SINK": ("A05:2025", ("CWE-79",)),
    "GEN-HARDCODED-SECRET": ("A07:2025", ("CWE-798",)),
    "GEN-JWT-NO-VERIFY": ("A07:2025", ("CWE-347",)),
    "GEN-UNSAFE-DESERIALIZATION": ("A08:2025", ("CWE-502",)),
    "GEN-SENSITIVE-LOGGING": ("A09:2025", ("CWE-532",)),
    "PY-BARE-EXCEPT": ("A10:2025", ("CWE-396",)),
    "GEN-SWALLOWED-EXCEPTION": ("A10:2025", ("CWE-390",)),
}


def owasp_for_rule(rule_id: str) -> dict | None:
    mapped = RULE_OWASP.get(rule_id)
    if not mapped:
        return None
    category_id, cwe_ids = mapped
    category = _CATEGORY_BY_ID[category_id]
    return {
        "edition": OWASP_EDITION,
        "category_id": category_id,
        "category_name": category["category_name"],
        "cwe_ids": list(cwe_ids),
        "coverage": "limited_static",
        "reference_url": category["reference_url"],
    }


def owasp_summary(rule_ids: Iterable[str]) -> dict:
    rule_ids = list(rule_ids)
    counts = Counter(
        mapping["category_id"]
        for rule_id in rule_ids
        if (mapping := owasp_for_rule(rule_id)) is not None
    )
    categories = []
    for category in OWASP_TOP_10:
        supported_rules = sorted(
            rule_id
            for rule_id, (category_id, _) in RULE_OWASP.items()
            if category_id == category["category_id"]
        )
        categories.append(
            {
                **category,
                "coverage": "limited_static" if supported_rules else "not_assessed",
                "finding_count": counts[category["category_id"]],
                "supported_rules": supported_rules,
            }
        )
    return {
        "edition": OWASP_EDITION,
        "mapped_findings": sum(counts.values()),
        "disclaimer": OWASP_DISCLAIMER,
        "categories": categories,
    }

