"""
Detection rules for the WAF.

Each rule has an ID, a category, a human-readable description and a compiled
regular expression. Rules are matched against *normalised* (fully decoded,
lower-cased) input, so attackers cannot bypass them with simple URL-encoding,
double-encoding or HTML entities.
"""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    description: str
    pattern: re.Pattern


def _r(rule_id, category, description, regex):
    return Rule(rule_id, category, description, re.compile(regex, re.IGNORECASE))


# ---------------------------------------------------------------------------
# SQL Injection
# ---------------------------------------------------------------------------
SQLI_RULES = [
    _r("SQLI-001", "SQL Injection", "UNION-based SELECT",
       r"\bunion\b[\s\S]{0,40}?\bselect\b"),
    _r("SQLI-002", "SQL Injection", "Quote followed by boolean tautology (' OR '1'='1)",
       r"['\"]\s*\)?\s*\b(or|and)\b\s*['\"(]?\s*\w+\s*['\")]?\s*(=|like|<|>)\s*['\"(]?\s*\w+"),
    _r("SQLI-003", "SQL Injection", "Numeric tautology (OR 1=1)",
       r"\b(or|and)\b\s+(\d+)\s*=\s*\2\b"),
    _r("SQLI-004", "SQL Injection", "Stacked query (; DROP/DELETE/INSERT ...)",
       r";\s*\b(drop|delete|insert|update|alter|create|truncate|exec|shutdown)\b"),
    _r("SQLI-005", "SQL Injection", "Quote followed by SQL comment",
       r"['\"]\s*\)?\s*(--|#|/\*)"),
    _r("SQLI-006", "SQL Injection", "Time-based blind injection",
       r"\b(sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b"),
    _r("SQLI-007", "SQL Injection", "Schema enumeration",
       r"\binformation_schema\b|\bsysobjects\b|\bsqlite_master\b"),
    _r("SQLI-008", "SQL Injection", "Dangerous stored procedure",
       r"\bxp_cmdshell\b|\bload_file\s*\(|\binto\s+(out|dump)file\b"),
]

# ---------------------------------------------------------------------------
# Cross-Site Scripting
# ---------------------------------------------------------------------------
XSS_RULES = [
    _r("XSS-001", "XSS", "<script> tag",
       r"<\s*/?\s*script\b"),
    _r("XSS-002", "XSS", "Inline event handler inside a tag (onerror=, onload= ...)",
       r"<[^>]*\bon[a-z]+\s*="),
    _r("XSS-003", "XSS", "javascript: / vbscript: URI",
       r"\b(javascript|vbscript)\s*:"),
    _r("XSS-004", "XSS", "Dangerous embedding tag",
       r"<\s*(iframe|object|embed|applet|meta|base|frameset)\b"),
    _r("XSS-005", "XSS", "DOM access to cookies / document.write",
       r"\bdocument\s*\.\s*(cookie|domain|write)\b"),
    _r("XSS-006", "XSS", "Script execution function",
       r"\b(alert|prompt|confirm|eval)\s*\("),
    _r("XSS-007", "XSS", "data: URI carrying HTML/JS",
       r"data\s*:\s*text/(html|javascript)"),
]

# ---------------------------------------------------------------------------
# Path Traversal
# ---------------------------------------------------------------------------
TRAVERSAL_RULES = [
    _r("PT-001", "Path Traversal", "Directory traversal sequence (../ or ..\\)",
       r"\.\.[/\\]|[/\\]\.\.(?:[/\\]|$)"),
    _r("PT-002", "Path Traversal", "Sensitive Unix file",
       r"/etc/(passwd|shadow|hosts|group)\b|/proc/self/"),
    _r("PT-003", "Path Traversal", "Sensitive Windows file",
       r"\b(win\.ini|boot\.ini)\b|\\windows\\system32\b"),
    _r("PT-004", "Path Traversal", "Null byte injection",
       r"\x00"),
]

ALL_RULES = SQLI_RULES + XSS_RULES + TRAVERSAL_RULES
