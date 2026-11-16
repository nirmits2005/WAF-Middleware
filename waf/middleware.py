"""
WSGI Web Application Firewall middleware.

Wraps any WSGI application (Flask, Django, etc.) and inspects every incoming
request *before* it reaches the application:

    path  ->  query string  ->  selected headers  ->  cookies  ->  body

If a rule matches, the request is blocked with HTTP 403 (in "block" mode) or
allowed through (in "monitor" mode). In both modes the event is written to a
JSON-lines log file for later analysis.
"""

import html
import io
import json
import logging
import uuid
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import unquote_plus

from .rules import ALL_RULES

# Headers commonly abused to carry payloads
INSPECTED_HEADERS = ("HTTP_USER_AGENT", "HTTP_REFERER", "HTTP_X_FORWARDED_FOR")
MAX_BODY_BYTES = 1024 * 1024  # inspect at most 1 MB of body


def normalise(value: str, max_rounds: int = 3) -> str:
    """Repeatedly URL-decode and HTML-unescape so encoded payloads are exposed.

    e.g. %252e%252e%252f -> %2e%2e%2f -> ../
    """
    previous = None
    rounds = 0
    while value != previous and rounds < max_rounds:
        previous = value
        value = html.unescape(unquote_plus(value))
        rounds += 1
    return value.lower()


class WAFMiddleware:
    def __init__(self, app, log_file="logs/waf.log", mode="block", rules=None):
        if mode not in ("block", "monitor"):
            raise ValueError("mode must be 'block' or 'monitor'")
        self.app = app
        self.mode = mode
        self.rules = rules or ALL_RULES
        self.stats = Counter()

        self.logger = logging.getLogger(f"waf.{id(self)}")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        handler = logging.FileHandler(log_file, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
        self.logger.addHandler(handler)

    # ------------------------------------------------------------------ #
    # Inspection
    # ------------------------------------------------------------------ #
    def _collect_inputs(self, environ):
        """Return a list of (location, raw_value) pairs to inspect."""
        raw_path = (environ.get("RAW_URI") or environ.get("REQUEST_URI")
                    or environ.get("PATH_INFO", "")).split("?", 1)[0]
        inputs = [
            ("path", raw_path),
            ("query", environ.get("QUERY_STRING", "")),
        ]
        for header in INSPECTED_HEADERS:
            if environ.get(header):
                inputs.append((header[5:].lower().replace("_", "-"), environ[header]))
        if environ.get("HTTP_COOKIE"):
            inputs.append(("cookie", environ["HTTP_COOKIE"]))

        body = self._read_body(environ)
        if body:
            inputs.append(("body", body.decode("utf-8", errors="replace")))
        return inputs

    @staticmethod
    def _read_body(environ):
        """Read the body, then put it back so the application can still read it."""
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return b""
        body = environ["wsgi.input"].read(length)
        environ["wsgi.input"] = io.BytesIO(body)
        return body[:MAX_BODY_BYTES]

    def inspect(self, environ):
        """Return the first matching (rule, location, snippet) or None."""
        for location, raw in self._collect_inputs(environ):
            if not raw:
                continue
            text = normalise(raw)
            for rule in self.rules:
                match = rule.pattern.search(text)
                if match:
                    start = max(match.start() - 20, 0)
                    snippet = text[start:match.end() + 20]
                    return rule, location, snippet
        return None

    # ------------------------------------------------------------------ #
    # Logging
    # ------------------------------------------------------------------ #
    def _log(self, environ, rule, location, snippet, action, request_id):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "request_id": request_id,
            "client_ip": environ.get("HTTP_X_FORWARDED_FOR", environ.get("REMOTE_ADDR", "-")),
            "method": environ.get("REQUEST_METHOD"),
            "path": environ.get("PATH_INFO"),
            "category": rule.category,
            "rule_id": rule.id,
            "rule": rule.description,
            "location": location,
            "matched": snippet[:200],
            "action": action,
        }
        self.logger.info(json.dumps(entry))
        return entry

    # ------------------------------------------------------------------ #
    # WSGI entry point
    # ------------------------------------------------------------------ #
    def __call__(self, environ, start_response):
        self.stats["total"] += 1
        result = self.inspect(environ)

        if result is None:
            self.stats["allowed"] += 1
            return self.app(environ, start_response)

        rule, location, snippet = result
        request_id = str(uuid.uuid4())
        self.stats[rule.category] += 1

        if self.mode == "monitor":
            self.stats["flagged"] += 1
            self._log(environ, rule, location, snippet, "logged", request_id)
            return self.app(environ, start_response)

        self.stats["blocked"] += 1
        self._log(environ, rule, location, snippet, "blocked", request_id)
        body = json.dumps({
            "error": "Request blocked by Web Application Firewall",
            "category": rule.category,
            "rule_id": rule.id,
            "request_id": request_id,
        }).encode()
        start_response("403 Forbidden", [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(body))),
        ])
        return [body]
