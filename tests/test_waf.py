import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app          # noqa: E402
from waf import normalise           # noqa: E402


@pytest.fixture
def log_file(tmp_path):
    return str(tmp_path / "waf.log")


@pytest.fixture
def client(log_file):
    return create_app(log_file=log_file, mode="block").test_client()


def read_log(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


# --------------------------------------------------------------------------- #
# Malicious requests must be blocked
# --------------------------------------------------------------------------- #
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "admin' --",
    "1 OR 1=1",
    "1 UNION SELECT username, password FROM users",
    "1; DROP TABLE users",
    "1' AND SLEEP(5)--",
    "x' UNION ALL SELECT table_name FROM information_schema.tables--",
    "%27%20OR%20%271%27%3D%271",            # URL-encoded
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert('xss')>",
    "javascript:alert(document.cookie)",
    "<iframe src='http://evil.example'></iframe>",
    "&lt;script&gt;alert(1)&lt;/script&gt;",  # HTML-entity encoded
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",     # URL-encoded
]

TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",          # URL-encoded
    "%252e%252e%252fetc%252fpasswd",           # double-encoded
    "/etc/shadow",
    "report.pdf%00.jpg",                       # null byte
]


@pytest.mark.parametrize("payload", SQLI_PAYLOADS)
def test_sqli_in_query_blocked(client, payload):
    resp = client.get(f"/search?q={payload}")
    assert resp.status_code == 403
    assert resp.get_json()["category"] == "SQL Injection"


@pytest.mark.parametrize("payload", XSS_PAYLOADS)
def test_xss_in_query_blocked(client, payload):
    resp = client.get(f"/search?q={payload}")
    assert resp.status_code == 403
    assert resp.get_json()["category"] == "XSS"


@pytest.mark.parametrize("payload", TRAVERSAL_PAYLOADS)
def test_path_traversal_blocked(client, payload):
    resp = client.get(f"/file?name={payload}")
    assert resp.status_code == 403
    assert resp.get_json()["category"] == "Path Traversal"


def test_sqli_in_form_body_blocked(client):
    resp = client.post("/login", data={"username": "admin' --", "password": "x"})
    assert resp.status_code == 403


def test_xss_in_json_body_blocked(client):
    resp = client.post("/comment", json={"text": "<script>alert('hi')</script>"})
    assert resp.status_code == 403


def test_attack_in_user_agent_blocked(client):
    resp = client.get("/", headers={"User-Agent": "<script>alert(1)</script>"})
    assert resp.status_code == 403


def test_attack_in_cookie_blocked(client):
    client.set_cookie("session", "' OR 1=1 --")
    resp = client.get("/")
    assert resp.status_code == 403


# --------------------------------------------------------------------------- #
# Legitimate requests must pass (false-positive checks)
# --------------------------------------------------------------------------- #
BENIGN_QUERIES = [
    "laptop",
    "rock and roll",
    "O'Brien",
    "select a colour",
    "union jack flag",
    "one=1",
    "5 > 3",
    "reports/2026/summary.pdf",
    "it's raining",
]


@pytest.mark.parametrize("q", BENIGN_QUERIES)
def test_benign_queries_allowed(client, q):
    resp = client.get("/search", query_string={"q": q})
    assert resp.status_code == 200, f"False positive on: {q}"


def test_benign_login_allowed(client):
    resp = client.post("/login", data={"username": "alice", "password": "S3cure!pass"})
    assert resp.status_code == 200
    assert resp.get_json()["user"] == "alice"  # body still readable by the app


def test_benign_json_allowed(client):
    resp = client.post("/comment", json={"text": "Great article, thanks & well done!"})
    assert resp.status_code == 200


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #
def test_blocked_request_is_logged(client, log_file):
    client.get("/search?q=<script>alert(1)</script>")
    entries = read_log(log_file)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["action"] == "blocked"
    assert entry["category"] == "XSS"
    assert entry["location"] == "query"
    for key in ("timestamp", "request_id", "client_ip", "method", "rule_id", "matched"):
        assert key in entry


def test_benign_request_not_logged(client, log_file):
    client.get("/search?q=hello")
    assert not os.path.exists(log_file) or read_log(log_file) == []


def test_monitor_mode_logs_but_allows(log_file):
    client = create_app(log_file=log_file, mode="monitor").test_client()
    resp = client.get("/file?name=../../etc/passwd")
    assert resp.status_code == 200
    assert read_log(log_file)[0]["action"] == "logged"


def test_stats_endpoint(client):
    client.get("/search?q=ok")
    client.get("/search?q=' OR 1=1--")
    stats = client.get("/waf/stats").get_json()
    assert stats["blocked"] == 1
    assert stats["SQL Injection"] == 1


# --------------------------------------------------------------------------- #
# Unit test for the decoder
# --------------------------------------------------------------------------- #
def test_normalise_double_encoding():
    assert normalise("%252e%252e%252f") == "../"
    assert normalise("&lt;SCRIPT&gt;") == "<script>"
