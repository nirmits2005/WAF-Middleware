# Experiment 7 – Intrusion Detection System
## Web Application Firewall (WAF) Middleware

### Aim
To implement a middleware that detects and blocks SQL injection, Cross-Site Scripting (XSS) and path traversal patterns in HTTP requests, logs every detected attack, and verify it with automated tests.

### Theory
A **Web Application Firewall** sits between the client and the web application and inspects each HTTP request. This project implements a *signature-based* (rule-based) IDS/IPS:

| Attack | What it does | Example payload | Rules |
|---|---|---|---|
| SQL Injection | Alters the SQL query run by the server | `' OR '1'='1`, `UNION SELECT` | SQLI-001 to 008 |
| XSS | Injects JavaScript that runs in other users' browsers | `<script>alert(1)</script>` | XSS-001 to 007 |
| Path Traversal | Reads files outside the web root | `../../etc/passwd` | PT-001 to 004 |

**Evasion handling:** attackers often encode payloads (`%27`, `%252e`, `&lt;`). Every input is repeatedly URL-decoded and HTML-unescaped (up to 3 rounds) and lower-cased *before* matching, so encoded and double-encoded attacks are still caught.

**Modes:** `block` (IPS – returns HTTP 403) and `monitor` (IDS – logs only, request continues).

### Architecture
```
Client ──► WAFMiddleware ──(clean)──► Flask app ──► response
               │
               ├─(attack, block mode)──► 403 Forbidden (JSON)
               └─ every detection ─────► logs/waf.log (JSON lines)
```
Inspected locations: URL path, query string, User-Agent, Referer, X-Forwarded-For, cookies, and request body (form or JSON). The body is put back after reading so the application still receives it.

### Project structure
```
waf-project/
├── waf/
│   ├── rules.py         # regex signatures (19 rules)
│   └── middleware.py    # WSGI middleware: decode, inspect, block, log
├── app.py               # demo Flask app protected by the WAF
├── attack_demo.py       # attack simulation with results table
├── tests/test_waf.py    # 41 pytest test cases
├── logs/waf.log         # sample attack log
└── requirements.txt
```

### Procedure
```bash
pip install -r requirements.txt

# 1. Run the automated tests
python -m pytest -v

# 2. Run the attack simulation (prints results table, writes logs/waf.log)
python attack_demo.py

# 3. Run the live server and test manually
python app.py
curl "http://127.0.0.1:5000/search?q=laptop"                  # 200 OK
curl "http://127.0.0.1:5000/search?q=' OR '1'='1"             # 403 blocked
curl "http://127.0.0.1:5000/file?name=../../etc/passwd"       # 403 blocked
curl -X POST -d "username=admin' --" http://127.0.0.1:5000/login   # 403 blocked
curl http://127.0.0.1:5000/waf/stats                          # counters

# 4. Monitor (detect-only) mode
WAF_MODE=monitor python app.py        # Windows: set WAF_MODE=monitor
```

Using it in another Flask app:
```python
from waf import WAFMiddleware
app.wsgi_app = WAFMiddleware(app.wsgi_app, log_file="logs/waf.log", mode="block")
```

### Sample log entry
```json
{"timestamp": "2026-11-16T15:59:07+00:00", "request_id": "4ec983d9-...", "client_ip": "127.0.0.1",
 "method": "POST", "path": "/login", "category": "SQL Injection", "rule_id": "SQLI-005",
 "rule": "Quote followed by SQL comment", "location": "body", "matched": "username=admin' --",
 "action": "blocked"}
```

### Results
- `pytest`: **41/41 passed** (21 attack payloads incl. encoded variants, 12 benign/false-positive checks, logging, monitor mode, stats, decoder).
- `attack_demo.py`: **18/18** cases behaved as expected – 14 attacks blocked, 4 legitimate requests allowed.
- Benign inputs such as `O'Brien`, `rock and roll`, `union jack flag`, `select a colour` were **not** blocked.

### Limitations
- Signature-based detection cannot catch novel or heavily obfuscated attacks; a WAF is a defence-in-depth layer, **not** a substitute for parameterised queries, output encoding and safe file-path handling.
- Regex rules can still produce false positives on unusual legitimate input; tune rules per application and use `monitor` mode first.
- Production WAFs (e.g. ModSecurity with the OWASP Core Rule Set) use anomaly scoring and far larger rule sets.

### Conclusion
A WSGI-level WAF middleware was implemented that normalises request data, detects SQL injection, XSS and path traversal using signature rules, blocks malicious requests with HTTP 403, and logs each event in structured JSON for analysis. Automated tests confirmed correct detection, including encoded payloads, with no false positives on the benign test set.
# WAF-Middleware
