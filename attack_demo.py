"""
Attack simulation: fires benign and malicious requests at the protected app
and prints a results table. No server needed - uses Flask's test client.

Run:  python attack_demo.py
"""

from app import create_app

TESTS = [
    # (description, method, url, kwargs, expected)
    ("Normal search",               "GET",  "/search", {"query_string": {"q": "safety helmet"}}, "ALLOW"),
    ("Normal login",                "POST", "/login",  {"data": {"username": "alice", "password": "pw"}}, "ALLOW"),
    ("Normal comment",              "POST", "/comment", {"json": {"text": "Nice work!"}}, "ALLOW"),
    ("Normal file",                 "GET",  "/file",   {"query_string": {"name": "report.pdf"}}, "ALLOW"),
    ("SQLi - tautology",            "GET",  "/search?q=' OR '1'='1", {}, "BLOCK"),
    ("SQLi - UNION SELECT",         "GET",  "/search?q=1 UNION SELECT user,pass FROM users", {}, "BLOCK"),
    ("SQLi - login bypass (form)",  "POST", "/login",  {"data": {"username": "admin' --"}}, "BLOCK"),
    ("SQLi - stacked DROP",         "GET",  "/search?q=1; DROP TABLE users", {}, "BLOCK"),
    ("SQLi - time-based blind",     "GET",  "/search?q=1' AND SLEEP(5)--", {}, "BLOCK"),
    ("XSS - script tag",            "GET",  "/search?q=<script>alert(1)</script>", {}, "BLOCK"),
    ("XSS - img onerror",           "GET",  "/search?q=<img src=x onerror=alert(1)>", {}, "BLOCK"),
    ("XSS - JSON body",             "POST", "/comment", {"json": {"text": "<svg onload=alert(1)>"}}, "BLOCK"),
    ("XSS - URL-encoded",           "GET",  "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", {}, "BLOCK"),
    ("XSS - in User-Agent",         "GET",  "/", {"headers": {"User-Agent": "<script>x</script>"}}, "BLOCK"),
    ("Traversal - ../etc/passwd",   "GET",  "/file?name=../../etc/passwd", {}, "BLOCK"),
    ("Traversal - Windows",         "GET",  "/file?name=..\\..\\windows\\win.ini", {}, "BLOCK"),
    ("Traversal - double-encoded",  "GET",  "/file?name=%252e%252e%252fetc%252fpasswd", {}, "BLOCK"),
    ("Traversal - null byte",       "GET",  "/file?name=shell.php%00.jpg", {}, "BLOCK"),
]


def main():
    app = create_app(log_file="logs/waf.log", mode="block")
    client = app.test_client()

    print(f"{'#':<3}{'Test case':<30}{'Status':<8}{'Expected':<10}{'Result':<8}Rule")
    print("-" * 80)
    passed = 0
    for i, (desc, method, url, kwargs, expected) in enumerate(TESTS, 1):
        resp = client.open(url, method=method, **kwargs)
        actual = "BLOCK" if resp.status_code == 403 else "ALLOW"
        ok = actual == expected
        passed += ok
        rule = resp.get_json().get("rule_id", "") if actual == "BLOCK" else ""
        print(f"{i:<3}{desc:<30}{resp.status_code:<8}{expected:<10}{'PASS' if ok else 'FAIL':<8}{rule}")

    print("-" * 80)
    print(f"Result: {passed}/{len(TESTS)} test cases behaved as expected")
    print(f"WAF stats: {dict(app.waf.stats)}")
    print("Attack log written to logs/waf.log")


if __name__ == "__main__":
    main()
