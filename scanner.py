import requests, json, sys, uuid, os

TARGET = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:3000"
os.makedirs("reports", exist_ok=True)
findings = []

def add(title, severity, owasp, mitre, evidence, fix):
    findings.append({"title": title, "severity": severity, "owasp": owasp, "mitre": mitre,
                     "evidence": evidence, "fix": fix, "source": "Custom scanner"})

print(f"Scanning {TARGET} ...")
resp = requests.get(TARGET, timeout=10)

# CHECK 1: Security headers
headers_to_check = {
    "Content-Security-Policy": ("Medium", "Add a Content-Security-Policy header to limit which scripts can run."),
    "Strict-Transport-Security": ("Medium", "Add HSTS so browsers always use HTTPS."),
    "X-Frame-Options": ("Low", "Add X-Frame-Options: DENY to prevent clickjacking."),
    "X-Content-Type-Options": ("Low", "Add X-Content-Type-Options: nosniff."),
}
for h, (sev, fix) in headers_to_check.items():
    if h not in resp.headers:
        add(f"Missing security header: {h}", sev, "A05:2021 Security Misconfiguration", "T1595.002",
            f"Header '{h}' not present in response from {TARGET}", fix)

# CHECK 2: Cookie flags
for c in resp.cookies:
    if not c.secure:
        add(f"Cookie '{c.name}' missing Secure flag", "Low", "A02:2021 Cryptographic Failures", "T1595.002",
            f"Cookie {c.name} can be sent over plain HTTP", "Set the Secure flag on cookies.")
    if not c.has_nonstandard_attr("HttpOnly"):
        add(f"Cookie '{c.name}' missing HttpOnly flag", "Medium", "A05:2021 Security Misconfiguration", "T1595.002",
            f"Cookie {c.name} can be read by JavaScript", "Set the HttpOnly flag on cookies.")

# CHECK 3: Exposed paths (compared with a random fake page to avoid false positives)
baseline = requests.get(TARGET + "/" + uuid.uuid4().hex, timeout=10).text
paths = ["/admin", "/ftp", "/.git/HEAD", "/robots.txt", "/metrics", "/backup", "/.env"]
for p in paths:
    r = requests.get(TARGET + p, timeout=10)
    if r.status_code == 200 and r.text != baseline:
        add(f"Exposed path: {p}", "Medium", "A01:2021 Broken Access Control", "T1595.003",
            f"{TARGET}{p} returned HTTP 200 with unique content", "Restrict or remove this path.")

# CHECK 4: Server information leak
if "Server" in resp.headers or "X-Powered-By" in resp.headers:
    add("Server technology disclosed", "Low", "A05:2021 Security Misconfiguration", "T1592.002",
        f"Server: {resp.headers.get('Server')}, X-Powered-By: {resp.headers.get('X-Powered-By')}",
        "Hide version and technology banners.")

with open("reports/custom_findings.json", "w") as f:
    json.dump(findings, f, indent=2)
print(f"Done. {len(findings)} findings saved to reports/custom_findings.json")
for f in findings:
    print(f"  [{f['severity']}] {f['title']}")
