import json, re, sys, os
from datetime import date
from jinja2 import Template

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
findings = json.load(open("reports/custom_findings.json"))

risk_map = {"3": "High", "2": "Medium", "1": "Low", "0": "Info"}
def clean(t): return re.sub(r"<[^>]+>", "", t or "").strip()

if os.path.exists("reports/zap_report.json"):
    zap = json.load(open("reports/zap_report.json"))
    for site in zap.get("site", []):
        for a in site.get("alerts", []):
            findings.append({
                "title": a.get("name", "ZAP alert"),
                "severity": risk_map.get(str(a.get("riskcode")), "Info"),
                "owasp": "CWE-" + str(a.get("cweid", "n/a")),
                "mitre": "T1595.002",
                "evidence": clean(a.get("desc"))[:300],
                "fix": clean(a.get("solution"))[:300],
                "source": "OWASP ZAP",
            })
else:
    print("No ZAP report found, using custom findings only")

order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
findings.sort(key=lambda x: order.get(x["severity"], 9))
counts = {s: sum(1 for f in findings if f["severity"] == s) for s in order}

html = Template("""
<html><head><meta charset="utf-8"><title>Security Assessment Report</title>
<style>
body{font-family:Arial;max-width:1000px;margin:30px auto;padding:0 20px;color:#222}
h1{border-bottom:3px solid #8b1a1a;padding-bottom:8px}
table{border-collapse:collapse;width:100%;margin:15px 0;font-size:13px}
td,th{border:1px solid #ccc;padding:8px;text-align:left;vertical-align:top}
th{background:#8b1a1a;color:white}
.High{color:#c00;font-weight:bold}.Medium{color:#e07b00;font-weight:bold}
.Low{color:#2a7a2a;font-weight:bold}.Info{color:#555}
</style></head><body>
<h1>Web Application Security Assessment</h1>
<p><b>Target:</b> {{ target }} (OWASP Juice Shop, intentionally vulnerable)<br>
<b>Date:</b> {{ today }}<br><b>Analyst:</b> Jay Patel <br><b>Tools:</b> custom Python scanner, OWASP ZAP baseline scan</p>
<h2>Executive Summary</h2>
<p>The automated assessment found <b>{{ total }}</b> issues:
{{ c['High'] }} High, {{ c['Medium'] }} Medium, {{ c['Low'] }} Low, {{ c['Info'] }} Informational.
Fix the highest severity items first. This report covers automated checks only; manual exploitation is documented separately.</p>
<h2>Findings</h2>
<table><tr><th>#</th><th>Severity</th><th>Issue</th><th>OWASP / CWE</th><th>MITRE</th><th>Evidence</th><th>Remediation</th><th>Source</th></tr>
{% for f in findings %}
<tr><td>{{ loop.index }}</td><td class="{{ f.severity }}">{{ f.severity }}</td>
<td>{{ f.title }}</td><td>{{ f.owasp }}</td><td>{{ f.mitre }}</td><td>{{ f.evidence }}</td>
<td>{{ f.fix }}</td><td>{{ f.source }}</td></tr>
{% endfor %}</table>
</body></html>
""").render(findings=findings, c=counts, total=len(findings), target=TARGET, today=date.today())

open("reports/security_report.html", "w", encoding="utf-8").write(html)
print(f"Report saved: reports/security_report.html ({len(findings)} findings)")
