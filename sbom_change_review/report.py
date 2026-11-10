"""Reports use escaped text only: no input is interpreted as markup."""
import html
import json


def _versions(records):
    return "; ".join((item["version"] or "unknown version") + " [" + (", ".join(item["licenses"]) or "unknown license") + "]" for item in records) or "—"


def _md(value):
    return html.escape(str(value), quote=True).replace("|", "&#124;").replace("\n", " ").replace("\r", " ").replace("`", "&#96;")


def render(report, fmt):
    if fmt == "json":
        return json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2) + "\n"
    status = "PASS" if report["passed"] else "POLICY FAILED"
    if fmt == "markdown":
        lines = ["# SBOM release review", "", "Policy: **" + status + "**", "", "| Change | Component identity | Baseline | Current |", "|---|---|---|---|"]
        lines += ["| " + " | ".join(map(_md, (c["kind"], c["identity"], _versions(c["before"]), _versions(c["after"])))) + " |" for c in report["changes"]]
        lines += ["", "## Policy findings", ""]
        lines += ["- " + _md(v["rule"] + ": " + v["identity"] + " — " + v["detail"]) for v in report["violations"]] or ["None."]
        lines += ["", "This is inventory and release-policy evidence, not vulnerability scanning or legal advice."]
        return "\n".join(lines) + "\n"
    esc = lambda value: html.escape(str(value), quote=True)
    rows = "".join("<tr>" + "".join("<td>" + esc(v) + "</td>" for v in (c["kind"], c["identity"], _versions(c["before"]), _versions(c["after"]))) + "</tr>" for c in report["changes"])
    findings = "".join("<li><strong>" + esc(v["rule"]) + "</strong> " + esc(v["identity"]) + ": " + esc(v["detail"]) + "</li>" for v in report["violations"]) or "<li>None</li>"
    summary = esc(json.dumps(report["summary"], sort_keys=True))
    return """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SBOM release review</title>
<style>body{font:16px system-ui;margin:2rem auto;padding:0 1rem;max-width:1200px;color:#17304a;background:#f6f8fb}h1{margin-bottom:.4rem}.badge{font-weight:bold}table{border-collapse:collapse;width:100%;background:white}th,td{padding:.8rem;border:1px solid #cdd7e2;text-align:left;overflow-wrap:anywhere}th{background:#e5eef7}input{padding:.6rem;margin:1rem 0;min-width:250px}pre{white-space:pre-wrap}.note{color:#48576a}</style>
<h1>SBOM release review</h1><p class="badge">""" + status + "</p><pre>" + summary + """</pre><p class="note">Exact inventory comparison. Multiple candidate versions remain ambiguous; no upgrade/downgrade or vulnerability claim is inferred.</p>
<label>Filter changes <input id="search" type="search" placeholder="Component, version or license"></label><table><thead><tr><th>Change</th><th>Component identity</th><th>Baseline versions / licenses</th><th>Current versions / licenses</th></tr></thead><tbody>""" + rows + """</tbody></table><h2>Policy findings</h2><ul>""" + findings + """</ul><p class="note">Review denied license expressions manually. This report does not evaluate license obligations.</p>
<script>document.getElementById('search').addEventListener('input',function(){const q=this.value.toLowerCase();document.querySelectorAll('tbody tr').forEach(row=>{row.hidden=!row.textContent.toLowerCase().includes(q);});});</script></html>"""
