"""
Fetches a recent, high-severity CVE from the NVD public API and writes a short,
human-readable line into README.md between the CVE markers.

No API key required for light usage. If NVD rate-limits or errors, the script
exits cleanly without touching the README (so a bad run never breaks the page).
"""

import re
import sys
import urllib.request
import json
from datetime import datetime, timedelta, timezone

README_PATH = "README.md"
START_MARKER = "<!--CVE:START-->"
END_MARKER = "<!--CVE:END-->"

NVD_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
    "?resultsPerPage=5&cvssV3Severity=CRITICAL&pubStartDate={start}&pubEndDate={end}"
)


def fetch_recent_critical_cve():
    now = datetime.now(timezone.utc)
    start = (now - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000")
    end = now.strftime("%Y-%m-%dT%H:%M:%S.000")
    url = NVD_URL.format(start=start, end=end)

    req = urllib.request.Request(url, headers={"User-Agent": "github-readme-bot"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode())

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None

    cve = vulns[0]["cve"]
    cve_id = cve["id"]
    descriptions = cve.get("descriptions", [])
    desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
    desc = desc[:180].rsplit(" ", 1)[0] + "…" if len(desc) > 180 else desc

    return f"🛰️ **{cve_id}** — {desc}  \n[Details](https://nvd.nist.gov/vuln/detail/{cve_id})"


def update_readme(new_line: str):
    with open(README_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    pattern = re.compile(
        re.escape(START_MARKER) + r".*?" + re.escape(END_MARKER), re.DOTALL
    )
    replacement = f"{START_MARKER}\n{new_line}\n{END_MARKER}"

    if not pattern.search(content):
        print("Markers not found in README — skipping.")
        return

    content = pattern.sub(replacement, content)
    with open(README_PATH, "w", encoding="utf-8") as f:
        f.write(content)


def main():
    try:
        line = fetch_recent_critical_cve()
    except Exception as e:
        print(f"Fetch failed, leaving README untouched: {e}")
        sys.exit(0)

    if not line:
        print("No recent critical CVE found, leaving README untouched.")
        sys.exit(0)

    update_readme(line)
    print("README updated.")


if __name__ == "__main__":
    main()
