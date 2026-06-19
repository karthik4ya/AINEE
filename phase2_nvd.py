import requests
import json
import time

def query_nvd(product, version):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": f"apache http server {version}",
        "resultsPerPage": 20
    }
    headers = {"User-Agent": "AINEE/1.0"}

    response = requests.get(url, params=params, headers=headers)
    print(f"Status code: {response.status_code}")
    if response.status_code != 200:
        print(f"NVD API error: {response.status_code}")
        return []

    data = response.json()
    vulns = []

    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        cve_id = cve["id"]
        description = cve["descriptions"][0]["value"]

        metrics = cve.get("metrics", {})

        base_score = None
        exploitability_score = None
        severity = None

        if "cvssMetricV31" in metrics:
            m = metrics["cvssMetricV31"][0]
            base_score = m["cvssData"]["baseScore"]
            exploitability_score = m["exploitabilityScore"]
            severity = m["cvssData"]["baseSeverity"]
        elif "cvssMetricV30" in metrics:
            m = metrics["cvssMetricV30"][0]
            base_score = m["cvssData"]["baseScore"]
            exploitability_score = m["exploitabilityScore"]
            severity = m["cvssData"]["baseSeverity"]
        elif "cvssMetricV2" in metrics:
            m = metrics["cvssMetricV2"][0]
            base_score = m["cvssData"]["baseScore"]
            exploitability_score = m["exploitabilityScore"]
            severity = m["baseSeverity"]

        if base_score is None:
            continue

        score_vul = round(base_score * (exploitability_score / 10), 3)

        vulns.append({
            "cve_id": cve_id,
            "description": description[:100],
            "base_score": base_score,
            "exploitability_score": exploitability_score,
            "severity": severity,
            "score_vul": score_vul
        })

    return sorted(vulns, key=lambda x: x["score_vul"], reverse=True)


if __name__ == '__main__':
    targets = [
        {"product": "apache", "version": "2.4.25"}
    ]

    all_vulns = {}
    for t in targets:
        key = f"apache_http_{t['version']}"
        print(f"\nQuerying NVD for Apache {t['version']}...")
        vulns = query_nvd(t["product"], t["version"])
        all_vulns[key] = vulns
        print(f"Found {len(vulns)} CVEs")
        time.sleep(1)

    print("\n" + json.dumps(all_vulns, indent=2))

    with open("phase2_vulns.json", "w") as f:
        json.dump(all_vulns, f, indent=2)

    print("\nSaved to phase2_vulns.json")
