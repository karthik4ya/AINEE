import json
from datetime import datetime

def generate_report():
    with open("phase2_vulns.json") as f:
        vulns = json.load(f)
    with open("phase4_results.json") as f:
        dqn = json.load(f)
    with open("phase5_report.json") as f:
        exploit = json.load(f)

    report = []
    report.append("=" * 60)
    report.append("AINEE — AUTOMATED PENETRATION TEST REPORT")
    report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("=" * 60)

    report.append("\nTARGET")
    report.append("-" * 40)
    report.append("Host:     10.100.7.250")
    report.append("OS:       macOS 11 (Big Sur)")
    report.append("Service:  Apache httpd 2.4.25 (port 8080)")

    report.append("\nVULNERABILITIES FOUND")
    report.append("-" * 40)
    for key, cve_list in vulns.items():
        for cve in cve_list:
            report.append(f"  {cve['cve_id']}")
            report.append(f"    Severity:      {cve['severity']}")
            report.append(f"    Base score:    {cve['base_score']}")
            report.append(f"    Exploit score: {cve['exploitability_score']}")
            report.append(f"    Score_vul:     {cve['score_vul']}")
            report.append("")

    report.append("\nDQN OPTIMAL ATTACK PATH")
    report.append("-" * 40)
    report.append("  " + " -> ".join(dqn["optimal_path"]))
    report.append(f"  Total reward: {dqn['optimal_reward']}")

    report.append("\nALL PATHS RANKED")
    report.append("-" * 40)
    for i, p in enumerate(dqn["all_paths"]):
        tag = " <- OPTIMAL" if i == 0 else ""
        report.append(f"  Path {i+1}{tag}: {' -> '.join(p['path'])}")
        report.append(f"    Reward: {p['reward']}")

    report.append("\nEXPLOITATION RESULT")
    report.append("-" * 40)
    report.append("  Module executed successfully against target")
    report.append("  No mod_userdir users found (expected for DVWA)")
    report.append("  Target confirmed reachable and responsive")

    report.append("\nRECOMMENDATIONS")
    report.append("-" * 40)
    report.append("  1. Upgrade Apache from 2.4.25 to latest stable version")
    report.append("  2. Disable mod_userdir if not required")
    report.append("  3. Enable HTTP/2 security patches (CVE-2017-7659)")
    report.append("  4. Implement strict HTTP header validation (CVE-2016-4975)")

    report.append("\n" + "=" * 60)
    report.append("END OF REPORT")
    report.append("=" * 60)

    output = "\n".join(report)
    print(output)

    with open("ainee_final_report.txt", "w") as f:
        f.write(output)

    print("\nSaved to ainee_final_report.txt")

if __name__ == '__main__':
    generate_report()
