from pathlib import Path
from datetime import datetime
import json

REPORT_DIR = Path("logs")
REPORT_DIR.mkdir(exist_ok=True)


def save_report(
    package,
    downloaded_files,
    static_findings,
    evidence_summary,
    risk,
    hash_results=None,
    ioc_results=None,
    mitre_findings=None
):
    report = {
        "package": package,
        "scan_time": datetime.now().isoformat(),
        "downloaded_files": downloaded_files,
        "hashes": hash_results or [],
        "iocs": ioc_results or {},
        "static_findings": static_findings,
        "evidence_summary": evidence_summary,
        "mitre_attack": mitre_findings or [],
        "risk": risk
    }

    safe_name = package.replace("/", "_").replace("\\", "_").replace(":", "_")
    report_path = REPORT_DIR / f"{safe_name}_scan_report.json"

    with open(report_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    return report_path