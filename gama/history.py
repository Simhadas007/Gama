from pathlib import Path
import json

LOG_DIR = Path("logs")


def get_reports():
    LOG_DIR.mkdir(exist_ok=True)

    reports = sorted(
        LOG_DIR.glob("*_scan_report.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )

    return reports


def get_latest_report():
    reports = get_reports()
    return reports[0] if reports else None


def read_report(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def clean_reports():
    count = 0

    for file in LOG_DIR.glob("*_scan_report.*"):
        file.unlink()
        count += 1

    return count