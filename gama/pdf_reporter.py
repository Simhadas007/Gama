from pathlib import Path
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

REPORT_DIR = Path("logs")
REPORT_DIR.mkdir(exist_ok=True)


def save_pdf_report(package, risk, hash_results, ioc_results, mitre_findings):
    safe_name = package.replace("/", "_").replace("\\", "_").replace(":", "_")
    pdf_path = REPORT_DIR / f"{safe_name}_scan_report.pdf"

    c = canvas.Canvas(str(pdf_path), pagesize=A4)
    width, height = A4

    y = height - 50

    def line(text, size=10):
        nonlocal y
        if y < 50:
            c.showPage()
            y = height - 50
        c.setFont("Helvetica", size)
        c.drawString(40, y, str(text)[:110])
        y -= 16

    line("Gama Zero-Trust Security Scan Report", 16)
    line(f"Package/Source: {package}", 11)
    line("")

    line("Risk Report", 14)
    line(f"Risk Score: {risk.get('score')}/100")
    line(f"Verdict: {risk.get('verdict')}")
    line("")

    line("File Hashes", 14)
    for item in hash_results:
        line(f"File: {item.get('file')}")
        line(f"Size: {item.get('size')} bytes")
        line(f"SHA256: {item.get('sha256')}")
        line(f"MD5: {item.get('md5')}")
        line("")

    line("IOC Results", 14)
    for category, values in ioc_results.items():
        if values:
            line(category)
            for value in values[:10]:
                line(f"- {value}")

    line("")
    line("MITRE ATT&CK Mapping", 14)
    if mitre_findings:
        for finding in mitre_findings:
            line(
                f"{finding.get('technique_id')} | "
                f"{finding.get('technique')} | "
                f"{finding.get('tactic')} | "
                f"{finding.get('severity')}"
            )
    else:
        line("No MITRE techniques mapped.")

    c.save()
    return pdf_path