from pathlib import Path
import zipfile


SUSPICIOUS_KEYWORDS = [
    "subprocess",
    "os.system",
    "socket",
    "requests.post",
    "requests.get",
    "urllib",
    "base64",
    "eval(",
    "exec(",
    "chmod",
    "sudo",
    "powershell",
    "cmd.exe",
    "curl",
    "wget"
]


def scan_package_files(stream_path: Path):
    findings = []

    for file in stream_path.iterdir():
        if file.suffix == ".whl":
            try:
                with zipfile.ZipFile(file, "r") as zip_ref:
                    for name in zip_ref.namelist():
                        if name.endswith(".py"):
                            content = zip_ref.read(name).decode(errors="ignore")
                            for keyword in SUSPICIOUS_KEYWORDS:
                                if keyword in content:
                                    findings.append(
                                        f"{keyword} found in {file.name}:{name}"
                                    )
            except Exception as e:
                findings.append(f"Could not scan {file.name}: {e}")

    return findings