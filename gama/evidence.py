def collect_evidence(container):
    commands = {
        "python_packages": "python -m pip list",
        "processes": "ps aux",
        "network": "cat /etc/resolv.conf && hostname -I",
        "tmp_files": "find /tmp -maxdepth 3 -type f",
        "sensitive_paths": "ls -la /root /etc 2>/dev/null"
    }

    evidence = {}

    for name, cmd in commands.items():
        result = container.exec_run(f"sh -c \"{cmd}\"")
        evidence[name] = result.output.decode(errors="ignore")

    return evidence


def summarize_evidence(evidence):
    summary = []

    if "root" in evidence.get("processes", "").lower():
        summary.append("Processes running as root inside sandbox")

    if "nameserver" in evidence.get("network", "").lower():
        summary.append("Network configuration accessible inside sandbox")

    if "/tmp/package" in evidence.get("tmp_files", ""):
        summary.append("Package files found inside sandbox temp path")

    return summary