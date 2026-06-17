def capture_before_state(container):
    return {
        "processes": run(container, "ps aux || true"),
        "tmp_files": run(container, "find /tmp -type f || true"),
        "etc_files": run(container, "find /etc -maxdepth 2 -type f || true")
    }


def capture_after_state(container):
    return {
        "processes": run(container, "ps aux || true"),
        "tmp_files": run(container, "find /tmp -type f || true"),
        "etc_files": run(container, "find /etc -maxdepth 2 -type f || true"),
        "network": run(container, "cat /proc/net/tcp /proc/net/udp 2>/dev/null || true")
    }


def run(container, cmd):
    result = container.exec_run(f"sh -c \"{cmd}\"")
    return result.output.decode(errors="ignore")


def analyze_behavior(before, after):
    findings = []

    if before["tmp_files"] != after["tmp_files"]:
        findings.append("Filesystem changes detected in /tmp")

    if before["processes"] != after["processes"]:
        findings.append("Process activity changed during sandbox execution")

    if after.get("network", "").strip():
        findings.append("Network socket table accessible after execution")

    return findings