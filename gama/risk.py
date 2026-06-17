def calculate_risk(text: str):
    text = text.lower()

    score = 0
    findings = []

    weak_indicators = {
        "root": "Package executed as root inside container",
        "warning": "Warning found during execution",
        "socket": "Network-related code detected",
        "urllib": "URL handling code detected",
        "subprocess": "Subprocess-related code detected",
        "chmod": "Permission-related code detected",
    }

    medium_indicators = {
        "curl | sh": "Remote script execution pattern detected",
        "wget | sh": "Remote script execution pattern detected",
        "eval(": "Dynamic code execution detected",
        "exec(": "Dynamic code execution detected",
        "base64": "Possible obfuscation indicator detected",
        "powershell": "PowerShell execution detected",
        "cmd.exe": "Windows shell execution detected",
    }

    strong_indicators = {
        "rm -rf": "Destructive file deletion pattern detected",
        "sudo": "Privilege escalation keyword detected",
        "setuid": "Privilege escalation mechanism detected",
        "crontab": "Persistence via cron detected",
        "schtasks": "Persistence via scheduled task detected",
        "currentversion\\run": "Persistence via registry run key detected",
        "exfil": "Possible exfiltration keyword detected",
        "keylogger": "Keylogger keyword detected",
        "stealer": "Credential stealer keyword detected",
        "reverse shell": "Reverse shell keyword detected",
    }

    weak_hits = []
    medium_hits = []
    strong_hits = []

    for keyword, message in weak_indicators.items():
        if keyword in text:
            weak_hits.append(message)

    for keyword, message in medium_indicators.items():
        if keyword in text:
            medium_hits.append(message)

    for keyword, message in strong_indicators.items():
        if keyword in text:
            strong_hits.append(message)

    score += min(len(weak_hits) * 5, 20)
    score += min(len(medium_hits) * 15, 45)
    score += min(len(strong_hits) * 30, 90)

    findings.extend(weak_hits)
    findings.extend(medium_hits)
    findings.extend(strong_hits)

    if len(medium_hits) >= 2 and len(weak_hits) >= 2:
        score += 15
        findings.append("Multiple suspicious behavior categories combined")

    if len(strong_hits) >= 1 and len(medium_hits) >= 1:
        score += 20
        findings.append("Strong malware indicator combined with execution behavior")

    score = min(score, 100)

    if score >= 85:
        verdict = "HIGH RISK"
    elif score >= 45:
        verdict = "MEDIUM RISK"
    else:
        verdict = "LOW RISK"

    return {
        "score": score,
        "verdict": verdict,
        "findings": sorted(set(findings))
    }