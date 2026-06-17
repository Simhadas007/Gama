MITRE_MAPPINGS = [
    {
        "keywords": ["powershell", "powershell.exe"],
        "technique_id": "T1059.001",
        "technique": "PowerShell",
        "tactic": "Execution",
        "severity": "HIGH"
    },
    {
        "keywords": ["cmd.exe", "cmd /c"],
        "technique_id": "T1059.003",
        "technique": "Windows Command Shell",
        "tactic": "Execution",
        "severity": "HIGH"
    },
    {
        "keywords": ["bash", "/bin/sh", "sh -c"],
        "technique_id": "T1059.004",
        "technique": "Unix Shell",
        "tactic": "Execution",
        "severity": "MEDIUM"
    },
    {
        "keywords": ["python -c", "exec(", "eval(", "compile("],
        "technique_id": "T1059.006",
        "technique": "Python",
        "tactic": "Execution",
        "severity": "HIGH"
    },
    {
        "keywords": ["subprocess", "os.system", "popen", "spawn"],
        "technique_id": "T1059",
        "technique": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "severity": "HIGH"
    },
    {
        "keywords": ["curl", "wget", "requests.get", "requests.post", "urllib", "socket"],
        "technique_id": "T1071",
        "technique": "Application Layer Protocol",
        "tactic": "Command and Control",
        "severity": "MEDIUM"
    },
    {
        "keywords": ["http://", "https://", ".onion"],
        "technique_id": "T1105",
        "technique": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "severity": "MEDIUM"
    },
    {
        "keywords": ["base64", "b64decode", "frombase64string"],
        "technique_id": "T1027",
        "technique": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "severity": "HIGH"
    },
    {
        "keywords": ["chmod", "chown", "icacls", "takeown"],
        "technique_id": "T1222",
        "technique": "File and Directory Permissions Modification",
        "tactic": "Defense Evasion",
        "severity": "MEDIUM"
    },
    {
        "keywords": ["sudo", "runas", "setuid", "setgid"],
        "technique_id": "T1548",
        "technique": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "severity": "HIGH"
    },
    {
        "keywords": ["crontab", "/etc/cron", "schtasks", "task scheduler"],
        "technique_id": "T1053",
        "technique": "Scheduled Task/Job",
        "tactic": "Persistence",
        "severity": "HIGH"
    },
    {
        "keywords": ["startup", "runonce", "currentversion\\run", "registry run"],
        "technique_id": "T1060",
        "technique": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
        "severity": "HIGH"
    },
    {
        "keywords": ["whoami", "id", "uname", "hostname"],
        "technique_id": "T1082",
        "technique": "System Information Discovery",
        "tactic": "Discovery",
        "severity": "LOW"
    },
    {
        "keywords": ["ipconfig", "ifconfig", "netstat", "/proc/net", "hostname -i"],
        "technique_id": "T1016",
        "technique": "System Network Configuration Discovery",
        "tactic": "Discovery",
        "severity": "LOW"
    },
    {
        "keywords": ["find /", "dir /s", "ls -la", "os.listdir", "walk("],
        "technique_id": "T1083",
        "technique": "File and Directory Discovery",
        "tactic": "Discovery",
        "severity": "LOW"
    },
    {
        "keywords": ["passwd", "shadow", "credentials", "token", "api_key", "secret_key"],
        "technique_id": "T1552",
        "technique": "Unsecured Credentials",
        "tactic": "Credential Access",
        "severity": "HIGH"
    },
    {
        "keywords": ["zipfile", "tarfile", "archive", "compress"],
        "technique_id": "T1560",
        "technique": "Archive Collected Data",
        "tactic": "Collection",
        "severity": "MEDIUM"
    },
    {
        "keywords": ["upload", "exfil", "send_file", "requests.post"],
        "technique_id": "T1041",
        "technique": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "severity": "HIGH"
    },
    {
        "keywords": ["delete", "remove", "unlink", "shred", "rm -rf"],
        "technique_id": "T1070",
        "technique": "Indicator Removal",
        "tactic": "Defense Evasion",
        "severity": "HIGH"
    },
    {
        "keywords": ["pip install", "npm install", "curl | sh", "wget | sh"],
        "technique_id": "T1204",
        "technique": "User Execution",
        "tactic": "Execution",
        "severity": "MEDIUM"
    }
]


def map_to_mitre(text: str):
    detected = {}
    lower_text = text.lower()

    for item in MITRE_MAPPINGS:
        for keyword in item["keywords"]:
            if keyword.lower() in lower_text:
                key = item["technique_id"]

                if key not in detected:
                    detected[key] = {
                        "technique_id": item["technique_id"],
                        "technique": item["technique"],
                        "tactic": item["tactic"],
                        "severity": item["severity"],
                        "matched_keywords": []
                    }

                detected[key]["matched_keywords"].append(keyword)

    return list(detected.values())