# Gama – Zero-Trust Software Installation Security Platform

## Overview

Gama is a Zero-Trust command-line security platform designed to analyze software before installation. Traditional package managers download and install software directly on the host system, creating a potential risk from malicious packages, compromised repositories, supply-chain attacks, and hidden payloads.

Gama introduces a Zero-Trust workflow where software is intercepted, analyzed, and risk-assessed before installation is allowed.

The platform combines static analysis, dynamic sandbox analysis, IOC extraction, MITRE ATT&CK mapping, threat scoring, and forensic reporting to help users make informed installation decisions.

---

## Why Gama?

Modern software installations often trust package repositories by default.

Potential risks include:

* Malicious packages
* Supply-chain attacks
* Hidden backdoors
* Credential stealers
* Crypto miners
* Remote access malware
* Dependency confusion attacks
* Typosquatting packages

Gama follows the principle:

**"Never Trust. Always Verify."**

Every package is treated as potentially untrusted until analysis is completed.

---

## Key Features

### Zero-Trust Installation Workflow

Intercepts software acquisition before installation.

### Static Analysis

Scans downloaded packages for suspicious patterns such as:

* Network operations
* Subprocess execution
* Dynamic code execution
* File manipulation
* Encoded payloads

### Docker Sandboxing

Executes software inside an isolated Docker container to prevent direct host execution.

### IOC Extraction

Extracts Indicators of Compromise:

* URLs
* IP addresses
* Domains
* Email addresses
* Base64 strings

### MITRE ATT&CK Mapping

Maps discovered behaviors to MITRE ATT&CK techniques.

Examples:

* T1059 – Command and Scripting Interpreter
* T1071 – Application Layer Protocol
* T1105 – Ingress Tool Transfer
* T1204 – User Execution

### Risk Scoring Engine

Generates a risk score based on:

* Static findings
* Sandbox behavior
* IOC discovery
* MITRE mappings

### Reporting

Automatically generates:

* JSON Reports
* PDF Reports

### Scan History

Stores and retrieves previous scan reports.

### Cross Platform Architecture

Supports:

* Windows
* Linux
* macOS

---

## Supported Sources

### Python Packages

```bash
gama requests
gama flask
gama django
```

### GitHub Repositories

```bash
gama https://github.com/pallets/flask/archive/refs/heads/main.zip
```

### URLs

```bash
gama https://example.com/file.zip
```

### Local Files

```bash
gama suspicious.exe
```

### NPM Packages

```bash
gama npm:express
```

### Operating System Packages

```bash
gama python
gama java
gama git
```

---

## Architecture

                    User Request

                          ↓
 
                  Package Acquisition

                          ↓

                OS Stream Interception

                           ↓

                   Static Analysis

                           ↓

                     Hash Analysis

                           ↓

                      IOC Extraction

                             ↓
 
                       Docker Sandbox

                             ↓

                    Behavior Monitoring

                             ↓

                   MITRE ATT&CK Mapping

                             ↓

                      Risk Scoring

                              ↓

                JSON/PDF Report Generation

                             ↓

                     User Approval

                           ↓

                    Host Installation

---

## How Gama Works

### Step 1 – Intercept

The requested package is captured into an isolated temporary stream.

The package is not installed on the host.

### Step 2 – Analyze

Gama performs:

* File hashing
* Static scanning
* IOC extraction

### Step 3 – Sandbox

If Docker is available:

* Package is transferred to sandbox
* Executed in isolation
* Behavior monitored

If Docker is unavailable:

* Static analysis continues
* Dynamic analysis is skipped

### Step 4 – Risk Assessment

Findings are correlated and scored.

Example:

```text
Risk Score: 72/100
Verdict: Medium Risk
```

### Step 5 – Reporting

Detailed reports are generated.

```text
reports/
 ├── report.json
 └── report.pdf
```

### Step 6 – Installation Decision

User decides:

```text
Install this package on host system? [Yes/No]:
```

Only approved packages are installed.

---

## Installation

### Clone Repository

```bash
git clone https://github.com/Simhadas007/Gama.git

cd Gama
```

### Install

```bash
pip install .
```

### Verify

```bash
gama --version
```

---

## Usage

Scan Package

```bash
gama requests
```

View History

```bash
gama --history
```

View Latest Report

```bash
gama --report latest
```

Show Version

```bash
gama --version
```

Verbose Mode

```bash
gama requests --verbose
```

---

## Example Output

```text
Gama Zero-Trust Installer

Target: requests

✓ Package captured
✓ Static analysis completed
✓ IOC extraction completed
✓ Docker sandbox started
✓ Sandbox execution completed

Risk Summary

Risk Score : 12/100
Verdict    : LOW RISK

Reports

JSON : report.json
PDF  : report.pdf
```

---

## Security Model

Gama follows Zero-Trust principles:

* Assume breach
* Verify everything
* Isolate execution
* Minimize trust
* Monitor behavior
* Require approval before installation

---

## Future Roadmap

Version 1.1

* YARA scanning
* VirusTotal integration
* SBOM generation
* CVE enrichment

Version 2.0

* Web dashboard
* Threat intelligence feeds
* Cloud sandbox execution
* Multi-user reporting

---

## Author

Narasimha Pavan B

Cybersecurity | DevSecOps | Security Engineering

---

## License

MIT License
