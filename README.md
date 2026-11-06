# EWB Phishing URL Awareness Checker

## Overview
Phishing is a deceptive social engineering attack where malicious actors use look-alike links to compromise credentials and sensitive personal data. This project is a lightweight, Python-based command-line tool that statically inspects individual URL strings to identify common structural red flags.

## Features
- Scans for hidden `@` routing symbols within the URL string.
- Flags obfuscated and unusually long links exceeding 100 characters.
- Detects the usage of bare IP address hostnames instead of legible domain configurations.
- Alerts when a hostname contains 5 or more complex naming segments or subdomains.
- Pinpoints the use of Punycode configurations (`xn--`) used to mimic mainstream brands.
- Identifies unencrypted HTTP connection layers.
- **[Improvement 1] Continuous Loop Integration:** Features a repeatable runtime execution sequence that allows users to scan multiple inputs until manually issuing a termination command (`q`).
- **[Improvement 2] Review Summary Alert:** Automatically generates an end-of-run log alert explicitly counting the total volume of flagged criteria.

## Requirements
- Python 3.10 or higher.
- No external packages or third-party dependencies required.

## How to Run
Execute the script using a terminal environment inside the project directory:

```bash
python phishing_checker.py
```

## Example Output
```text
Enter a sample URL (or type q to quit): http://192.0.2

Result:
- Uses an IP address instead of a familiar domain.
- Uses HTTP. HTTPS alone does not prove trust.

[!] REVIEW CAREFULLY: 2 warning sign(s) found.
```

## Screenshots
![Sample run](screenshots/sample_run.png)
![Test results](screenshots/test_results.png)

## Limitations
This program is exclusively an educational pattern analysis script. It strictly executes string logic locally and does not perform active malware lookups, verify active registration tables, or query domain reputation systems. A zero-warning result must never be interpreted as an absolute safety validation.

## Ethical Use
Intended strictly for defensive security training contexts. Do not compile user credentials, run lookups against unauthorized sites, or repurpose this framework to build deceptive interfaces.

## Author
[Your Name], EWB Courses Student
