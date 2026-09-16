# Website Security Scanner

A simple web-based security scanner built using Python and Flask. The project uses different security tools to scan a website, collect their outputs and identify possible security issues.

## Features

* Scan a website by entering its URL
* Uses multiple security tools
* Shows security score and grade
* Shows detected security findings
* Shows severity and confidence of findings
* Provides basic security recommendations
* Displays the original output of each tool

## Tools Used

* Nmap - Finds open ports and services
* Nikto - Checks common web server issues
* SSLScan - Checks SSL/TLS configuration
* WhatWeb - Identifies web technologies
* SQLMap - Tests for SQL injection
* WPScan - Scans WordPress websites
* WHOIS - Collects domain information

## How It Works

The application is built using Flask.

The user enters a website URL and the Flask backend runs the security tools on the target. The output from each tool is then analyzed using separate parsing logic.

The scanner converts useful observations into security findings. Each finding is given:

* Severity
* Confidence
* Reason
* Penalty

The final score is calculated from the detected findings.

The project does not simply give a fixed penalty to a particular tool. For example, Nmap itself does not automatically reduce the score. The score changes when the scanner identifies a security-related finding from the Nmap output.

## Scoring

The project uses the following application-defined values:

| Severity      | Penalty |
| ------------- | ------- |
| Critical      | 25      |
| High          | 18      |
| Medium        | 10      |
| Low           | 4       |
| Informational | 0       |

The effective penalty is calculated using the confidence of the finding.

```text
Effective Penalty = Severity Penalty × Confidence
```

The final score starts from 100 and the detected penalties are deducted from it.

The grade is then calculated from the final score.

These scoring values are part of the project design and are not meant to be an industry-standard security rating.

## Project Structure

```text
Website-Security-Scanner/
│
├── app.py
├── requirements.txt
├── .gitignore
├── README.md
│
├── templates/
│   └── app.html
│
└── static/
    └── app.css
```

## Technologies

* Python
* Flask
* Flask-CORS
* HTML
* CSS
* JavaScript
* Kali Linux security tools

## Output

The website displays:

* Security score
* Security grade
* Security findings
* Severity
* Confidence
* Effective penalty
* Recommendations
* Raw output from all the security tools

## Limitations

The scanner uses rule-based parsing for the tool outputs, so results depend on the output format of the installed tool versions.

A detected finding may also need manual verification before considering it a confirmed vulnerability.

This project is mainly intended for learning and authorized security testing. It is not a replacement for a professional vulnerability assessment.

## Purpose

This project was developed to understand how security tools can be integrated into a Python web application and how their outputs can be processed to generate useful security information.
