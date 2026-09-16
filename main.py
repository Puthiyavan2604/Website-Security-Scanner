from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import subprocess
import re
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

SCAN_TIMEOUT = 180

SEVERITY_PENALTY = {
    "critical": 25,
    "high": 18,
    "medium": 10,
    "low": 4,
    "informational": 0
}


def validate_url(url):
    if not url:
        return False, "URL is required."

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        return False, "URL must start with http:// or https://"

    try:
        parsed = urlparse(url)

        if not parsed.hostname:
            return False, "Invalid hostname."

        dangerous_chars = [
            ";", "|", "&", "`", "$",
            "(", ")", "<", ">", "\n", "\r"
        ]

        if any(char in url for char in dangerous_chars):
            return False, "Invalid characters found in URL."

        return True, url

    except Exception:
        return False, "Invalid URL."


def run_command(command, timeout=SCAN_TIMEOUT):
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False
        )

        stdout = process.stdout or ""
        stderr = process.stderr or ""

        combined_output = stdout

        if stderr.strip():
            combined_output += "\n\n[stderr]\n" + stderr

        return {
            "output": combined_output.strip(),
            "return_code": process.returncode,
            "status": "completed"
        }

    except subprocess.TimeoutExpired:
        return {
            "output": "Tool execution timed out.",
            "return_code": -1,
            "status": "timeout"
        }

    except FileNotFoundError:
        return {
            "output": "Tool is not installed or is not available.",
            "return_code": -1,
            "status": "not_installed"
        }

    except Exception as error:
        return {
            "output": f"Tool execution error: {str(error)}",
            "return_code": -1,
            "status": "error"
        }


def scan_website(url):
    parsed = urlparse(url)
    hostname = parsed.hostname

    results = {}

    results["Nmap"] = run_command([
        "nmap",
        "-sV",
        hostname
    ])

    results["Nikto"] = run_command([
        "nikto",
        "-h",
        url
    ])

    results["SSLScan"] = run_command([
        "sslscan",
        hostname
    ])

    results["WhatWeb"] = run_command([
        "whatweb",
        url
    ])

    results["SQLMap"] = run_command([
        "sqlmap",
        "-u",
        url,
        "--batch",
        "--level=1",
        "--risk=1"
    ])

    results["WPScan"] = run_command([
        "wpscan",
        "--url",
        url,
        "--no-update"
    ])

    results["WHOIS"] = run_command([
        "whois",
        hostname
    ])

    return results


def create_finding(
    tool,
    finding_id,
    title,
    severity,
    confidence,
    reason
):
    return {
        "tool": tool,
        "id": finding_id,
        "title": title,
        "severity": severity,
        "confidence": round(confidence, 2),
        "reason": reason
    }


def parse_nmap(output):
    findings = []

    for line in output.splitlines():
        match = re.search(
            r"(\d+)/tcp\s+open\s+([^\s]+)",
            line,
            re.IGNORECASE
        )

        if not match:
            continue

        port = int(match.group(1))
        service = match.group(2).lower()

        database_services = {
            3306: "MySQL",
            5432: "PostgreSQL",
            1433: "Microsoft SQL Server",
            1521: "Oracle Database",
            27017: "MongoDB",
            6379: "Redis"
        }

        if port in database_services:
            database_name = database_services[port]

            findings.append(
                create_finding(
                    "Nmap",
                    f"exposed_database_{port}",
                    f"{database_name} service exposed on port {port}",
                    "medium",
                    0.90,
                    "A database service is reachable through an open network port. "
                    "The actual security impact depends on network exposure and access controls."
                )
            )

        elif port == 23 or service == "telnet":
            findings.append(
                create_finding(
                    "Nmap",
                    "telnet_exposed",
                    "Telnet service exposed",
                    "high",
                    0.95,
                    "Telnet is an unencrypted remote administration protocol."
                )
            )

        elif port == 21 or service == "ftp":
            findings.append(
                create_finding(
                    "Nmap",
                    "ftp_exposed",
                    "FTP service exposed",
                    "low",
                    0.90,
                    "FTP is an exposed file-transfer service and may transmit "
                    "credentials without encryption depending on configuration."
                )
            )

    return findings


def parse_sslscan(output):
    findings = []

    lower_output = output.lower()

    if re.search(
        r"\btlsv1\.0\b|\btls\s*1\.0\b",
        lower_output
    ):
        findings.append(
            create_finding(
                "SSLScan",
                "tls_10_enabled",
                "TLS 1.0 protocol detected",
                "high",
                0.95,
                "TLS 1.0 is an obsolete protocol version and should not "
                "normally be enabled on modern public-facing services."
            )
        )

    if re.search(
        r"\btlsv1\.1\b|\btls\s*1\.1\b",
        lower_output
    ):
        findings.append(
            create_finding(
                "SSLScan",
                "tls_11_enabled",
                "TLS 1.1 protocol detected",
                "high",
                0.95,
                "TLS 1.1 is deprecated and should normally be disabled."
            )
        )

    if re.search(
        r"\bsslv2\b.*(enabled|accepted)",
        lower_output
    ):
        findings.append(
            create_finding(
                "SSLScan",
                "sslv2_enabled",
                "SSLv2 protocol enabled",
                "critical",
                0.95,
                "SSLv2 is obsolete and insecure."
            )
        )

    if re.search(
        r"\bsslv3\b.*(enabled|accepted)",
        lower_output
    ):
        findings.append(
            create_finding(
                "SSLScan",
                "sslv3_enabled",
                "SSLv3 protocol enabled",
                "high",
                0.95,
                "SSLv3 is obsolete and should not be used."
            )
        )

    weak_patterns = [
        (r"\bnull\b.*cipher", "Null cipher detected"),
        (r"\bexport\b.*cipher", "Export-grade cipher detected"),
        (r"\brc4\b", "RC4 cipher detected"),
        (r"\b3des\b", "3DES cipher detected")
    ]

    for pattern, title in weak_patterns:
        if re.search(pattern, lower_output):
            finding_id = "weak_cipher_" + title.lower().replace(" ", "_")

            findings.append(
                create_finding(
                    "SSLScan",
                    finding_id,
                    title,
                    "medium",
                    0.85,
                    "The scanner reported a legacy or weak cryptographic configuration."
                )
            )

    return findings


def parse_nikto(output):
    findings = []

    for line in output.splitlines():
        text = line.strip()

        if not text.startswith("+"):
            continue

        lower = text.lower()

        if any(
            phrase in lower
            for phrase in [
                "directory indexing",
                "directory listing",
                "index of"
            ]
        ):
            findings.append(
                create_finding(
                    "Nikto",
                    "directory_listing",
                    "Directory listing or indexing detected",
                    "medium",
                    0.90,
                    "The web server appears to expose directory contents."
                )
            )

        elif any(
            phrase in lower
            for phrase in [
                "server leaks",
                "server information",
                "version information",
                "server version"
            ]
        ):
            findings.append(
                create_finding(
                    "Nikto",
                    "server_information_disclosure",
                    "Web server information disclosure",
                    "low",
                    0.80,
                    "The scanner reported information about the underlying web server."
                )
            )

        elif any(
            phrase in lower
            for phrase in [
                "/.env",
                "backup file",
                "configuration file",
                "config file",
                "password file"
            ]
        ):
            findings.append(
                create_finding(
                    "Nikto",
                    "sensitive_file_exposure",
                    "Potentially sensitive file exposed",
                    "high",
                    0.85,
                    "The web scanner identified a potentially sensitive file or backup."
                )
            )

        elif len(text) > 20:
            findings.append(
                create_finding(
                    "Nikto",
                    "nikto_observation_" + str(abs(hash(text)) % 100000),
                    "Nikto reported a web-server observation",
                    "informational",
                    0.60,
                    text.lstrip("+").strip()
                )
            )

    return findings


def parse_whatweb(output):
    findings = []

    known_technologies = [
        "wordpress",
        "apache",
        "nginx",
        "php",
        "jquery",
        "drupal",
        "joomla",
        "iis"
    ]

    lower_output = output.lower()

    detected = []

    for technology in known_technologies:
        if technology in lower_output:
            detected.append(technology)

    if detected:
        technology_text = ", ".join(
            item.upper() if item == "php" else item.title()
            for item in sorted(set(detected))
        )

        findings.append(
            create_finding(
                "WhatWeb",
                "technology_identification",
                "Web technologies identified",
                "informational",
                1.00,
                "Detected technologies: " +
                technology_text +
                ". Technology identification alone does not establish a vulnerability."
            )
        )

    return findings


def parse_sqlmap(output):
    findings = []

    lower_output = output.lower()

    strong_patterns = [
        r"is vulnerable",
        r"injectable",
        r"parameter .* is vulnerable",
        r"sql injection"
    ]

    strong_match = any(
        re.search(pattern, lower_output)
        for pattern in strong_patterns
    )

    if strong_match:
        findings.append(
            create_finding(
                "SQLMap",
                "sql_injection_detected",
                "Potential SQL injection identified by SQLMap",
                "critical",
                0.95,
                "SQLMap reported an injection-related finding during its test."
            )
        )

    elif (
        "parameter:" in lower_output
        and (
            "payload:" in lower_output
            or "type:" in lower_output
        )
    ):
        findings.append(
            create_finding(
                "SQLMap",
                "sqlmap_injection_test_result",
                "SQLMap identified an injection test result",
                "high",
                0.80,
                "SQLMap produced structured injection-test information. "
                "The result should be manually verified before treating it as confirmed."
            )
        )

    return findings


def parse_wpscan(output):
    findings = []

    lower_output = output.lower()

    if "wordpress" in lower_output:
        findings.append(
            create_finding(
                "WPScan",
                "wordpress_detected",
                "WordPress installation detected",
                "informational",
                1.00,
                "WPScan identified WordPress. This observation alone does not "
                "mean that the installation is vulnerable."
            )
        )

    vulnerability_indicators = [
        "fixed in",
        "vulnerability",
        "cve-",
        "interesting finding"
    ]

    vulnerability_found = any(
        indicator in lower_output
        for indicator in vulnerability_indicators
    )

    if vulnerability_found:
        findings.append(
            create_finding(
                "WPScan",
                "wordpress_security_finding",
                "WPScan reported a WordPress security finding",
                "high",
                0.85,
                "WPScan reported vulnerability-related information. "
                "The specific issue should be reviewed from the scanner output."
            )
        )

    return findings


def parse_whois(output):
    findings = []

    if output.strip():
        findings.append(
            create_finding(
                "WHOIS",
                "domain_information",
                "Domain registration information collected",
                "informational",
                1.00,
                "WHOIS provided domain-registration information. "
                "This is reconnaissance data and is not automatically treated as a vulnerability."
            )
        )

    return findings


def parse_tool_output(tool, output):
    if not output:
        return []

    parsers = {
        "Nmap": parse_nmap,
        "Nikto": parse_nikto,
        "SSLScan": parse_sslscan,
        "WhatWeb": parse_whatweb,
        "SQLMap": parse_sqlmap,
        "WPScan": parse_wpscan,
        "WHOIS": parse_whois
    }

    parser = parsers.get(tool)

    if parser:
        return parser(output)

    return []


def deduplicate_findings(findings):
    unique = {}

    for finding in findings:
        finding_id = finding["id"]

        if finding_id not in unique:
            finding_copy = finding.copy()
            finding_copy["supporting_tools"] = [
                finding["tool"]
            ]
            unique[finding_id] = finding_copy

        else:
            existing = unique[finding_id]

            if finding["tool"] not in existing["supporting_tools"]:
                existing["supporting_tools"].append(
                    finding["tool"]
                )

            existing["confidence"] = min(
                1.0,
                existing["confidence"] + 0.05
            )

    return list(unique.values())


def calculate_score(findings):
    total_penalty = 0.0

    for finding in findings:
        severity = finding["severity"]
        confidence = finding["confidence"]

        base_penalty = SEVERITY_PENALTY.get(
            severity,
            0
        )

        effective_penalty = base_penalty * confidence

        finding["base_penalty"] = base_penalty
        finding["effective_penalty"] = round(
            effective_penalty,
            2
        )

        total_penalty += effective_penalty

    score = 100 - total_penalty

    score = max(
        15,
        min(100, score)
    )

    return round(score, 2)


def calculate_grade(score):
    if score >= 90:
        return "A"

    if score >= 75:
        return "B"

    if score >= 60:
        return "C"

    if score >= 40:
        return "D"

    return "F"


def generate_suggestions(findings):
    suggestions = []

    suggestion_map = {
        "tls_10_enabled":
            "Disable TLS 1.0 and use modern TLS versions.",

        "tls_11_enabled":
            "Disable TLS 1.1 and use modern TLS versions.",

        "sslv2_enabled":
            "Disable SSLv2 immediately.",

        "sslv3_enabled":
            "Disable SSLv3.",

        "telnet_exposed":
            "Replace Telnet with a secure remote administration protocol.",

        "ftp_exposed":
            "Review whether FTP is required and consider encrypted alternatives.",

        "directory_listing":
            "Disable unnecessary directory indexing.",

        "server_information_disclosure":
            "Reduce unnecessary server-version information exposure.",

        "sensitive_file_exposure":
            "Remove or restrict access to sensitive configuration or backup files.",

        "exposed_database_3306":
            "Restrict external access to MySQL and expose it only to trusted systems.",

        "exposed_database_5432":
            "Restrict external access to PostgreSQL.",

        "exposed_database_1433":
            "Restrict external access to Microsoft SQL Server.",

        "exposed_database_1521":
            "Restrict external access to Oracle Database.",

        "exposed_database_27017":
            "Restrict external access to MongoDB.",

        "exposed_database_6379":
            "Restrict external access to Redis.",

        "sql_injection_detected":
            "Review the affected parameter and use parameterized queries or prepared statements.",

        "sqlmap_injection_test_result":
            "Manually verify the SQLMap result and review the affected application parameter.",

        "wordpress_security_finding":
            "Review the reported WordPress finding and update the affected component."
    }

    for finding in findings:
        finding_id = finding["id"]

        if finding_id in suggestion_map:
            suggestion = suggestion_map[finding_id]

            if suggestion not in suggestions:
                suggestions.append(suggestion)

    if not suggestions:
        suggestions.append(
            "No high-confidence security remediation was generated from the parsed findings."
        )

    return suggestions


def analyze_results(raw_results):
    all_findings = []

    for tool, result in raw_results.items():
        output = result.get(
            "output",
            ""
        )

        tool_findings = parse_tool_output(
            tool,
            output
        )

        all_findings.extend(
            tool_findings
        )

    findings = deduplicate_findings(
        all_findings
    )

    score = calculate_score(
        findings
    )

    grade = calculate_grade(
        score
    )

    suggestions = generate_suggestions(
        findings
    )

    return {
        "findings": findings,
        "score": score,
        "grade": grade,
        "suggestions": suggestions
    }


@app.route("/")
def home():
    return render_template("app.html")


@app.route("/scan", methods=["POST"])
def scan():
    try:
        data = request.get_json()

        if not data:
            return jsonify({
                "success": False,
                "error": "No JSON data received."
            }), 400

        url = data.get(
            "url",
            ""
        ).strip()

        valid, validated_url = validate_url(
            url
        )

        if not valid:
            return jsonify({
                "success": False,
                "error": validated_url
            }), 400

        raw_results = scan_website(
            validated_url
        )

        analysis = analyze_results(
            raw_results
        )

        return jsonify({
            "success": True,
            "url": validated_url,
            "score": analysis["score"],
            "grade": analysis["grade"],
            "findings": analysis["findings"],
            "suggestions": analysis["suggestions"],
            "results": raw_results
        })

    except Exception as error:
        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
