from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess

app = Flask(__name__)
CORS(app)

def run_command(command):
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=180
        )
        output = result.stdout if result.stdout else ""
        error = result.stderr if result.stderr else ""
        return (output + "\n" + error).strip()
    except subprocess.TimeoutExpired:
        return "Command timed out."
    except Exception as e:
        return f"Error: {str(e)}"

def scan_website(url):
    results = {}
    url_clean = url.replace("https://", "").replace("http://", "").strip("/")
    results['nmap']    = run_command(f"nmap -p 80,443 --script ssl-enum-ciphers {url_clean}")
    results['nikto']   = run_command(f"nikto -h {url_clean}")
    results['sslscan'] = run_command(f"sslscan {url_clean}")
    results['whatweb'] = run_command(f"whatweb {url_clean}")
    results['sqlmap']  = run_command(f"sqlmap -u {url} --batch --crawl=1 --level=1 --risk=1")
    results['wpscan']  = run_command(f"wpscan --url {url} --no-update")
    results['whois']   = run_command(f"whois {url_clean}")
    return results

def evaluate_security(results):
    score = 100
    suggestions = []

    nikto_output = results.get('nikto', '').lower()
    nikto_hits = sum(
        word in nikto_output 
        for word in ["vulnerable", "insecure", "outdated", "error", "issue", "obsolete", "x-powered-by"]
    )
    score -= nikto_hits * 8
    if nikto_hits > 0:
        suggestions.append("Nikto found issues: review vulnerabilities listed above.")

    ssl_output = results.get('sslscan', '').lower()
    ssl_hits = sum(
        word in ssl_output
        for word in ["ssl", "vulnerable", "fail", "weak", "error", "deprecated"]
    )
    score -= ssl_hits * 5
    if ssl_hits > 0: 
        suggestions.append("SSLScan found weak HTTPS settings or issues.")

    whatweb_output = results.get('whatweb', '').lower()
    if "wordpress" in whatweb_output:
        score -= 5
        suggestions.append("WordPress detected by WhatWeb: ensure it's patched and secured.")

    sqlmap_output = results.get('sqlmap', '').lower()
    sqlmap_hits = sum(
        word in sqlmap_output
        for word in ["injection", "vulnerable", "error", "possible sql injection"]
    )
    score -= sqlmap_hits * 12
    if sqlmap_hits > 0:
        suggestions.append("SQLMap found probable SQLi vulnerability. Prioritize remediation.")

    wpscan_output = results.get('wpscan', '').lower()
    wp_hits = sum(
        word in wpscan_output
        for word in ["vulnerable", "error", "outdated", "issue"]
    )
    score -= wp_hits * 7
    if wp_hits > 0:
        suggestions.append("WPSCan found issues on WordPress site.")

    nmap_output = results.get('nmap', '').lower()
    nm_hits = sum(
        word in nmap_output 
        for word in ["vulnerable", "weak", "error", "outdated", "fail"]
    )
    score -= nm_hits * 6
    if nm_hits > 0:
        suggestions.append("Nmap found weak SSL or configuration vulnerabilities.")

    score = max(min(score, 100), 15)  # Clamp score between 15 and 100

    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    if not suggestions:
        suggestions.append("No major vulnerabilities found. Good job! Keep monitoring regularly.")

    return score, grade, suggestions

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url = data.get('url', '')
    if not url:
        return jsonify({"error": "URL is required!"}), 400
    results = scan_website(url)
    score, grade, suggestions = evaluate_security(results)
    return jsonify({
        "url": url,
        "score": score,
        "grade": grade,
        "suggestions": suggestions,
        "results": results
    })

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)