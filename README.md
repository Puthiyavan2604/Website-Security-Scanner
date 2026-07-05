WEBSITE  SECURITY SCANNER

This is a Flask web application that runs a set of security scanning tools against a given URL and returns a security score and grade. The frontend is a static HTML page that communicates with the backend via a POST request.

Requirements
The following tools must be installed on the system where the Flask server runs:

nmap

nikto

sslscan

whatweb

sqlmap

wpscan

whois

They are invoked via subprocess. If any tool is missing, its output will be empty or an error message will appear.

Installation
Clone the repository (or download the three files).

Install Python dependencies:

text
pip install flask flask-cors
Install the security tools using your package manager. For example, on Debian/Ubuntu:

text
sudo apt install nmap nikto sslscan whatweb sqlmap wpscan whois
On macOS with Homebrew:

text
brew install nmap nikto sslscan whatweb sqlmap wpscan whois
Running the application
Start the Flask backend:

text
python main.py
The server runs on http://0.0.0.0:5000 with debug mode enabled.

Open main.html in a web browser. No web server is required for the frontend; it is a static file.

Usage
Enter a full URL (including http:// or https://) into the input field and click "Run Scan". The backend will execute all tools sequentially, each with a timeout of 180 seconds. After completion, the result page shows:

The scanned URL

A security score (0–100) and a letter grade (A–F)

A list of suggestions based on detected issues

The raw output from each tool

Scoring logic
The score starts at 100. For each tool, the output is scanned for specific keywords. Each match reduces the score by a fixed amount:

Tool	Penalty per keyword match
nikto	8
sqlmap	12
wpscan	7
nmap	6
sslscan	5
whatweb	5 (if WordPress is detected)
The keywords are: "vulnerable", "insecure", "outdated", "error", "issue", "obsolete", "x-powered-by", "fail", "weak", "deprecated", "injection", "possible sql injection".

The score is clamped between 15 and 100. Grade mapping:

A: 90–100

B: 75–89

C: 60–74

D: 40–59

F: <40

Suggestions are generated based on which tools reported issues. If no issues are found, a single suggestion says no major vulnerabilities were found.

Disclaimer
This tool runs active security scans against the target URL. Do not use it against domains you do not own or have explicit permission to test. Unauthorised scanning is illegal in many jurisdictions.

File structure
main.py – Flask backend, scanning functions, and scoring logic.

main.html – Frontend HTML with embedded JavaScript.

App.css – Styling for the frontend.

