from flask import Flask, render_template, request, jsonify
import ssl
import socket
import whois
from datetime import datetime
from urllib.parse import urlparse
import re

app = Flask(__name__)

# -------- Extract Domain --------
def extract_domain(url):
    parsed = urlparse(url)

    domain = parsed.netloc
    if not domain:
        domain = parsed.path  # handle cases without http/https

    if domain.startswith("www."):
        domain = domain.replace("www.", "")

    return domain


# -------- SSL CHECK --------
def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry = cert.get('notAfter')
                return True, expiry
    except Exception:
        return False, None


# -------- WHOIS CHECK --------
def check_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        if not creation_date:
            return None

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        age_days = (datetime.now() - creation_date).days
        return age_days

    except Exception:
        return None


# -------- Suspicious Pattern Check --------
def check_patterns(domain):
    suspicious_words = ["login", "verify", "secure", "update", "account"]
    risk = 0
    findings = []

    # Check suspicious words only in domain
    for word in suspicious_words:
        if word in domain.lower():
            risk += 20
            findings.append(f"⚠ Suspicious word in domain: {word}")

    # Too many subdomains
    if domain.count('.') > 2:
        risk += 15
        findings.append("⚠ Too many subdomains detected.")

    # Excessive numbers
    if re.search(r"\d{3,}", domain):
        risk += 15
        findings.append("⚠ Excessive numbers in domain.")

    # Suspicious TLDs
    suspicious_tlds = [".xyz", ".top", ".tk", ".cf", ".gq"]
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            risk += 20
            findings.append(f"⚠ Suspicious TLD detected: {tld}")

    return risk, findings


# -------- MAIN ROUTES --------
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    domain = extract_domain(url)

    total_risk = 0
    results = []

    # -------- SSL CHECK --------
    ssl_valid, expiry = check_ssl(domain)

    if not ssl_valid:
        total_risk += 40
        results.append("❌ No valid SSL certificate detected.")
    else:
        results.append(f"✔ Valid SSL certificate. Expiry: {expiry}")

    # -------- DOMAIN AGE CHECK --------
    age = check_domain_age(domain)

    if age is None:
        results.append("ℹ WHOIS data not publicly available.")
    else:
        if age < 30:
            total_risk += 40
            results.append("❌ Domain is very new (<30 days).")
        elif age < 180:
            total_risk += 20
            results.append("⚠ Domain is relatively new (<6 months).")
        else:
            results.append("✔ Domain is old and established.")

    # -------- PATTERN CHECK --------
    pattern_risk, pattern_findings = check_patterns(domain)

    total_risk += pattern_risk
    results.extend(pattern_findings)

    # -------- FINAL RISK LEVEL --------
    if total_risk < 30:
        level = "Low Risk"
    elif total_risk < 60:
        level = "Suspicious"
    else:
        level = "High Risk"

    return jsonify({
        "risk": total_risk,
        "level": level,
        "details": results
    })


import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
