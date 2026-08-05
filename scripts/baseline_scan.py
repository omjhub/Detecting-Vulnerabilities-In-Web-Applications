"""
Baseline ZAP Scan
------------------
Runs ZAP's spider and a SCOPED active scanner against target applications
(DVWA, Juice Shop) with no custom enhancement.

Both targets are seeded with proxied requests to known input-bearing
endpoints before active scanning, since ZAP's active scanner can only test
URLs already present in its site tree (i.e. traffic it has observed).
Juice Shop's login/feedback endpoints require actual form submission
(POST with JSON body) which its AJAX spider does not trigger on its own.

Active scanning is scoped to these known endpoints rather than the entire
discovered site, both for methodological consistency with manual testing
and because scanning the full site (700+ URLs) repeatedly caused an
out-of-memory crash.

Usage:
    caffeinate -i python3 baseline_scan.py
"""

import time
import json
import csv
import re
import requests
from datetime import datetime
from zapv2 import ZAPv2

ZAP_ADDRESS = 'http://127.0.0.1:8090'

TARGETS = {
    "dvwa": "http://host.docker.internal:8080",
    "juiceshop": "http://host.docker.internal:3000",
}

DVWA_ENDPOINTS = [
    "http://host.docker.internal:8080/vulnerabilities/sqli/?id=1&Submit=Submit#",
    "http://host.docker.internal:8080/vulnerabilities/sqli_blind/?id=1&Submit=Submit#",
    "http://host.docker.internal:8080/vulnerabilities/xss_r/?name=test#",
    "http://host.docker.internal:8080/vulnerabilities/xss_s/",
]

JUICESHOP_ENDPOINTS = [
    "http://host.docker.internal:3000/rest/products/search?q=test",
    "http://host.docker.internal:3000/rest/user/login",
    "http://host.docker.internal:3000/api/Feedbacks/",
]

zap = ZAPv2(apikey='', proxies={'http': ZAP_ADDRESS, 'https': ZAP_ADDRESS})


def disable_passive_scan():
    print("\n[POLICY] Disabling passive scan to reduce memory overhead...")
    zap.pscan.set_enabled('false')
    print("[POLICY] Passive scan disabled.")


def authenticate_dvwa():
    print("\n[AUTH] Logging into DVWA via ZAP proxy...")
    proxies = {'http': ZAP_ADDRESS, 'https': ZAP_ADDRESS}
    session = requests.Session()
    session.proxies = proxies
    session.verify = False

    login_page = session.get(f"{TARGETS['dvwa']}/login.php")
    print(f"[AUTH DEBUG] Status code: {login_page.status_code}")

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

    login_data = {
        "username": "admin", "password": "password",
        "Login": "Login", "user_token": user_token,
    }
    resp = session.post(f"{TARGETS['dvwa']}/login.php", data=login_data)

    if "Logout" in resp.text or resp.status_code == 302:
        print("[AUTH] DVWA login successful, session captured by ZAP.")
    else:
        print("[AUTH] WARNING: login may have failed - check manually.")

    session.post(f"{TARGETS['dvwa']}/security.php", data={"security": "low", "seclev_submit": "Submit"})
    print("[AUTH] DVWA security level set to Low.")
    return session


def seed_dvwa_endpoints(session):
    print("\n[SEED] Visiting known vulnerable DVWA modules to seed ZAP's site tree...")
    for url in DVWA_ENDPOINTS[:-1]:
        try:
            r = session.get(url)
            print(f"  Visited: {url} -> status {r.status_code}")
        except Exception as e:
            print(f"  ERROR visiting {url}: {e}")

    try:
        stored_xss_page = DVWA_ENDPOINTS[-1]
        session.get(stored_xss_page)
        session.post(stored_xss_page, data={"txtName": "test", "mtxMessage": "test", "btnSign": "Sign Guestbook"})
        print(f"  Visited + submitted: {stored_xss_page}")
    except Exception as e:
        print(f"  ERROR visiting stored XSS page: {e}")

    print("[SEED] Done seeding DVWA endpoints.")


def seed_juiceshop_endpoints():
    """Send proxied requests to Juice Shop's login and feedback endpoints
    so ZAP records them in its site tree. These require actual POST
    submissions with JSON bodies (Juice Shop's API format), which the
    AJAX spider does not trigger just by crawling links."""
    print("\n[SEED] Seeding Juice Shop endpoints (login, feedback) via proxy...")
    proxies = {'http': ZAP_ADDRESS, 'https': ZAP_ADDRESS}
    session = requests.Session()
    session.proxies = proxies
    session.verify = False

    base = TARGETS["juiceshop"]

    try:
        r = session.get(f"{base}/rest/products/search?q=test")
        print(f"  Visited search -> status {r.status_code}")
    except Exception as e:
        print(f"  ERROR visiting search: {e}")

    try:
        r = session.post(
            f"{base}/rest/user/login",
            json={"email": "test@test.com", "password": "test123"},
            headers={"Content-Type": "application/json"},
        )
        print(f"  Visited login (POST) -> status {r.status_code}")
    except Exception as e:
        print(f"  ERROR visiting login: {e}")

    try:
        r = session.post(
            f"{base}/api/Feedbacks/",
            json={"comment": "test feedback", "rating": 3},
            headers={"Content-Type": "application/json"},
        )
        print(f"  Visited feedback (POST) -> status {r.status_code}")
    except Exception as e:
        print(f"  ERROR visiting feedback: {e}")

    print("[SEED] Done seeding Juice Shop endpoints.")


def configure_scan_policy():
    print("\n[POLICY] Restricting active scan to SQLi/XSS-relevant rules...")
    all_scanners = zap.ascan.scanners()
    keywords = ["sql injection", "cross site scripting", "persistent xss"]
    exclude_keywords = ["dom xss"]

    enabled_count = 0
    disabled_count = 0
    for scanner in all_scanners:
        name = scanner.get("name", "").lower()
        scan_id = scanner.get("id")
        if any(k in name for k in keywords) and not any(x in name for x in exclude_keywords):
            zap.ascan.enable_scanners(scan_id)
            enabled_count += 1
        else:
            zap.ascan.disable_scanners(scan_id)
            disabled_count += 1

    print(f"[POLICY] Enabled {enabled_count} SQLi/XSS-relevant scan rules, disabled {disabled_count} others.")


def run_spider(target_url):
    print(f"\n[SPIDER] Starting spider scan on {target_url}")
    scan_id = zap.spider.scan(target_url)
    while int(zap.spider.status(scan_id)) < 100:
        time.sleep(2)
    results = zap.spider.results(scan_id)
    print(f"[SPIDER] Complete. URLs found: {len(results)}")
    return results


def run_ajax_spider(target_url):
    print(f"\n[AJAX SPIDER] Starting AJAX spider scan on {target_url}")
    zap.ajaxSpider.scan(target_url)
    max_polls = 20
    polls = 0
    while zap.ajaxSpider.status == 'running' and polls < max_polls:
        time.sleep(3)
        polls += 1
    results = zap.ajaxSpider.results(start=0, count=1000)
    print(f"[AJAX SPIDER] Complete. URLs found: {len(results)}")
    return results


def run_scoped_active_scan(endpoints):
    for url in endpoints:
        print(f"\n[SCOPED SCAN] Scanning: {url}")
        scan_id = zap.ascan.scan(url, recurse=False)
        if not str(scan_id).isdigit():
            print(f"  ERROR: could not start scan for {url}. Response: {scan_id}")
            continue
        try:
            while int(zap.ascan.status(scan_id)) < 100:
                time.sleep(3)
            print("  Complete.")
        except requests.exceptions.ProxyError:
            print(f"  ERROR: lost connection to ZAP while scanning {url}")
            return False
    return True


def get_alerts(target_url):
    try:
        alerts = zap.core.alerts(baseurl=target_url)
        print(f"\n[ALERTS] {target_url} -> {len(alerts)} alert(s):")
        for a in alerts:
            print(f"    - {a.get('alert')} | {a.get('risk')} | {a.get('url')} | param={a.get('param')}")
        return alerts
    except requests.exceptions.ProxyError:
        print(f"[ALERTS] ERROR: Could not reach ZAP to fetch alerts for {target_url}")
        return []


def save_target_results(target_name, alerts):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = f"results/baseline_{target_name}_{timestamp}.json"
    with open(json_path, "w") as f:
        json.dump({target_name: alerts}, f, indent=2)
    print(f"[SAVE] {target_name} raw results saved to {json_path}")

    csv_path = f"results/baseline_{target_name}_{timestamp}.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["target", "alert_name", "risk", "confidence", "url", "param"])
        for alert in alerts:
            writer.writerow([
                target_name, alert.get("alert"), alert.get("risk"),
                alert.get("confidence"), alert.get("url"), alert.get("param"),
            ])
    print(f"[SAVE] {target_name} summary CSV saved to {csv_path}")


def main():
    disable_passive_scan()
    endpoint_map = {"dvwa": DVWA_ENDPOINTS, "juiceshop": JUICESHOP_ENDPOINTS}

    for name, url in TARGETS.items():
        print(f"\n{'='*50}\nTARGET: {name} ({url})\n{'='*50}")

        if name == "dvwa":
            session = authenticate_dvwa()
            if session:
                seed_dvwa_endpoints(session)
            run_spider(url)
        else:
            run_ajax_spider(url)
            seed_juiceshop_endpoints()

        configure_scan_policy()
        scan_ok = run_scoped_active_scan(endpoint_map[name])
        alerts = get_alerts(url)

        save_target_results(name, alerts)

        if not scan_ok:
            print(f"[{name}] WARNING: scan did not complete cleanly, results may be partial.")

    print("\nBaseline scan run finished (see per-target result files in results/).")


if __name__ == "__main__":
    main()