# Detecting Vulnerabilities in Web Applications — Enhancing ZAP's Detection Granularity

**Context:** MSc Computer Forensics and Cybersecurity dissertation, University of Greenwich, September 2026.
**Full dissertation:** [available on request / linked from my portfolio]
**Question:** Can a lightweight, targeted enhancement to OWASP ZAP's workflow measurably improve the actionable detail available to a tester, beyond a plain "vulnerable: yes" alert?

## The problem this addresses

OWASP ZAP and similar scanners are widely used, but a positive alert only confirms that a vulnerability class exists at a location, not which specific technique exploits it or what real-world impact it enables. There's a real difference between "this endpoint is vulnerable to SQL injection" and "this endpoint leaks all six username/password-hash pairs via a UNION-based attack," and ZAP's own output doesn't make that distinction.

## What I built

A controlled empirical comparison across three stages, tested against DVWA (a traditional server-rendered app) and OWASP Juice Shop (a modern single-page app), in an isolated Docker lab:

1. **Manual ground truth** — 16 vulnerabilities manually found and verified by hand first, establishing what should be detected before any tool touched the target.
2. **Unmodified ZAP baseline scan** — run exactly as the tool ships, no configuration tuning.
3. **A Python enhancement tool I built** (`enhancement.py`) — an expanded payload library plus baseline-differential response verification: it compares response behaviour against a known baseline rather than just pattern-matching a response, a capability with no equivalent setting inside ZAP itself.

## Results

Across nine tested techniques, classified against standard detection outcomes (true/false positive, true/false negative):

| | True Positives | False Negatives | True Negatives | False Positives |
|---|---|---|---|---|
| ZAP baseline | 4 | 3 | 0 (not possible with ZAP's alert format) | 0 |
| Enhancement tool | 6 | 1 | 2 | 0 |

The enhancement tool matched every single detection ZAP made, and converted two of ZAP's three false negatives into confirmed true positives, specifically two XSS filter-bypass techniques (a nested-tag bypass and an `<img onerror>` handler bypass) that fell outside ZAP's default payload behaviour but were confirmed present through manual testing. It did this without introducing a single false positive of its own, evidenced by two cases where it correctly withheld confirmation rather than over-reporting.

Where both tools detected the same underlying vulnerability, the enhancement tool distinguished a basic injection point from a confirmed six-record credential exfiltration via UNION-based extraction, a distinction ZAP's generic alert cannot make.

**Honest limitation, stated plainly:** blind SQL injection was detected by neither approach, and is reported as a clear gap rather than omitted.

## Why the response-differential approach matters

The enhancement tool doesn't just check whether a payload "worked" once. It compares response behaviour against a baseline across multiple checks, for example a row-count anomaly (1 row returned normally versus 5 or 6 after an injection) or an HTTP status code anomaly (a 500 error appearing only under a specific payload). That's what lets it confirm absence, not just presence, correctly returning a negative result on a quote-free bypass attempt against DVWA where the underlying query wraps input in quotes, rather than reporting a false positive.

## Tools

`Python` `OWASP ZAP` `ZAP REST API` `DVWA` `OWASP Juice Shop` `Docker`
