# Ground Truth Vulnerability Log

Manually verified vulnerabilities in lab targets (DVWA, Juice Shop), used as the
reference set for evaluating baseline ZAP scans vs the enhanced workflow.

## DVWA

| # | Vuln Class | Security Level | Location/Module | Payload | Result | Verified |
|---|---|---|---|---|---|---|
| 1 | SQL Injection | Low | SQL Injection module (User ID field) | `1' OR '1'='1` | Returned all 5 user records instead of 1 | Yes |

## Juice Shop

| # | Vuln Class | Location | Payload | Result | Verified |
|---|---|---|---|---|---|

## Notes

- Security levels tested so far: DVWA Low only. Medium and High still to do.
- Each entry here should later map to a ZAP alert (or lack thereof) in baseline results.
