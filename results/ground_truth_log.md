# Ground Truth Vulnerability Log

Manually verified vulnerabilities in lab targets (DVWA, Juice Shop), used as the
reference set for evaluating baseline ZAP scans vs the enhanced workflow.

## DVWA

| # | Vuln Class | Security Level | Location/Module | Payload | Result | Verified |
|---|---|---|---|---|---|---|
| 1 | SQL Injection | Low | SQL Injection module (User ID field) | `1' OR '1'='1` | Returned all 5 user records instead of 1 | Yes |
| 2 | SQL Injection | Low | SQL Injection module (User ID field) | `1' AND '1'='2` | Returned 0 rows, confirming injected logic is evaluated by the DB, not just lenient string matching | Yes |
| 3 | SQL Injection | Low | SQL Injection module (User ID field) | `1' UNION SELECT user, password FROM users #` | Extracted 6 username/password-hash pairs from the users table (unsalted MD5). Confirms data exfiltration beyond intended query scope. Note: original `--` comment syntax failed due to trailing space being trimmed by the input field; `#` used instead as MySQL/MariaDB comment marker. | Yes |
| 4 | SQL Injection | Medium | SQL Injection module (User ID dropdown) | `1' OR '1'='1` (bypassed dropdown restriction via browser DevTools, editing `<option value>` directly) | SQL syntax error returned. Confirms Medium applies server-side escaping (likely `mysqli_real_escape_string`) that neutralises the quote-breakout technique that worked at Low. Also confirms the dropdown was a client-side-only restriction, not a real control. | Yes |
| 5 | SQL Injection | Medium | SQL Injection module (User ID dropdown, DevTools bypass) | `1 OR 1=1` (no quotes) | Returned all 5 user records. Confirms the quote-escaping filter is fully bypassed by a quote-free payload. Demonstrates that Medium's validation is partial/brittle, not a genuine fix. | Yes |
| 6 | SQL Injection | High | SQL Injection module (Session ID mechanism, set via popup) | `1' OR '1'='1` | Only returned 1 row (admin), not all 5. Injection logic still executed but output appears capped, likely by a `LIMIT 1` clause in the High-level query. Absence of multi-row output does not necessarily mean the injection failed. | Yes |
| 7 | SQL Injection | High | SQL Injection module (Session ID mechanism) | `1' UNION SELECT user, password FROM users -- -` | Successfully returned all 6 username/password-hash pairs, same as the Low-level UNION result. Confirms UNION-based injection bypasses the apparent row-limiting behaviour that blocked the simple OR payload. High-level filtering is bypassable via a different technique than the ones blocked at Medium. | Yes |
| 8 | Reflected XSS | Low | XSS (Reflected) module (Name field) | `<script>alert('XSS')</script>` | Browser executed the injected JavaScript, displaying a real alert popup ("XSS"). Confirms the app reflects user input into the page without HTML-encoding it, allowing arbitrary script execution. | Yes |
| 9 | Reflected XSS | Medium | XSS (Reflected) module (Name field) | `<script>alert('XSS')</script>` | Blocked. Page displayed literal text "alert('XSS')" with tags stripped, confirming Medium applies a naive filter that removes the literal string `<script>`. | Yes |
| 10 | Reflected XSS | Medium | XSS (Reflected) module (Name field) | `<scr<script>ipt>alert('XSS')</scr<script>ipt>` | Successful bypass. Alert popup triggered. Confirms the filter performs a single, non-recursive removal of the string `<script>`, allowing nested tags to reassemble into a valid script tag after filtering completes. | Yes |
| 11 | Reflected XSS | High | XSS (Reflected) module (Name field) | `<script>alert('XSS')</script>` | Blocked. Tags stripped entirely from output. | Yes |
| 12 | Reflected XSS | High | XSS (Reflected) module (Name field) | `<scr<script>ipt>alert('XSS')</scr<script>ipt>` | Blocked. Nested-tag bypass that succeeded at Medium failed here, suggesting High uses a more robust filter (likely regex-based, matching "script" case-insensitively and/or recursively) rather than Medium's single-pass string removal. | Yes |
| 13 | Reflected XSS | High | XSS (Reflected) module (Name field) | `<img src=x onerror=alert('XSS')>` | Successful bypass. Confirms High's filter targets variations of the word "script" specifically, and has a blind spot for non-script-tag XSS vectors (event-handler-based execution via `<img onerror>`). Demonstrates that keyword-based filtering, even when more sophisticated than Medium's, does not generalise to the full range of XSS techniques. | Yes |
| 14 | Stored XSS | Low | XSS (Stored) module (Message field) | `<script>alert('Stored XSS')</script>` | Alert triggered on submission AND again on page refresh, without resubmitting. Confirms the payload persisted in the database and re-executes for any user loading the page, unlike reflected XSS which requires the malicious link/request each time. Higher-severity finding due to persistence. | Yes |

## Juice Shop

| # | Vuln Class | Location | Payload | Result | Verified |
|---|---|---|---|---|---|

## Notes

- Security levels tested so far: DVWA Low only. Medium and High still to do.
- Each entry here should later map to a ZAP alert (or lack thereof) in baseline results.
