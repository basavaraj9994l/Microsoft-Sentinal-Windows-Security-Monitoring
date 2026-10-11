# Screenshot Checklist — Microsoft Sentinel SOC Lab

Capture screenshots from your own Azure portal; screenshots are not embedded in this package.

## Recommended evidence (in this order)

- [ ] **Azure Arc machine:** `DESKTOP-JJ3JKHS` shown as connected.
- [ ] **Data Collection Rule:** `DCR-WindowsSecurity-Sentinel` and its Windows Security event configuration.
- [ ] **Log Analytics ingestion:** a successful `SecurityEvent | take 10` query with results.
- [ ] **Failed-logon investigation:** query results for Event ID 4625, with sensitive account details blurred if needed.
- [ ] **Threshold validation:** query using `FailedAttempts >= 5` showing no matching rows for the recorded test window. Label this as a negative validation result.
- [ ] **Analytics rule configuration:** `SOC - Repeated Failed Logons` shown as enabled, with the 5-minute evaluation and 15-minute lookback settings if visible.
- [ ] **Workbook:** `Windows Security Logon Monitoring Dashboard` showing the saved successful-versus-failed logon chart.
- [ ] **Service logon analysis:** results filtered to Event ID 4624 and LogonType 5, with sensitive fields obscured.

## Before publishing

- Blur subscription IDs, tenant IDs, email addresses, public IPs if sensitive, usernames, device identifiers you do not want public, and any other private information.
- Never include access keys, passwords, tokens, browser session data, or downloaded raw logs with personal data.
- Use screenshots from your actual environment only. Do not fabricate alerts, incidents, event counts, or screenshots.
- The rule was enabled, but the recorded threshold test did not reach 5 failed logons in a 15-minute bin. Do not caption it as a triggered alert.
