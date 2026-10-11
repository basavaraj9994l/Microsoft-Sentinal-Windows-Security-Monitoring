# Screenshot Checklist — Microsoft Sentinel SOC Lab
- [ ] **Azure Arc machine:** `DESKTOP-JJ3JKHS` shown as connected.
- [ ] **Data Collection Rule:** `DCR-WindowsSecurity-Sentinel` and its Windows Security event configuration.
- [ ] **Log Analytics ingestion:** a successful `SecurityEvent | take 10` query with results.
- [ ] **Failed-logon investigation:** query results for Event ID 4625, with sensitive account details blurred if needed.
- [ ] **Threshold validation:** query using `FailedAttempts >= 5` showing no matching rows for the recorded test window. Label this as a negative validation result.
- [ ] **Analytics rule configuration:** `SOC - Repeated Failed Logons` shown as enabled, with the 5-minute evaluation and 15-minute lookback settings if visible.
- [ ] **Workbook:** `Windows Security Logon Monitoring Dashboard` showing the saved successful-versus-failed logon chart.
- [ ] **Service logon analysis:** results filtered to Event ID 4624 and LogonType 5, with sensitive fields obscured.

