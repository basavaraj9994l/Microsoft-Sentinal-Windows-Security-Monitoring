Microsoft Sentinel SOC Project — Screenshot Checklist

This checklist documents the evidence collected for the Windows Security Monitoring and Threat Detection project.

Environment Setup

- [ ] Azure Arc connected Windows machine
- [ ] Log Analytics workspace
- [ ] Data Collection Rule configuration
- [ ] Azure Monitor Agent or connected machine status

Security Event Collection

- [ ] Windows Security events visible in Microsoft Sentinel
- [ ] KQL query results for Event ID 4624 — Successful Logons
- [ ] KQL query results for Event ID 4625 — Failed Logons

Investigation

- [ ] Failed logons grouped by account and computer
- [ ] Successful logons grouped by logon type
- [ ] Service logon investigation results

Detection and Visualization

- [ ] Repeated Failed Logons analytics rule showing Enabled
- [ ] Windows Security Logon Monitoring Dashboard workbook

Evidence Notes

- Screenshots should show genuine results from the lab.
- Sensitive information should be redacted before publication.
- The repeated failed-logon detection rule was enabled, but the configured threshold was not met during validation.
- No triggered alert or incident is claimed.

Project

Title: Windows Security Monitoring and Threat Detection Using Microsoft Sentinel

Technologies: Microsoft Sentinel, Azure Monitor, Azure Arc, Log Analytics, KQL, Windows Security Events.
