# Windows Security Monitoring and Threat Detection Using Microsoft Sentinel

A hands-on SOC portfolio lab using Microsoft Sentinel, Azure Arc, Azure Monitor Agent (AMA), Log Analytics, Kusto Query Language (KQL), and a scheduled analytics rule.

> **Validation note:** The repeated failed-logon analytics rule was enabled, but it did **not** trigger during the recorded test window. The highest observed count was 3 failed logons in a 15-minute bin, below the configured threshold of 5. Do not describe this as a confirmed alert or incident.

## Project goals

- Collect Windows Security events from a Windows endpoint.
- Investigate successful and failed logons using KQL.
- Explore interactive and service logon patterns.
- Configure a scheduled rule for repeated failed logons.
- Visualize successful versus failed logon event counts in a Sentinel workbook.
- Document results and limitations clearly.

## Lab environment

| Component | Value |
|---|---|
| Resource group | `rg-sentinal-lab` |
| Log Analytics workspace | `soc-sentinel-law-2026` |
| Workspace / Arc location | Korea Central |
| Windows endpoint | `DESKTOP-JJ3JKHS` |
| Event collection | Azure Arc + Azure Monitor Agent + Data Collection Rule |
| Data Collection Rule | `DCR-WindowsSecurity-Sentinel` |
| Sentinel content | Windows Security Events via AMA |
| Workbook | `Windows Security Logon Monitoring Dashboard` |
| Analytics rule | `SOC - Repeated Failed Logons` |

## Architecture

1. A Windows endpoint is onboarded to Azure Arc.
2. Azure Monitor Agent collects Windows Security events according to `DCR-WindowsSecurity-Sentinel`.
3. Events are sent to the `soc-sentinel-law-2026` Log Analytics workspace.
4. Microsoft Sentinel queries the `SecurityEvent` table using KQL.
5. A scheduled analytics rule checks for at least 5 failed logons for the same account and computer within a 15-minute bin.
6. A workbook visualizes successful versus failed logon event counts.

## Implementation and investigation

### 1. Data ingestion validation

```kusto
SecurityEvent
| take 10
```

This was used to verify that Windows Security events were available in the workspace.

### 2. Event volume by computer

```kusto
SecurityEvent
| summarize EventCount=count() by Computer
| order by EventCount desc
```

### 3. Failed logons by account and computer

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| summarize FailedAttempts = count() by Account, Computer
| order by FailedAttempts desc
```

Event ID **4625** represents a failed logon. Review account and computer context before deciding whether activity is suspicious.

### 4. Failed logons in 15-minute bins

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| summarize FailedAttempts = count()
    by bin(TimeGenerated, 15m), Account
| order by TimeGenerated asc
```

### 5. Threshold validation query

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| summarize FailedAttempts = count()
    by bin(TimeGenerated, 15m), Account, Computer
| where FailedAttempts >= 5
| order by FailedAttempts desc
```

**Observed outcome:** No rows were returned for the recorded validation window. The maximum observed count in a 15-minute bin was 3, so the threshold of 5 was not met. This is a valid negative test result, not evidence that an alert fired.

### 6. Successful versus failed logon event counts

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID in (4624, 4625)
| summarize EventCount = count() by EventID
| extend EventType = case(
    EventID == 4624, "Successful logons",
    EventID == 4625, "Failed logons",
    "Other"
)
| project EventType, EventCount
| order by EventCount desc
```

Event ID **4624** represents a successful logon. Counts are event counts, not unique users or unique sessions.

### 7. Successful logons by logon type

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624
| summarize LogonCount = count() by LogonType, Account
| order by LogonCount desc
```

Common examples include logon type 2 (interactive) and logon type 5 (service). Interpret logon types with the endpoint's normal operating context.

### 8. Service logon summary

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624
| where LogonType == 5
| summarize
    LogonCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Account, Computer
| order by LogonCount desc
```

### 9. Service logon details

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624
| where LogonType == 5
| project TimeGenerated, Computer, Account, TargetUserName, ProcessName
| order by TimeGenerated desc
| take 10
```

### 10. Failed logon event details

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| project
    TimeGenerated,
    Computer,
    Account,
    TargetUserName,
    LogonType,
    Activity,
    IpAddress,
    ProcessName,
    Status,
    SubStatus
| order by TimeGenerated desc
| take 20
```

Some fields can be empty depending on the event and connector schema. Validate field availability in the returned results before relying on them.

## Analytics rule

- **Rule name:** `SOC - Repeated Failed Logons`
- **Status:** Enabled
- **Evaluation frequency:** Every 5 minutes
- **Lookback period:** 15 minutes
- **Detection condition:** 5 or more Event ID 4625 events for the same account and computer within a 15-minute bin
- **Incident creation:** Enabled
- **Recorded validation:** Threshold not reached; no alert/incident was confirmed during the observed test.

The rule's enabled state confirms configuration, not successful alert generation. For a future controlled test, use an approved test account and avoid repeated failed attempts that could lock out an account.

## Workbook

**Workbook name:** `Windows Security Logon Monitoring Dashboard`

The saved workbook includes a visualization based on successful versus failed logon event counts. The chart reflects the query's selected time range; it should not be interpreted as a count of unique users or confirmed malicious activity.

## Findings

- Windows Security events were successfully ingested into the `SecurityEvent` table.
- KQL investigations returned successful logon, failed logon, and service logon records.
- The analytics rule was enabled and configured for repeated failed logons.
- The recorded 15-minute failed-logon count did not reach the threshold; maximum observed was 3.
- The workbook visualization was saved and reopened successfully.

## Limitations and next steps

- This is a single-endpoint learning lab, not a production SOC deployment.
- No malicious activity or successful alert was confirmed by the recorded validation.
- The threshold rule should be tested in an approved, controlled environment if end-to-end alert validation is required.
- Future improvements could include enrichment with source IP and logon failure status, additional detections, and documented incident triage steps.

## Resume-ready project entry

**Windows Security Monitoring and Threat Detection Using Microsoft Sentinel**
- Configured Azure Arc, Azure Monitor Agent, and a Data Collection Rule to ingest Windows Security events into Log Analytics for Microsoft Sentinel investigations.
- Wrote KQL queries to investigate Event IDs 4624 and 4625, summarize failed logons, and analyze interactive and service logon patterns.
- Enabled a scheduled analytics rule for 5+ failed logons within 15 minutes and built a workbook visualization comparing successful and failed logon event counts.
- Validated the threshold logic against observed data; the threshold was not reached during the recorded test window.

## Repository setup

1. Create a new GitHub repository named `microsoft-sentinel-windows-security-monitoring`.
2. Add this file as `README.md`.
3. Add your PDF report if you want the report public.
4. Add only screenshots that do not expose personal information, tenant IDs, subscription IDs, email addresses, tokens, or other secrets.
5. Do not upload credentials, exported logs containing personal data, or Azure configuration secrets.
6. Keep the validation outcome accurate: the rule was enabled, but no alert was confirmed.
