# KQL Reference: Password Spray

## Parameters
- `{{source_ip}}` - Attacking IP address
- `{{time_range}}` - Lookback period (e.g., 24h, 7d)

---

## Detection Validation

### 1. Confirm Spray Pattern from Source IP
Use when: Validating alert for known suspicious IP.
```kql
SigninLogs
| where TimeGenerated > ago({{time_range}})
| where IPAddress == "{{source_ip}}"
| where ResultType != 0
| summarize FailedAttempts = count(), TargetedUsers = dcount(UserPrincipalName) by IPAddress
```

---

## Investigation Queries

### 2. Targeted Users with Context
Use when: Identifying impacted accounts with risk signals.
```kql
SigninLogs
| where TimeGenerated > ago({{time_range}})
| where IPAddress == "{{source_ip}}"
| where ResultType != 0
| summarize Attempts = count() by UserPrincipalName, ResultDescription
| order by Attempts desc
```

### 3. Successful Logins from Spray IP
Use when: Checking if attacker achieved access.
```kql
SigninLogs
| where TimeGenerated > ago({{time_range}})
| where IPAddress == "{{source_ip}}"
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, AppDisplayName, Location, RiskLevelAggregated, ConditionalAccessStatus
```

### 4. Timeline with MFA and CA Context
Use when: Understanding attack progression and defensive controls.
```kql
SigninLogs
| where TimeGenerated > ago({{time_range}})
| where IPAddress == "{{source_ip}}"
| summarize Attempts = count(), Failures = countif(ResultType != 0), Successes = countif(ResultType == 0) by bin(TimeGenerated, 5m)
| order by TimeGenerated asc
```
