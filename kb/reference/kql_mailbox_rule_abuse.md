# KQL Reference: Mailbox Rule Abuse

## Parameters
- `{{user}}` - Target user UPN
- `{{time_range}}` - Lookback period (e.g., 7d, 30d)
- `{{domain}}` - Organization domain for external forwarding check

---

## Detection Validation

### 1. Confirm Rule Activity for User
Use when: Validating alert for specific user.
```kql
OfficeActivity
| where TimeGenerated > ago({{time_range}})
| where UserId == "{{user}}"
| where Operation in ("New-InboxRule", "Set-InboxRule", "Enable-InboxRule")
| extend RuleName = tostring(parse_json(Parameters)[0].Value)
| project TimeGenerated, UserId, Operation, RuleName, ClientIP, ClientInfoString
```

---

## Investigation Queries

### 2. External Forwarding Rules
Use when: Detecting data exfiltration via forwarding.
```kql
OfficeActivity
| where TimeGenerated > ago({{time_range}})
| where Operation in ("New-InboxRule", "Set-InboxRule")
| extend Params = parse_json(Parameters)
| mv-expand Params
| where Params.Name in ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo")
| extend ForwardingAddress = tostring(Params.Value)
| where ForwardingAddress !endswith "{{domain}}"
| project TimeGenerated, UserId, ForwardingAddress, ClientIP
```

### 3. Rules That Hide or Delete Email
Use when: Checking for defense evasion tactics.
```kql
OfficeActivity
| where TimeGenerated > ago({{time_range}})
| where Operation in ("New-InboxRule", "Set-InboxRule")
| extend Params = parse_json(Parameters)
| mv-expand Params
| where Params.Name in ("MoveToFolder", "DeleteMessage", "MarkAsRead")
| extend Action = tostring(Params.Name), ActionValue = tostring(Params.Value)
| project TimeGenerated, UserId, Action, ActionValue, ClientIP
```

### 4. Correlate Rule with Sign-in
Use when: Checking if rule created from suspicious session.
```kql
let ruleEvent = OfficeActivity
| where TimeGenerated > ago({{time_range}})
| where UserId == "{{user}}"
| where Operation == "New-InboxRule"
| project RuleTime = TimeGenerated, RuleIP = ClientIP;
SigninLogs
| where TimeGenerated > ago({{time_range}})
| where UserPrincipalName == "{{user}}"
| where ResultType == 0
| join kind=inner (ruleEvent) on $left.TimeGenerated == $right.RuleTime
| project TimeGenerated, IPAddress, Location, RiskLevelAggregated, RuleIP
```
