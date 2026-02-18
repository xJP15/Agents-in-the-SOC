# Suspicious Inbox Rule / Mail Forwarding

## Definition
An attacker creates or modifies inbox rules to automatically forward, delete, or hide emails. Commonly used to intercept sensitive communications, hide security alerts, or maintain persistence after account compromise. A key indicator of Business Email Compromise (BEC).

## Key Signals
- New inbox rule created, especially with external forwarding
- Rule moves emails to RSS Feeds, Deleted Items, or obscure folders
- Rule deletes emails matching specific keywords (invoice, payment, password)
- Rule marks emails as read automatically
- Rule created shortly after suspicious sign-in
- Forwarding to external/personal email address
- Rule targets emails from IT, Security, HR, or Finance
- Rule created via unusual client (PowerShell, API, unknown app)
- Multiple rules created in short timeframe

## Primary Logs
| Log Source | Table Name (Sentinel) | Notes |
|------------|----------------------|-------|
| Office 365 Unified Audit Log | `OfficeActivity` | Mailbox rule operations |
| Exchange Online Audit | `ExchangeAdmin` | Admin-level mailbox changes |
| Entra ID Sign-in Logs | `SigninLogs` | Correlate rule creation with sign-in |
| Entra ID Audit Logs | `AuditLogs` | If changes made via Graph API |
| Microsoft 365 Defender | `EmailEvents`, `EmailPostDeliveryEvents` | Email activity context |
| Cloud App Events | `CloudAppEvents` | MCAS detections |

**Fallback:** If `OfficeActivity` is not available, use Exchange Admin PowerShell to query `Get-InboxRule` and `Get-TransportRule` directly.

## False Positives / Benign Explanations
- **User organizing inbox:** Creating legitimate filters for newsletters, notifications
- **Out-of-office setup:** Rules created for vacation responses
- **Delegation setup:** Executive assistants managing shared mailboxes
- **Migration:** IT migration project creating temporary forwarding
- **Personal preference:** User forwarding to personal email (policy violation, not attack)
- **Application integration:** Sanctioned apps creating rules for automation

## Triage Steps
1. **Identify the rule:** Rule name, actions, conditions, target folders/addresses
2. **Check creation context:** When was it created? From what IP/device/client?
3. **Correlate with sign-ins:** Was there a suspicious sign-in before rule creation?
4. **Review rule logic:** Does it hide emails? Forward externally? Target sensitive keywords?
5. **Check forwarding address:** Is it external? Known attacker infrastructure?
6. **Contact user:** Did they create this rule? Do they recognize it?
7. **Look for other persistence:** Are there other rules? OAuth apps? MFA changes?
8. **Check email flow:** Have emails already been forwarded/deleted by this rule?
9. **Assess impact:** What emails would this rule affect? Any sensitive data exposed?
10. **Review other mailboxes:** Is this part of larger BEC campaign?

## Recommended KQL Queries (Sentinel)

### 1. All Inbox Rule Operations (Creation, Modification, Deletion)
```kql
OfficeActivity
| where TimeGenerated > ago(<TimeRange>)
| where Operation in ("New-InboxRule", "Set-InboxRule", "Enable-InboxRule", "Remove-InboxRule")
| extend RuleName = tostring(parse_json(Parameters)[0].Value)
| project TimeGenerated, UserId, Operation, RuleName, ClientIP, ClientInfoString, Parameters
| order by TimeGenerated desc
```
**Purpose:** List all inbox rule changes to identify suspicious activity.

### 2. Rules with External Forwarding
```kql
OfficeActivity
| where TimeGenerated > ago(30d)
| where Operation in ("New-InboxRule", "Set-InboxRule")
| extend Params = parse_json(Parameters)
| mv-expand Params
| where Params.Name in ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo")
| extend ForwardingAddress = tostring(Params.Value)
| where ForwardingAddress !endswith "yourdomain.com" // Adjust for your domain
| project TimeGenerated, UserId, Operation, ForwardingAddress, ClientIP, ClientInfoString
```
**Purpose:** Find rules forwarding email to external addresses.

### 3. Rules Targeting Deletion or Hiding
```kql
OfficeActivity
| where TimeGenerated > ago(30d)
| where Operation in ("New-InboxRule", "Set-InboxRule")
| extend Params = parse_json(Parameters)
| mv-expand Params
| where Params.Name in ("MoveToFolder", "DeleteMessage", "MarkAsRead")
| extend Action = tostring(Params.Name), ActionValue = tostring(Params.Value)
| where ActionValue has_any ("Deleted Items", "RSS Feeds", "Junk", "Archive") or Action == "DeleteMessage"
| project TimeGenerated, UserId, Operation, Action, ActionValue, ClientIP
```
**Purpose:** Find rules designed to hide or delete emails.

### 4. Rules with Suspicious Keyword Filters
```kql
OfficeActivity
| where TimeGenerated > ago(30d)
| where Operation in ("New-InboxRule", "Set-InboxRule")
| extend Params = tostring(Parameters)
| where Params has_any ("invoice", "payment", "wire", "bank", "password", "credential",
    "security", "urgent", "reset", "verify", "confirm", "MFA", "2FA")
| project TimeGenerated, UserId, Operation, ClientIP, Params
```
**Purpose:** Find rules targeting sensitive business or security keywords.

### 5. Correlate Rule Creation with Sign-in Events
```kql
let ruleCreation =
    OfficeActivity
    | where TimeGenerated > ago(7d)
    | where Operation == "New-InboxRule"
    | project RuleTime = TimeGenerated, UserId, RuleClientIP = ClientIP, Operation;
let signins =
    SigninLogs
    | where TimeGenerated > ago(7d)
    | where ResultType == 0
    | project SignInTime = TimeGenerated, UserPrincipalName, SignInIP = IPAddress, Location;
ruleCreation
| join kind=inner (signins) on $left.UserId == $right.UserPrincipalName
| where SignInTime between ((RuleTime - 1h) .. RuleTime)
| where RuleClientIP != SignInIP
| project RuleTime, UserId, RuleClientIP, SignInIP, Location
```
**Purpose:** Find rules created from different IP than the sign-in (compromised session).

### 6. Specific User's Inbox Rules
```kql
let user = "<UserUPN>";
OfficeActivity
| where TimeGenerated > ago(90d)
| where UserId == user
| where Operation has "InboxRule"
| project TimeGenerated, Operation, ClientIP, ClientInfoString, Parameters
| order by TimeGenerated desc
```
**Purpose:** Review all inbox rule activity for a specific compromised user.

### 7. Transport Rules (Admin-Level Forwarding)
```kql
OfficeActivity
| where TimeGenerated > ago(30d)
| where Operation in ("New-TransportRule", "Set-TransportRule")
| extend RuleName = tostring(parse_json(Parameters)[0].Value)
| project TimeGenerated, UserId, Operation, RuleName, Parameters
```
**Purpose:** Detect admin-level mail flow rules that could affect entire org.

### 8. Email Activity After Rule Creation
```kql
let user = "<UserUPN>";
let ruleTime = datetime(<RuleCreationTime>);
OfficeActivity
| where TimeGenerated between (ruleTime .. (ruleTime + 24h))
| where UserId == user
| where Operation has_any ("MailItemsAccessed", "Send", "Move", "SoftDelete")
| summarize Count = count() by Operation, bin(TimeGenerated, 1h)
```
**Purpose:** See what email activity occurred after rule was created.

## MITRE Mapping
| Tactic | Technique ID | Technique Name | Rationale |
|--------|-------------|----------------|-----------|
| Persistence | T1137.005 | Office Application Startup: Outlook Rules | Inbox rules persist attacker access |
| Collection | T1114.003 | Email Collection: Email Forwarding Rule | Forwarding rules collect emails |
| Defense Evasion | T1564.008 | Hide Artifacts: Email Hiding Rules | Rules hide security notifications |
| Exfiltration | T1567 | Exfiltration Over Web Service | Forwarded to external email |
| Impact | T1565.003 | Data Manipulation: Runtime Data Manipulation | Deleting/modifying emails |

## Containment Actions (with guardrails)

| Action | When to Use | Risk/Impact | Rollback | Owner |
|--------|-------------|-------------|----------|-------|
| Delete malicious inbox rule | Confirmed malicious rule identified | None; rule removed | Re-create rule if it was legitimate | SOC / Email Admin |
| Disable all inbox rules | Multiple suspicious rules; unclear scope | User's legitimate rules also disabled | Re-enable specific rules after review | Email Admin |
| Block external forwarding (OWA policy) | Prevent future external forwarding | Users cannot forward to personal email | Modify OWA mailbox policy | Email Admin |
| Revoke user sessions | Account compromised; attacker has access | User must re-authenticate | Sessions auto-regenerate | SOC / IAM |
| Reset user password | Credentials compromised | User locked out until reset | Temp password from IAM | IAM |
| Enable mailbox auditing (enhanced) | Need better visibility | Minor performance impact | Revert audit settings | Email Admin |
| Quarantine affected emails | Sensitive emails may be exfiltrated | Users lose access to quarantined mail | Release from quarantine | Email Admin |

## Follow-Up Investigation
- Identify how the account was compromised (phishing, credential theft)
- Review all emails forwarded by the rule (what data was exposed?)
- Check for other persistence (OAuth apps, MFA changes, other rules)
- Search for similar rules in other mailboxes (campaign detection)
- Review sent items (did attacker send emails as user - BEC?)
- Check for payment fraud indicators (modified invoices, wire requests)
- Interview user about any suspicious emails or credential entry
- Notify any third parties if sensitive data was exposed

## Escalation Criteria
- **Escalate to Tier 2/Incident Response if:**
  - Rule forwarded to external address and emails already sent
  - Rule targeted financial keywords (payment, invoice, wire)
  - Evidence of BEC (attacker sent emails as compromised user)
  - Executive/VIP mailbox affected
  - Multiple users have similar malicious rules (campaign)
  - Sensitive data confirmed forwarded externally
  - Rule was created by admin account (insider threat?)
  - Cannot determine full scope of email exposure

## Notes for Automation (RAG / SOAR)

### Entity Extraction (from alert)
- `UserId` / `UserPrincipalName` (mailbox owner)
- `RuleName` / `RuleId`
- `Operation` (New-InboxRule, Set-InboxRule, etc.)
- `ForwardingAddress` (external email if forwarding)
- `MoveToFolder` (target folder for hiding)
- `Conditions` (keywords, senders, subjects filtered)
- `Actions` (forward, delete, mark read)
- `ClientIP` (where rule was created from)
- `ClientInfoString` (client used - Outlook, OWA, PowerShell)
- `TimeGenerated` (rule creation time)

### Suggested Retrieval Keywords
`inbox rule`, `mail forwarding`, `email forwarding`, `mailbox rule`, `BEC`, `business email compromise`, `email hiding`, `mail deletion rule`, `T1137.005`, `email collection`, `forward to external`

### Suggested Output Fields (JSON)
```json
{
  "alert_type": "mailbox_rule_abuse",
  "severity": "high|medium|low",
  "confidence": "high|medium|low",
  "user_upn": "<extracted>",
  "rule_name": "<extracted>",
  "rule_operation": "create|modify|enable",
  "forwarding_address": "<external email or null>",
  "is_external_forward": true|false,
  "move_to_folder": "<folder name or null>",
  "deletes_email": true|false,
  "marks_as_read": true|false,
  "keyword_filters": ["<keyword1>", "<keyword2>"],
  "creation_ip": "<extracted>",
  "creation_client": "<extracted>",
  "creation_timestamp": "<time>",
  "emails_affected_estimate": "<count>",
  "recommended_actions": ["delete_rule", "revoke_sessions", "reset_password"],
  "escalate": true|false,
  "escalation_reason": "<reason if applicable>"
}
```
