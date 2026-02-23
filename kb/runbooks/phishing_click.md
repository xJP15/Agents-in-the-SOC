# Phishing – User Clicked Malicious Link

## Definition
A user has clicked on a link in a phishing email that leads to a malicious destination (credential harvesting page, malware download, OAuth consent phish, etc.). The click may or may not have resulted in credential compromise or malware execution, requiring immediate investigation.

## Key Signals
- Safe Links click event with threat verdict (malicious, phishing)
- URL reputation: known phishing domain, newly registered domain, typosquat
- User submitted credentials on the page (credential harvesting)
- Post-click suspicious sign-in from new location
- Post-click OAuth consent
- Post-click file download
- Multiple users clicked same link (campaign)
- Email originated from spoofed sender or lookalike domain
- URL redirect chain terminating at malicious page

## Primary Logs
| Log Source | Table Name (Sentinel) | Notes |
|------------|----------------------|-------|
| Defender for Office 365 | `UrlClickEvents` | Safe Links click telemetry |
| Defender for Office 365 | `EmailEvents` | Email metadata |
| Defender for Office 365 | `EmailUrlInfo` | URLs in emails |
| Defender for Office 365 | `EmailPostDeliveryEvents` | ZAP and post-delivery actions |
| Entra ID Sign-in Logs | `SigninLogs` | Post-click authentication |
| Defender for Endpoint | `DeviceNetworkEvents` | Network connections from device |
| Defender for Endpoint | `DeviceFileEvents` | File downloads post-click |
| Cloud App Events | `CloudAppEvents` | OAuth consent events |

**Fallback:** If `UrlClickEvents` unavailable, use `EmailUrlInfo` to identify URLs in emails and correlate with `DeviceNetworkEvents` or proxy logs for click evidence.

## False Positives / Benign Explanations
- **URL reputation lag:** Legitimate URL on newly registered domain
- **Security testing:** Internal phishing simulation campaign
- **Redirect services:** Legitimate short URL or redirect (still investigate chain)
- **Marketing email:** Aggressive marketing mistakenly flagged as phishing
- **Personal email on device:** User clicked link in personal webmail (still risk)
- **Safe Links training:** User testing Safe Links behavior

## Triage Steps
1. **Confirm the click:** Verify click event, timestamp, user, device
2. **Analyze the URL:** Domain age, reputation, redirect chain, final destination
3. **Determine URL purpose:** Credential harvesting, malware download, OAuth consent, generic phishing
4. **Check if credentials submitted:** Did user enter username/password on the page?
5. **Review post-click sign-ins:** New sign-in from unusual IP after the click?
6. **Check for OAuth consent:** Did user consent to a malicious app post-click?
7. **Check device for malware:** Any suspicious downloads or process execution?
8. **Find the source email:** What email contained this link? Who sent it?
9. **Scope the campaign:** How many users received this email? How many clicked?
10. **Assess credential exposure:** If creds submitted, what accounts are at risk?

## Recommended KQL Queries (Sentinel)

### 1. Get Click Event Details
```kql
UrlClickEvents
| where TimeGenerated > ago(<TimeRange>)
| where AccountUpn == "<UserUPN>"
| project TimeGenerated, AccountUpn, Url, UrlChain, ActionType,
    ThreatTypes, IsClickedThrough, NetworkMessageId, IPAddress
| order by TimeGenerated desc
```
**Purpose:** Get details of the specific click event including URL chain and verdict.

### 2. Find Source Email for Clicked URL
```kql
let messageId = "<NetworkMessageId>";
EmailEvents
| where NetworkMessageId == messageId
| project TimeGenerated, SenderFromAddress, SenderMailFromAddress, RecipientEmailAddress,
    Subject, DeliveryAction, DeliveryLocation, ThreatTypes, AuthenticationDetails
```
**Purpose:** Identify the phishing email that contained the malicious link.

### 3. Campaign Scope: All Recipients of Phishing Email
```kql
let senderDomain = "<SenderDomain>";
let subjectPattern = "<SubjectKeyword>";
EmailEvents
| where TimeGenerated > ago(7d)
| where SenderFromAddress has senderDomain or Subject has subjectPattern
| summarize Recipients = make_set(RecipientEmailAddress),
    RecipientCount = dcount(RecipientEmailAddress),
    MessageIds = make_set(NetworkMessageId)
    by SenderFromAddress, Subject
```
**Purpose:** Find all users who received emails from this phishing campaign.

### 4. All Users Who Clicked Same Malicious URL
```kql
let maliciousUrl = "<MaliciousURL>";
UrlClickEvents
| where TimeGenerated > ago(7d)
| where Url has maliciousUrl or UrlChain has maliciousUrl
| summarize ClickCount = count(),
    Users = make_set(AccountUpn),
    Devices = make_set(DeviceName),
    FirstClick = min(TimeGenerated),
    LastClick = max(TimeGenerated)
    by Url
```
**Purpose:** Identify all users who clicked the same malicious link (campaign impact).

### 5. Post-Click Sign-in Activity
```kql
let user = "<UserUPN>";
let clickTime = datetime(<ClickTime>);
SigninLogs
| where TimeGenerated between (clickTime .. (clickTime + 4h))
| where UserPrincipalName == user
| project TimeGenerated, IPAddress, Location, AppDisplayName, DeviceDetail,
    ResultType, RiskLevelDuringSignIn, ConditionalAccessStatus
| order by TimeGenerated asc
```
**Purpose:** Detect suspicious sign-ins immediately after user clicked phishing link.

### 6. Post-Click OAuth Consent
```kql
let user = "<UserUPN>";
let clickTime = datetime(<ClickTime>);
AuditLogs
| where TimeGenerated between (clickTime .. (clickTime + 2h))
| where OperationName has "Consent"
| where TargetResources has user or InitiatedBy has user
| project TimeGenerated, OperationName, InitiatedBy, TargetResources
```
**Purpose:** Detect if user consented to a malicious OAuth app after clicking.

### 7. Post-Click File Downloads on Device
```kql
let deviceName = "<DeviceName>";
let clickTime = datetime(<ClickTime>);
DeviceFileEvents
| where TimeGenerated between (clickTime .. (clickTime + 1h))
| where DeviceName == deviceName
| where ActionType == "FileCreated"
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".ps1"
    or FileName endswith ".js" or FileName endswith ".vbs" or FileName endswith ".zip"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName
```
**Purpose:** Detect malware downloads on the device following the click.

### 8. URL Reputation and Domain Analysis
```kql
let url = "<MaliciousURL>";
let domain = "<ExtractedDomain>";
// Check if URL appears in threat intelligence
ThreatIntelligenceIndicator
| where Url == url or DomainName == domain
| project TimeGenerated, ThreatType, ConfidenceScore, Description, SourceSystem
```
**Purpose:** Check threat intelligence for URL/domain reputation.

## MITRE Mapping
| Tactic | Technique ID | Technique Name | Rationale |
|--------|-------------|----------------|-----------|
| Initial Access | T1566.002 | Phishing: Spearphishing Link | User clicked malicious link in email |
| Credential Access | T1056.003 | Input Capture: Web Portal Capture | Credentials harvested on fake login page |
| Initial Access | T1566.003 | Phishing: Spearphishing via Service | If link from trusted service (SharePoint, OneDrive) |
| Execution | T1204.001 | User Execution: Malicious Link | User clicked, enabling attack |
| Credential Access | T1528 | Steal Application Access Token | If OAuth consent phish |
| Execution | T1204.002 | User Execution: Malicious File | If drive-by download resulted |

## Containment Actions (with guardrails)

| Action | When to Use | Risk/Impact | Rollback | Owner |
|--------|-------------|-------------|----------|-------|
| Block URL tenant-wide | Confirmed malicious URL; prevent further clicks | May block legitimate redirect service | Remove from Tenant Allow/Block List | Email Admin |
| Quarantine email from all mailboxes | Phishing campaign ongoing; remove email | Users lose access to email | Release from quarantine | Email Admin |
| Reset user password | Credentials likely submitted on phishing page | User locked out until reset | Temp password from IAM | IAM |
| Revoke user sessions | Credentials compromised; active attacker session | User must re-authenticate | Auto-regenerate on sign-in | SOC / IAM |
| Isolate device | Malware downloaded; device compromised | User cannot work until released | Release from isolation | SOC / Endpoint Team |
| Block sender domain | Campaign from malicious domain | May block legitimate if domain spoofed | Remove from block list | Email Admin |
| Enable Safe Links block | Prevent clicked-through access to malicious URL | User cannot access URL even if needed | Modify Safe Links policy | Email Admin |

## Follow-Up Investigation
- Determine if credentials were actually submitted (page analysis, sign-in correlation)
- If creds submitted, check all accounts using those credentials (password reuse)
- Analyze device for malware indicators (processes, network connections, persistence)
- Review user's sent items (attacker may have sent emails from their account)
- Check for inbox rules created post-compromise
- Search for OAuth consents post-click
- Determine campaign scope and notify all affected users
- Report phishing infrastructure to security vendors and registrars
- Consider user security awareness training referral

## Escalation Criteria
- **Escalate to Tier 2/Incident Response if:**
  - Credentials confirmed submitted and unauthorized access detected
  - Malware executed on device
  - OAuth consent to malicious app granted
  - Executive/VIP user clicked
  - Multiple users clicked and submitted credentials
  - Attacker has active session (post-click sign-in from new IP)
  - Evidence of lateral movement or data access post-compromise
  - Campaign targeting sensitive business function (Finance, HR, IT)
  - Phishing page mimics internal application or trusted partner

## Notes for Automation (RAG / SOAR)

### Entity Extraction (from alert)
- `AccountUpn` / `UserPrincipalName` (who clicked)
- `Url` (clicked URL)
- `UrlChain` (redirect chain)
- `Domain` (extracted from URL)
- `NetworkMessageId` (link to source email)
- `SenderFromAddress` (phishing email sender)
- `Subject` (email subject for campaign correlation)
- `ThreatTypes` (verdict from Safe Links)
- `ActionType` (was click blocked or allowed through)
- `DeviceName` / `DeviceId` (device that clicked)
- `TimeGenerated` (click timestamp)
- `IPAddress` (user's IP at time of click)

### Suggested Retrieval Keywords
`phishing click`, `malicious link`, `safe links`, `URL click`, `credential harvesting`, `phishing page`, `credential phish`, `drive-by download`, `phishing campaign`, `T1566.002`, `spearphishing link`

### Suggested Output Fields (JSON)
```json
{
  "alert_type": "phishing_click",
  "severity": "critical|high|medium|low",
  "confidence": "high|medium|low",
  "user_upn": "<extracted>",
  "clicked_url": "<extracted>",
  "url_chain": ["<url1>", "<url2>"],
  "final_domain": "<extracted>",
  "domain_age_days": "<calculated>",
  "threat_verdict": "phishing|malware|clean",
  "was_blocked": true|false,
  "click_timestamp": "<time>",
  "device_name": "<extracted>",
  "source_email_sender": "<extracted>",
  "source_email_subject": "<extracted>",
  "campaign_scope": {
    "recipients_count": "<count>",
    "clickers_count": "<count>"
  },
  "post_click_indicators": {
    "suspicious_signin": true|false,
    "oauth_consent": true|false,
    "file_download": true|false,
    "credential_submission_likely": true|false
  },
  "recommended_actions": ["reset_password", "revoke_sessions", "quarantine_email", "isolate_device"],
  "escalate": true|false,
  "escalation_reason": "<reason if applicable>"
}
```
