# MFA Fatigue / Push Bombing

## Definition
An attack where an adversary repeatedly triggers MFA push notifications to a user's device, hoping the user will eventually approve one out of frustration, confusion, or to stop the notifications. Often follows credential theft and precedes account takeover.

## Key Signals
- High volume of MFA prompts in short timeframe (>5 in 10 minutes)
- MFA prompts outside user's normal hours
- MFA prompts from unusual IP/location
- Eventual MFA approval after multiple denials
- Failed sign-ins followed by successful sign-in
- User reports receiving unexpected MFA prompts
- No number matching used (legacy push)
- Authentication from different IP than user's baseline

## Primary Logs
| Log Source | Table Name (Sentinel) | Notes |
|------------|----------------------|-------|
| Entra ID Sign-in Logs | `SigninLogs` | MFA status, result codes, IP, location |
| Entra ID Non-Interactive Sign-ins | `AADNonInteractiveUserSignInLogs` | Background auth attempts |
| Entra ID Audit Logs | `AuditLogs` | MFA method changes, registration events |
| Entra ID Risk Detections | `AADUserRiskEvents` | Risk flags may fire on MFA bombing |
| Microsoft Authenticator Logs | `AADManagedIdentitySignInLogs` | If available; Authenticator telemetry |
| Azure AD MFA Logs | Custom connector or `SigninLogs.MfaDetail` | MFA method, result |

**Fallback:** If dedicated MFA logs unavailable, use `SigninLogs` with `ResultType` codes 50074 (MFA required), 50076 (MFA prompt), 500121 (MFA failed).

## False Positives / Benign Explanations
- **User forgot session:** User repeatedly trying to sign in, triggering MFA
- **App misconfiguration:** Application continuously requesting auth, flooding MFA
- **Shared account:** Multiple users triggering MFA (policy violation but not attack)
- **Token expiration storm:** Many apps refreshing tokens simultaneously
- **User testing:** User testing MFA during enrollment or troubleshooting
- **SSO loop:** Broken SSO causing repeated auth requests

## Triage Steps
1. **Quantify the MFA prompts:** Count MFA-related events for user in last 24 hours
2. **Identify the timeline:** When did prompts start? When did they stop? Was there eventual success?
3. **Check IP addresses:** Are prompts coming from user's normal IP or attacker IP?
4. **Compare to baseline:** Is this volume/pattern normal for this user?
5. **Check final outcome:** Did user eventually approve? If yes, from which IP?
6. **Review post-approval activity:** What did the authenticated session do?
7. **Contact user:** Did they intentionally approve? Were they confused/frustrated?
8. **Check for credential theft:** How did attacker get password? (phishing, breach, spray)
9. **Verify MFA method:** Is number matching enabled? Which MFA method was used?
10. **Look for persistence:** Post-approval, did attacker add MFA method, create app, set rules?

## Recommended KQL Queries (Sentinel)

### 1. Count MFA Prompts per User (Last 24 Hours)
```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType in (50074, 50076, 500121, 50140) // MFA-related codes
| summarize MFAPrompts = count(),
    FailedMFA = countif(ResultType == 500121),
    SuccessAfterMFA = countif(ResultType == 0),
    IPs = make_set(IPAddress),
    Locations = make_set(Location)
    by UserPrincipalName
| where MFAPrompts > 5
| order by MFAPrompts desc
```
**Purpose:** Identify users with abnormally high MFA prompt counts.

### 2. MFA Fatigue Pattern Detection (Denials Then Approval)
```kql
let user = "<UserUPN>";
let timerange = <TimeRange>;
SigninLogs
| where TimeGenerated > ago(timerange)
| where UserPrincipalName == user
| where ResultType in (0, 500121, 50074, 50076) // Success and MFA failures
| project TimeGenerated, ResultType, ResultDescription, IPAddress, Location,
    DeviceDetail, AppDisplayName, MfaDetail
| order by TimeGenerated asc
| serialize
| extend PrevResult = prev(ResultType)
| where ResultType == 0 and PrevResult == 500121 // Success after MFA failure
```
**Purpose:** Detect the critical pattern: MFA failures followed by eventual success.

### 3. MFA Prompts by IP Address for Specific User
```kql
let user = "<UserUPN>";
SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName == user
| where ResultType in (50074, 50076, 500121, 0)
| summarize Attempts = count(),
    Successes = countif(ResultType == 0),
    Failures = countif(ResultType != 0),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by IPAddress, Location
| order by Attempts desc
```
**Purpose:** See which IPs are generating MFA prompts; distinguish attacker from user IP.

### 4. MFA Prompt Timeline (Minute-by-Minute)
```kql
let user = "<UserUPN>";
SigninLogs
| where TimeGenerated > ago(4h)
| where UserPrincipalName == user
| where ResultType in (50074, 50076, 500121, 0)
| summarize Count = count(), Results = make_list(ResultType) by bin(TimeGenerated, 1m)
| order by TimeGenerated asc
```
**Purpose:** Visualize the attack timeline; see prompt frequency and when success occurred.

### 5. Successful Sign-in After MFA Bombing (Post-Approval Activity)
```kql
let user = "<UserUPN>";
let approvalTime = datetime(<ApprovalTime>);
SigninLogs
| where TimeGenerated between (approvalTime .. (approvalTime + 2h))
| where UserPrincipalName == user
| where ResultType == 0
| project TimeGenerated, IPAddress, Location, AppDisplayName, ResourceDisplayName,
    DeviceDetail, ConditionalAccessStatus
| order by TimeGenerated asc
```
**Purpose:** See what the attacker accessed immediately after gaining access.

### 6. Check for MFA Registration Changes
```kql
let user = "<UserUPN>";
AuditLogs
| where TimeGenerated > ago(7d)
| where TargetResources has user
| where OperationName has_any ("MFA", "authentication method", "StrongAuthentication")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result
| order by TimeGenerated desc
```
**Purpose:** Detect if attacker registered their own MFA method post-compromise.

### 7. Cross-User MFA Bombing Detection (Campaign)
```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 500121 // MFA failures
| summarize FailedMFA = count(), Users = make_set(UserPrincipalName),
    UserCount = dcount(UserPrincipalName) by IPAddress
| where FailedMFA > 10 and UserCount > 1
| order by FailedMFA desc
```
**Purpose:** Detect coordinated MFA fatigue campaign targeting multiple users from same IP.

### 8. Number Matching Status Check
```kql
let user = "<UserUPN>";
SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName == user
| where isnotempty(MfaDetail)
| extend MfaMethod = tostring(MfaDetail.authMethod),
    MfaResult = tostring(MfaDetail.authDetail)
| project TimeGenerated, MfaMethod, MfaResult, IPAddress, ResultType
```
**Purpose:** Verify what MFA method was used; number matching provides more protection.

## MITRE Mapping
| Tactic | Technique ID | Technique Name | Rationale |
|--------|-------------|----------------|-----------|
| Credential Access | T1621 | Multi-Factor Authentication Request Generation | Direct technique for MFA bombing |
| Credential Access | T1110 | Brute Force | Attacker has password; trying to bypass MFA |
| Initial Access | T1078 | Valid Accounts | Credentials already compromised pre-attack |
| Persistence | T1098 | Account Manipulation | If attacker registers own MFA method post-access |
| Persistence | T1098.005 | Account Manipulation: Device Registration | Attacker may register rogue device |

## Containment Actions (with guardrails)

| Action | When to Use | Risk/Impact | Rollback | Owner |
|--------|-------------|-------------|----------|-------|
| Revoke all refresh tokens | Confirmed MFA fatigue success; attacker authenticated | User must re-auth everywhere; disrupts work | Auto-regenerate on next sign-in | SOC / IAM |
| Reset user password | Attacker knew password; credentials compromised | User locked out until reset | IAM provides temp password | IAM |
| Block attacker IP | Identified attacker IP distinct from user's | May affect shared IPs; verify before blocking | Remove from block list | SOC / IAM |
| Remove suspicious MFA method | Attacker registered own MFA device | User loses that method; may need re-enrollment | Re-add method if legitimate | IAM |
| Require re-registration of all MFA | Full account compromise suspected | User must re-enroll all MFA; inconvenient | Cannot easily rollback; document original methods | IAM |
| Enable number matching | Org-wide protection improvement | Minor UX change; users must match number | Policy can be reverted | IAM |
| Disable legacy MFA prompts | Prevent simple push bombing | Users must use Authenticator app | Policy can be reverted | IAM |

## Follow-Up Investigation
- Determine how credentials were stolen (phishing campaign, credential dump, password spray)
- Review all activity during the authenticated session post-approval
- Check for inbox rules, OAuth apps, or other persistence mechanisms created
- Search for same attacker IP targeting other users
- Verify user's other accounts (personal email, linked accounts)
- Check if user credentials appear in recent breach dumps
- Review user's security training history; consider targeted training

## Escalation Criteria
- **Escalate to Tier 2/Incident Response if:**
  - User confirmed they approved under duress/confusion
  - Attacker successfully authenticated and accessed resources
  - Attacker established persistence (new MFA method, OAuth app, inbox rule)
  - Multiple users targeted by same campaign
  - VIP/executive account involved
  - Evidence of data exfiltration or lateral movement post-compromise
  - Attacker IP linked to known threat actor

## Notes for Automation (RAG / SOAR)

### Entity Extraction (from alert)
- `UserPrincipalName` / `UserID`
- `IPAddress` (attacker IP triggering prompts)
- `IPAddress` (user's legitimate IP for comparison)
- `TimeGenerated` (first prompt, last prompt, approval time)
- `MfaDetail` (method used)
- `ResultType` (pattern of failures and success)
- `AppDisplayName` (target application)
- `Location` (geo of attacker vs. user)

### Suggested Retrieval Keywords
`MFA fatigue`, `push bombing`, `MFA bombing`, `MFA spam`, `authentication fatigue`, `push notification abuse`, `MFA bypass`, `repeated MFA`, `MFA approval`, `T1621`

### Suggested Output Fields (JSON)
```json
{
  "alert_type": "mfa_fatigue",
  "severity": "high|medium|low",
  "confidence": "high|medium|low",
  "user_upn": "<extracted>",
  "attacker_ip": "<extracted>",
  "user_ip": "<extracted>",
  "mfa_prompt_count": "<count>",
  "mfa_denial_count": "<count>",
  "eventual_approval": true|false,
  "approval_timestamp": "<time>",
  "time_window_minutes": "<calculated>",
  "post_approval_activity": ["<apps accessed>"],
  "persistence_detected": true|false,
  "persistence_type": ["new_mfa_method", "oauth_app", "inbox_rule"],
  "recommended_actions": ["revoke_tokens", "reset_password", "remove_mfa_method"],
  "escalate": true|false,
  "escalation_reason": "<reason if applicable>"
}
```
