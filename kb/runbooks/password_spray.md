# Password Spray Attack

## Definition
An attack where an adversary attempts a small number of commonly used passwords against many accounts simultaneously, avoiding account lockouts while systematically testing credentials. Often targets cloud identity providers (Entra ID) and may precede account takeover if successful.

## Key Signals
- High volume of failed sign-ins (error code 50126) across many accounts
- Failures originate from one or few IP addresses
- Same password attempted against multiple users (if password visible in logs)
- Rapid cadence of authentication attempts
- Targeting pattern (alphabetical, department-based, leaked list)
- Failures followed by eventual success on one or more accounts
- Attempts against non-existent accounts mixed with valid accounts
- Off-hours authentication attempts
- Attempts from hosting providers, VPNs, or Tor exit nodes

## Primary Logs
| Log Source | Table Name (Sentinel) | Notes |
|------------|----------------------|-------|
| Entra ID Sign-in Logs | `SigninLogs` | Primary source; interactive sign-ins |
| Entra ID Non-Interactive Sign-ins | `AADNonInteractiveUserSignInLogs` | Service/app-based spray attempts |
| Entra ID Audit Logs | `AuditLogs` | Account lockouts, password changes |
| Entra ID Risk Detections | `AADUserRiskEvents` | Risk flags for spray activity |
| VPN/SSO Logs | Varies by vendor | On-prem or third-party IdP attempts |
| Microsoft Defender for Identity | `IdentityLogonEvents` | If MDI deployed for on-prem AD |
| Azure AD Identity Protection | `AADRiskyUsers` | Users flagged as at risk |

**Fallback:** If `AADNonInteractiveUserSignInLogs` unavailable, focus on `SigninLogs` with `ResultType` 50126 (invalid password) and 50053 (locked account).

## False Positives / Benign Explanations
- **Misconfigured service accounts:** Application repeatedly failing auth with old credentials
- **User password confusion:** User trying multiple passwords after reset
- **Password manager sync issues:** Outdated credentials syncing across devices
- **Legacy app compatibility:** Old app using cached credentials
- **Penetration testing:** Authorized red team activity (verify with security team)
- **Migration activity:** Bulk account testing during directory migration
- **SSO misconfiguration:** Broken SSO causing repeated auth failures

## Triage Steps
1. **Quantify the attack:** Count failed logins, unique users targeted, unique IPs involved
2. **Identify source IPs:** List all IPs generating failures; check reputation/ASN
3. **Check IP characteristics:** Hosting provider? VPN? Tor? Residential?
4. **Review target list:** Any pattern? Executives? Specific department? Alphabetical?
5. **Look for successes:** Did any account authenticate successfully from attacker IP?
6. **Check timing:** When did spray start/stop? Business hours or off-hours?
7. **Correlate with threat intel:** Are IPs associated with known campaigns?
8. **Check account status:** Any accounts locked out? Any password resets triggered?
9. **Verify authorization:** Is this authorized pen testing?
10. **Assess MFA coverage:** Would successful password guess be blocked by MFA?

## Recommended KQL Queries (Sentinel)

### 1. Detect Password Spray Pattern (Many Users, Few IPs, High Failures)
```kql
SigninLogs
| where TimeGenerated > ago(<TimeRange>)
| where ResultType == "50126" // Invalid username or password
| summarize FailureCount = count(),
    TargetedUsers = dcount(UserPrincipalName),
    UserList = make_set(UserPrincipalName, 100),
    Apps = make_set(AppDisplayName)
    by IPAddress
| where FailureCount > 10 and TargetedUsers > 5
| order by FailureCount desc
```
**Purpose:** Identify IPs exhibiting spray behavior (many failures across many users).

### 2. Password Spray Timeline Analysis
```kql
let suspiciousIP = "<IP>";
SigninLogs
| where TimeGenerated > ago(24h)
| where IPAddress == suspiciousIP
| where ResultType in ("50126", "50053", "0") // Failed, locked, success
| summarize Attempts = count(),
    Failures = countif(ResultType == "50126"),
    Lockouts = countif(ResultType == "50053"),
    Successes = countif(ResultType == "0"),
    Users = dcount(UserPrincipalName)
    by bin(TimeGenerated, 5m)
| order by TimeGenerated asc
```
**Purpose:** Visualize attack timeline and identify when/if attacker achieved success.

### 3. Successful Logins from Spray IP (Critical)
```kql
let sprayIPs =
    SigninLogs
    | where TimeGenerated > ago(24h)
    | where ResultType == "50126"
    | summarize FailCount = count() by IPAddress
    | where FailCount > 20
    | project IPAddress;
SigninLogs
| where TimeGenerated > ago(24h)
| where IPAddress in (sprayIPs)
| where ResultType == 0 // Successful sign-in
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName,
    DeviceDetail, Location, ConditionalAccessStatus, MfaDetail
```
**Purpose:** Find accounts that were successfully compromised during the spray.

### 4. Targeted Users Analysis
```kql
let suspiciousIP = "<IP>";
SigninLogs
| where TimeGenerated > ago(24h)
| where IPAddress == suspiciousIP
| where ResultType == "50126"
| summarize AttemptCount = count(),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by UserPrincipalName
| order by AttemptCount desc
```
**Purpose:** See which users were targeted and how many attempts per user.

### 5. Check for Account Lockouts
```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == "50053" // Account locked
| summarize LockoutCount = count(),
    LockoutIPs = make_set(IPAddress)
    by UserPrincipalName
| order by LockoutCount desc
```
**Purpose:** Identify accounts that were locked due to spray activity.

### 6. IP Reputation and ASN Analysis
```kql
let suspiciousIP = "<IP>";
SigninLogs
| where TimeGenerated > ago(7d)
| where IPAddress == suspiciousIP
| summarize TotalAttempts = count(),
    UniqueUsers = dcount(UserPrincipalName),
    SuccessRate = round(100.0 * countif(ResultType == 0) / count(), 2),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Countries = make_set(Location)
    by IPAddress, AutonomousSystemNumber
```
**Purpose:** Profile the attacking IP including ASN for threat context.

### 7. Cross-Reference with Threat Intelligence
```kql
let suspiciousIP = "<IP>";
ThreatIntelligenceIndicator
| where TimeGenerated > ago(90d)
| where NetworkIP == suspiciousIP or NetworkSourceIP == suspiciousIP
| project TimeGenerated, ThreatType, ConfidenceScore, Description,
    SourceSystem, ExpirationDateTime, Active
```
**Purpose:** Check if spray IP is known in threat intelligence feeds.

### 8. Compare to User's Normal Sign-in Pattern
```kql
let user = "<UserUPN>";
SigninLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName == user
| where ResultType == 0
| summarize NormalIPs = make_set(IPAddress),
    NormalLocations = make_set(Location),
    NormalApps = make_set(AppDisplayName),
    NormalDevices = make_set(tostring(DeviceDetail.deviceId))
    by UserPrincipalName
```
**Purpose:** Establish user baseline to determine if spray success IP is anomalous.

## MITRE Mapping
| Tactic | Technique ID | Technique Name | Rationale |
|--------|-------------|----------------|-----------|
| Credential Access | T1110 | Brute Force | Parent technique for password attacks |
| Credential Access | T1110.003 | Brute Force: Password Spraying | Specific technique for spray attacks |
| Initial Access | T1078 | Valid Accounts | Goal is to obtain valid credentials |
| Initial Access | T1078.004 | Valid Accounts: Cloud Accounts | Targeting cloud identity (Entra ID) |
| Reconnaissance | T1589.001 | Gather Victim Identity Information: Credentials | Attacker may use leaked credential lists |

## Containment Actions (with guardrails)

| Action | When to Use | Risk/Impact | Rollback | Owner |
|--------|-------------|-------------|----------|-------|
| Block attacking IP(s) | Confirmed malicious spray source | May affect legitimate users on shared IP | Remove from Conditional Access named location | SOC / IAM |
| Reset compromised passwords | Success detected from spray IP | User locked out until reset | IAM provides temp password | IAM |
| Revoke sessions for compromised users | Attacker may have active session | User must re-authenticate | Sessions auto-regenerate | SOC / IAM |
| Enable smart lockout tuning | Reduce lockout impact while blocking spray | May allow more attempts before lockout | Revert lockout settings | IAM |
| Require MFA for all users | Prevent password-only compromise | Users without MFA enrolled face access issues | Adjust CA policy | IAM |
| Block legacy authentication | Legacy auth bypasses MFA | Legacy apps break; plan migration | Re-enable with CA exceptions | IAM |
| Enable Password Protection | Prevent common passwords org-wide | Some user passwords may not meet new requirements | Adjust banned password list | IAM |

## Follow-Up Investigation
- Identify how attacker obtained target list (public enumeration, breach data, LinkedIn)
- Check if compromised accounts were used for further access
- Review email activity for compromised accounts (BEC indicators)
- Check for OAuth app consents from compromised accounts
- Search for inbox rules created after compromise
- Verify MFA enrollment status for all targeted accounts
- Assess password policy effectiveness (complexity, banned passwords)
- Check for related spray activity against other org services (VPN, OWA)
- Review Azure AD Identity Protection risk detections

## Escalation Criteria
- **Escalate to Tier 2/Incident Response if:**
  - Any account successfully compromised from spray IP
  - Spray targeting VIP/executive accounts
  - Large-scale spray (>100 accounts targeted)
  - Spray from known threat actor infrastructure
  - Evidence of post-compromise activity (email access, data exfiltration)
  - Spray correlates with other attack indicators (phishing campaign, malware)
  - Multiple spray campaigns from different IPs (coordinated attack)
  - Accounts without MFA are successfully compromised

## Notes for Automation (RAG / SOAR)

### Entity Extraction (from alert)
- `IPAddress` (attacking IP or IPs)
- `AutonomousSystemNumber` / `ASN`
- `UserPrincipalName` (list of targeted users)
- `ResultType` (50126 = invalid password, 50053 = locked, 0 = success)
- `TimeGenerated` (attack window start/end)
- `AppDisplayName` (targeted application)
- `Location` (geographic location of attacker)
- `FailureCount` (total failed attempts)
- `TargetedUserCount` (number of unique users)

### Suggested Retrieval Keywords
`password spray`, `brute force`, `credential stuffing`, `password attack`, `failed login`, `authentication failure`, `50126`, `account lockout`, `T1110.003`, `credential attack`, `invalid password`

### Suggested Output Fields (JSON)
```json
{
  "alert_type": "password_spray",
  "severity": "critical|high|medium|low",
  "confidence": "high|medium|low",
  "attacking_ips": ["<ip1>", "<ip2>"],
  "ip_asn": "<asn>",
  "ip_reputation": "malicious|suspicious|clean",
  "targeted_users_count": "<count>",
  "targeted_users_sample": ["<user1>", "<user2>"],
  "failure_count": "<count>",
  "success_count": "<count>",
  "compromised_users": ["<user if any>"],
  "attack_window_start": "<time>",
  "attack_window_end": "<time>",
  "spray_velocity": "<attempts per minute>",
  "lockouts_triggered": "<count>",
  "mfa_blocked_attempts": "<count>",
  "recommended_actions": ["block_ip", "reset_passwords", "revoke_sessions", "enforce_mfa"],
  "escalate": true|false,
  "escalation_reason": "<reason if applicable>"
}
```
