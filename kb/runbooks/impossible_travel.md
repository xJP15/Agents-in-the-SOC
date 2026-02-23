# Impossible Travel / Atypical Sign-in

## Definition
Two or more sign-ins from geographically distant locations within a timeframe that makes physical travel impossible (e.g., New York to Moscow in 30 minutes). May also include atypical sign-in patterns such as new countries, unusual hours, or anomalous authentication behaviors.

## Key Signals
- Geographic distance vs. time delta between sign-ins exceeds feasible travel speed (~500-600 mph max)
- Sign-in from a country never seen for this user
- New device or browser fingerprint
- New ASN / ISP not previously associated with user
- Risky sign-in flags from Entra ID Protection (e.g., `riskState`, `riskLevelDuringSignIn`)
- Token replay indicators (same token used from multiple IPs)
- Sign-in outside normal working hours for user's baseline
- Conditional Access policy bypass attempts

## Primary Logs
| Log Source | Table Name (Sentinel) | Notes |
|------------|----------------------|-------|
| Entra ID Sign-in Logs | `SigninLogs` | Interactive sign-ins; primary source |
| Entra ID Non-Interactive Sign-ins | `AADNonInteractiveUserSignInLogs` | Token refreshes, background auth |
| Entra ID Audit Logs | `AuditLogs` | MFA registration changes, CA policy changes |
| Entra ID Risk Detections | `AADRiskyUsers`, `AADUserRiskEvents` | Risk scores and detections |
| Microsoft Defender for Cloud Apps | `CloudAppEvents` | If MCAS is enabled; session activity |
| Device Logs | `DeviceInfo`, `DeviceLogonEvents` | Defender for Endpoint; device context |

**Fallback:** If `AADNonInteractiveUserSignInLogs` is unavailable, rely on `SigninLogs` and correlate with `OfficeActivity` for session continuity.

## False Positives / Benign Explanations
- **VPN usage:** User connects to corporate VPN in different region; check ASN for known VPN providers
- **Mobile roaming:** Cellular carrier IP may geolocate incorrectly
- **Cloud egress:** User's traffic routes through cloud provider (Azure, AWS, GCP) in different region
- **Shared accounts:** Multiple users accessing same account (violates policy but not compromise)
- **Proxy/anonymizer:** User intentionally using privacy tools
- **Travel:** User is actually traveling (verify with manager or travel system if available)
- **IP geolocation inaccuracy:** Some IPs have incorrect geo data

## Triage Steps
1. **Confirm the alert details:** Extract both sign-in events, IPs, timestamps, locations, and devices
2. **Calculate travel feasibility:** Distance / time delta; >600 mph is suspicious
3. **Check IP reputation:** Query threat intel for both IPs (VirusTotal, AbuseIPDB, GreyNoise)
4. **Identify ASN/ISP:** Is it a known VPN, cloud provider, or hosting service?
5. **Review device info:** Same device ID? New device? Device compliance status?
6. **Check user's sign-in history:** Is either location in their normal pattern (last 30-90 days)?
7. **Look for MFA prompt:** Was MFA completed? From which location?
8. **Check for risky sign-in flags:** `riskLevelDuringSignIn`, `riskState` values
9. **Look for session anomalies:** Token reuse, concurrent sessions, impossible session overlap
10. **Contact user (if needed):** Verify travel or VPN usage; document response

## Recommended KQL Queries (Sentinel)

### 1. Get Sign-in Details for Specific User and Time Range
```kql
SigninLogs
| where TimeGenerated between (datetime(<StartTime>) .. datetime(<EndTime>))
| where UserPrincipalName == "<UserUPN>"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion), DeviceDetail, AppDisplayName,
    ResultType, ResultDescription, RiskLevelDuringSignIn, RiskState, ConditionalAccessStatus
| order by TimeGenerated asc
```
**Purpose:** Retrieve all sign-ins for the user during the alert window to see full context.

### 2. Calculate Geographic Velocity Between Sign-ins
```kql
let user = "<UserUPN>";
let timerange = <TimeRange>;
SigninLogs
| where TimeGenerated > ago(timerange)
| where UserPrincipalName == user
| where ResultType == 0
| extend City = tostring(LocationDetails.city), Country = tostring(LocationDetails.countryOrRegion),
    Lat = toreal(LocationDetails.geoCoordinates.latitude),
    Long = toreal(LocationDetails.geoCoordinates.longitude)
| order by TimeGenerated asc
| serialize
| extend PrevTime = prev(TimeGenerated), PrevLat = prev(Lat), PrevLong = prev(Long), PrevIP = prev(IPAddress)
| extend TimeDeltaMinutes = datetime_diff('minute', TimeGenerated, PrevTime)
| extend DistanceKm = geo_distance_2points(Long, Lat, PrevLong, PrevLat) / 1000
| extend SpeedKmh = DistanceKm / (TimeDeltaMinutes / 60.0)
| where SpeedKmh > 1000  // Flag impossible speeds (>1000 km/h)
| project TimeGenerated, IPAddress, City, Country, PrevIP, TimeDeltaMinutes, DistanceKm, SpeedKmh
```
**Purpose:** Identify sign-in pairs with impossible travel velocity.

### 3. Check IP Reputation via Enrichment (if TI available)
```kql
let suspiciousIP = "<IP>";
ThreatIntelligenceIndicator
| where NetworkIP == suspiciousIP or NetworkSourceIP == suspiciousIP
| project TimeGenerated, ThreatType, ConfidenceScore, Description, SourceSystem
```
**Purpose:** Check if the suspicious IP appears in threat intelligence feeds.

### 4. Find All Users Signing in from Suspicious IP
```kql
let suspiciousIP = "<IP>";
SigninLogs
| where TimeGenerated > ago(7d)
| where IPAddress == suspiciousIP
| summarize SignInCount = count(), Users = make_set(UserPrincipalName),
    Apps = make_set(AppDisplayName), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by IPAddress
| extend UserCount = array_length(Users)
```
**Purpose:** Determine if this IP is targeting multiple accounts (potential spray or ATO campaign).

### 5. Check for Token Replay / Concurrent Sessions
```kql
let user = "<UserUPN>";
SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName == user
| where ResultType == 0
| summarize IPs = make_set(IPAddress), Countries = make_set(tostring(LocationDetails.countryOrRegion)),
    SessionCount = dcount(CorrelationId) by bin(TimeGenerated, 5m)
| where array_length(IPs) > 1
```
**Purpose:** Detect concurrent active sessions from multiple IPs within short windows (token theft indicator).

### 6. User Sign-in Baseline (Last 30 Days)
```kql
let user = "<UserUPN>";
SigninLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName == user
| where ResultType == 0
| summarize SignInCount = count(), UniqueIPs = dcount(IPAddress),
    Countries = make_set(tostring(LocationDetails.countryOrRegion)),
    Cities = make_set(tostring(LocationDetails.city)),
    Devices = make_set(tostring(DeviceDetail.deviceId))
    by UserPrincipalName
```
**Purpose:** Establish baseline of normal sign-in locations/devices to compare against anomaly.

### 7. Check Non-Interactive Sign-ins (Token Refresh)
```kql
let user = "<UserUPN>";
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName == user
| project TimeGenerated, IPAddress, Location, AppDisplayName, ResourceDisplayName, ResultType
| order by TimeGenerated desc
```
**Purpose:** See background token activity that may indicate persistent access from attacker.

### 8. Conditional Access Evaluation Results
```kql
let user = "<UserUPN>";
SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName == user
| mv-expand CAPolicy = ConditionalAccessPolicies
| project TimeGenerated, IPAddress, PolicyName = tostring(CAPolicy.displayName),
    Result = tostring(CAPolicy.result), GrantControls = tostring(CAPolicy.enforcedGrantControls)
| where Result != "notApplied"
```
**Purpose:** Verify which Conditional Access policies were evaluated and their outcomes.

## MITRE Mapping
| Tactic | Technique ID | Technique Name | Rationale |
|--------|-------------|----------------|-----------|
| Initial Access | T1078 | Valid Accounts | Attacker using stolen credentials to authenticate |
| Initial Access | T1078.004 | Valid Accounts: Cloud Accounts | Specifically targeting cloud identity (Entra ID) |
| Credential Access | T1550 | Use Alternate Authentication Material | If token replay/theft is involved |
| Credential Access | T1550.001 | Application Access Token | Stolen OAuth/refresh token enables access |
| Defense Evasion | T1550.004 | Web Session Cookie | Session hijacking via stolen cookies |

## Containment Actions (with guardrails)

| Action | When to Use | Risk/Impact | Rollback | Owner |
|--------|-------------|-------------|----------|-------|
| Revoke all refresh tokens | Confirmed compromise; attacker has active session | User must re-authenticate on all devices; may disrupt legitimate work | Tokens auto-regenerate on next sign-in; no rollback needed | SOC / IAM |
| Reset user password | Confirmed credential theft; success from malicious IP | User locked out until password reset complete | IAM can set temporary password | IAM |
| Block suspicious IP (CA policy) | High confidence malicious IP; targeting multiple users | May block legitimate users on shared IP (NAT, VPN) | Remove IP from named location block list | IAM / SOC |
| Require MFA re-registration | MFA bypass suspected; attacker may have registered own method | User must re-enroll MFA; brief access disruption | Restore previous MFA methods from audit log | IAM |
| Disable user account | Active breach; user account fully compromised | Complete access loss for user | Re-enable account after investigation | IAM (with SOC approval) |
| Enable Conditional Access: Require compliant device | Ongoing protection; prevent unmanaged device access | May block BYOD or contractor access | Adjust CA policy scope | IAM |

## Follow-Up Investigation
- Check email for phishing (how were credentials stolen?)
- Review user's recent activity in M365 (file access, email forwarding rules, SharePoint/OneDrive)
- Check for OAuth app consents around the time of compromise
- Review MFA registration changes in Audit logs
- Search for lateral movement (did attacker access other resources?)
- Check if user credentials appear in known breaches (haveibeenpwned integration)
- Interview user: phishing email? credential reuse? device theft?

## Escalation Criteria
- **Escalate to Tier 2/Incident Response if:**
  - Confirmed successful sign-in from impossible location with no benign explanation
  - Evidence of data access or exfiltration post-compromise
  - Multiple users affected from same attacker IP
  - VIP/executive account involved
  - Attacker performed persistence actions (OAuth app, inbox rule, MFA change)
  - Credentials confirmed stolen (credential dump, phishing kit)

## Notes for Automation (RAG / SOAR)

### Entity Extraction (from alert)
- `UserPrincipalName` / `UserID`
- `IPAddress` (both IPs in travel pair)
- `Location` / `City` / `Country` for each sign-in
- `TimeGenerated` for each sign-in
- `DeviceId` / `DeviceDetail`
- `RiskLevel` / `RiskState`
- `ResultType` (success = 0)
- `AppDisplayName` (which app was accessed)

### Suggested Retrieval Keywords
`impossible travel`, `atypical sign-in`, `geographic anomaly`, `sign-in velocity`, `location anomaly`, `risky sign-in`, `token replay`, `session hijack`, `credential theft`, `account takeover`, `ATO`

### Suggested Output Fields (JSON)
```json
{
  "alert_type": "impossible_travel",
  "severity": "high|medium|low",
  "confidence": "high|medium|low",
  "user_upn": "<extracted>",
  "ip_addresses": ["<ip1>", "<ip2>"],
  "locations": ["<loc1>", "<loc2>"],
  "time_delta_minutes": "<calculated>",
  "distance_km": "<calculated>",
  "velocity_kmh": "<calculated>",
  "is_impossible": true|false,
  "ip_reputation": {"<ip>": "malicious|suspicious|clean"},
  "recommended_actions": ["revoke_tokens", "reset_password", "block_ip"],
  "queries_to_run": ["baseline_check", "concurrent_sessions", "token_replay"],
  "escalate": true|false,
  "escalation_reason": "<reason if applicable>"
}
```
