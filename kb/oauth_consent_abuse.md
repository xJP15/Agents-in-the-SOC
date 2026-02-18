# OAuth Consent Abuse / Malicious App Consent

## Definition
An attack where a user is tricked into granting OAuth permissions to a malicious or attacker-controlled application, allowing the app to access the user's data (email, files, calendar) without needing the user's password. Can result in persistent access that survives password resets.

## Key Signals
- New OAuth application consent, especially by single user
- Application requesting high-privilege scopes (Mail.Read, Mail.Send, Files.ReadWrite.All)
- Application from unverified publisher
- Consent granted to application with suspicious name or typosquat
- Admin consent granted (tenant-wide impact)
- Application with unusual redirect URIs
- Consent event followed by immediate data access
- Application created recently (new App ID)
- Multi-tenant application targeting your org

## Primary Logs
| Log Source | Table Name (Sentinel) | Notes |
|------------|----------------------|-------|
| Entra ID Audit Logs | `AuditLogs` | OAuth consent events, app registrations |
| Entra ID Sign-in Logs | `SigninLogs` | Service principal sign-ins |
| Cloud App Events | `CloudAppEvents` | MCAS alerts on OAuth apps |
| Office Activity | `OfficeActivity` | Data access by OAuth app |
| Service Principal Sign-ins | `AADServicePrincipalSignInLogs` | App authentication events |
| Microsoft Graph Activity | `MicrosoftGraphActivityLogs` | API calls made by apps (if enabled) |

**Fallback:** If Graph Activity Logs unavailable, correlate `AuditLogs` consent events with `OfficeActivity` to see subsequent data access patterns.

## False Positives / Benign Explanations
- **IT-approved third-party apps:** Legitimate SaaS integrations (Zoom, Slack, DocuSign)
- **Developer testing:** Internal devs testing applications in development
- **New IT deployment:** Sanctioned app rollout without prior documentation
- **User installing known productivity apps:** Verified Microsoft or popular vendors
- **Service account automation:** Automated workflows using legitimate OAuth

## Triage Steps
1. **Identify the application:** App ID, display name, publisher, verification status
2. **Review requested permissions:** What scopes were granted? Are they excessive?
3. **Check the consenting user:** Who consented? Were they phished?
4. **Determine consent type:** User consent or admin consent (tenant-wide)?
5. **Verify publisher:** Is the publisher verified? Is it a known legitimate vendor?
6. **Check app creation date:** When was this app registered? Recent = suspicious
7. **Review redirect URIs:** Do they point to suspicious domains?
8. **Search for consent phishing:** Did user receive suspicious email/link before consent?
9. **Check app activity:** What has the app accessed since consent?
10. **Assess blast radius:** If admin consent, all users affected; scope impact

## Recommended KQL Queries (Sentinel)

### 1. Recent OAuth Consent Events
```kql
AuditLogs
| where TimeGenerated > ago(<TimeRange>)
| where OperationName has_any ("Consent to application", "Add OAuth2PermissionGrant",
    "Add app role assignment to service principal")
| extend UserPrincipalName = tostring(InitiatedBy.user.userPrincipalName)
| extend AppDisplayName = tostring(TargetResources[0].displayName)
| extend AppId = tostring(TargetResources[0].id)
| project TimeGenerated, OperationName, UserPrincipalName, AppDisplayName, AppId,
    Result, TargetResources
| order by TimeGenerated desc
```
**Purpose:** List all recent OAuth consent events to identify suspicious applications.

### 2. Consent Details for Specific Application
```kql
let appId = "<AppId>";
AuditLogs
| where TimeGenerated > ago(30d)
| where TargetResources has appId
| extend UserPrincipalName = tostring(InitiatedBy.user.userPrincipalName)
| extend ModifiedProps = TargetResources[0].modifiedProperties
| mv-expand ModifiedProps
| extend PropName = tostring(ModifiedProps.displayName),
    NewValue = tostring(ModifiedProps.newValue)
| project TimeGenerated, OperationName, UserPrincipalName, PropName, NewValue
| order by TimeGenerated asc
```
**Purpose:** Get detailed history of specific suspicious application.

### 3. High-Risk Permission Grants
```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Add OAuth2PermissionGrant"
| extend Permissions = tostring(TargetResources[0].modifiedProperties)
| where Permissions has_any ("Mail.Read", "Mail.Send", "Mail.ReadWrite",
    "Files.ReadWrite.All", "Directory.ReadWrite.All", "User.ReadWrite.All",
    "MailboxSettings.ReadWrite", "Contacts.ReadWrite")
| extend UserPrincipalName = tostring(InitiatedBy.user.userPrincipalName)
| extend AppDisplayName = tostring(TargetResources[0].displayName)
| project TimeGenerated, UserPrincipalName, AppDisplayName, Permissions
```
**Purpose:** Find apps granted dangerous permissions (mail access, file access, directory write).

### 4. Admin Consent Events (Tenant-Wide)
```kql
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has "Consent to application"
| extend ConsentType = tostring(TargetResources[0].modifiedProperties)
| where ConsentType has "AllPrincipals" or ConsentType has "adminConsent"
| extend AdminUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend AppDisplayName = tostring(TargetResources[0].displayName)
| project TimeGenerated, AdminUPN, AppDisplayName, ConsentType, TargetResources
```
**Purpose:** Identify admin-level consents that affect all users in tenant.

### 5. Service Principal Sign-in Activity for Suspicious App
```kql
let appId = "<AppId>";
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(7d)
| where AppId == appId
| summarize SignInCount = count(),
    Resources = make_set(ResourceDisplayName),
    IPs = make_set(IPAddress),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by AppId, ServicePrincipalName
```
**Purpose:** See how actively the suspicious app is using its granted permissions.

### 6. Data Access by OAuth App (OfficeActivity)
```kql
let appId = "<AppId>";
OfficeActivity
| where TimeGenerated > ago(7d)
| where ApplicationId == appId or UserId has "ServicePrincipal"
| summarize ActionCount = count(),
    Actions = make_set(Operation),
    Objects = make_set(OfficeObjectId)
    by ApplicationId, UserId
| order by ActionCount desc
```
**Purpose:** Identify what data the malicious app has accessed (files, emails, etc.).

### 7. Find Phishing Email Leading to Consent
```kql
let user = "<UserUPN>";
let consentTime = datetime(<ConsentTime>);
EmailEvents
| where TimeGenerated between ((consentTime - 4h) .. consentTime)
| where RecipientEmailAddress == user
| where isnotempty(UrlCount) or Subject has_any ("verify", "confirm", "access", "permission", "consent")
| project TimeGenerated, SenderFromAddress, Subject, UrlCount, DeliveryAction
```
**Purpose:** Find the phishing email that tricked user into consenting.

### 8. All Users Who Consented to Specific App
```kql
let appId = "<AppId>";
AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName has "Consent"
| where TargetResources has appId
| extend UserPrincipalName = tostring(InitiatedBy.user.userPrincipalName)
| summarize ConsentCount = count(), FirstConsent = min(TimeGenerated),
    LastConsent = max(TimeGenerated) by UserPrincipalName
| order by FirstConsent asc
```
**Purpose:** Find all users affected by the malicious app consent.

## MITRE Mapping
| Tactic | Technique ID | Technique Name | Rationale |
|--------|-------------|----------------|-----------|
| Initial Access | T1566.002 | Phishing: Spearphishing Link | User tricked into clicking consent link |
| Persistence | T1098.003 | Account Manipulation: Additional Cloud Roles | App granted persistent permissions |
| Credential Access | T1528 | Steal Application Access Token | OAuth token theft via consent abuse |
| Collection | T1114.002 | Email Collection: Remote Email Collection | App reads emails via Graph API |
| Exfiltration | T1567.002 | Exfiltration Over Web Service: Cloud Storage | App exfils to attacker infrastructure |

## Containment Actions (with guardrails)

| Action | When to Use | Risk/Impact | Rollback | Owner |
|--------|-------------|-------------|----------|-------|
| Revoke app consent (user-level) | Single user consented to malicious app | User loses access to app functionality | Re-consent if legitimate | SOC / IAM |
| Remove service principal | Confirmed malicious app; need full removal | All users lose app access | Re-create service principal if needed | IAM |
| Revoke admin consent | Admin consent was malicious; tenant-wide | All users lose app access | Admin must re-consent | IAM (senior approval) |
| Block app tenant-wide | Prevent future consent to known-bad app | Legitimate use cases blocked | Remove from blocked apps list | IAM |
| Revoke user's OAuth tokens | User's account may be compromised | User must re-auth to all apps | Tokens auto-regenerate | SOC / IAM |
| Reset user password | User was phished; credentials may be compromised | User locked out until reset | Temp password from IAM | IAM |
| Disable consent for non-admin users | Prevent future user-level consent attacks | Users cannot self-service app consent | Re-enable or create exception workflow | IAM |

## Follow-Up Investigation
- Check what data the app accessed (emails read, files downloaded)
- Search for exfiltration indicators (large data transfers, unusual API patterns)
- Review user's email for phishing that led to consent
- Check if other users consented to the same app
- Investigate the app's publisher; is it a known attacker infrastructure?
- Review user's account for other compromise indicators
- Check if user's credentials were used elsewhere (credential stuffing)
- Search threat intel for the App ID or publisher

## Escalation Criteria
- **Escalate to Tier 2/Incident Response if:**
  - Admin consent was granted (tenant-wide impact)
  - App accessed sensitive data (executive mailboxes, confidential files)
  - App granted directory write permissions
  - Multiple users consented (coordinated campaign)
  - App is exfiltrating data to external infrastructure
  - App created by known threat actor
  - App permissions include Mail.Send (BEC risk)
  - Unable to determine full scope of data access

## Notes for Automation (RAG / SOAR)

### Entity Extraction (from alert)
- `AppId` / `ApplicationId`
- `AppDisplayName`
- `ServicePrincipalId`
- `UserPrincipalName` (who consented)
- `Permissions` / `Scopes` granted
- `ConsentType` (user vs. admin)
- `TimeGenerated` (consent timestamp)
- `PublisherName` / `VerifiedPublisher`
- `RedirectUris`

### Suggested Retrieval Keywords
`OAuth consent`, `app consent`, `illicit consent`, `consent phishing`, `malicious app`, `service principal`, `application permissions`, `delegated permissions`, `Graph API abuse`, `T1528`, `OAuth abuse`

### Suggested Output Fields (JSON)
```json
{
  "alert_type": "oauth_consent_abuse",
  "severity": "critical|high|medium|low",
  "confidence": "high|medium|low",
  "app_id": "<extracted>",
  "app_display_name": "<extracted>",
  "publisher": "<extracted>",
  "is_verified_publisher": true|false,
  "consenting_user": "<extracted>",
  "consent_type": "user|admin",
  "permissions_granted": ["<scope1>", "<scope2>"],
  "high_risk_permissions": ["Mail.Read", "Mail.Send"],
  "consent_timestamp": "<time>",
  "app_creation_date": "<date>",
  "data_accessed": ["email", "files", "calendar"],
  "affected_users": ["<user1>", "<user2>"],
  "recommended_actions": ["revoke_consent", "remove_service_principal", "reset_password"],
  "escalate": true|false,
  "escalation_reason": "<reason if applicable>"
}
```
