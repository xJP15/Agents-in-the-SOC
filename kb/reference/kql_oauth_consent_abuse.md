# KQL Reference: OAuth Consent Abuse

## Parameters
- `{{app_id}}` - Application/Client ID
- `{{user}}` - Consenting user UPN
- `{{time_range}}` - Lookback period (e.g., 7d, 30d)

---

## Detection Validation

### 1. Confirm Consent Event for App
Use when: Validating alert for specific application.
```kql
AuditLogs
| where TimeGenerated > ago({{time_range}})
| where TargetResources has "{{app_id}}"
| where OperationName has_any ("Consent to application", "Add OAuth2PermissionGrant")
| extend UserPrincipalName = tostring(InitiatedBy.user.userPrincipalName)
| extend AppDisplayName = tostring(TargetResources[0].displayName)
| project TimeGenerated, OperationName, UserPrincipalName, AppDisplayName, Result
```

---

## Investigation Queries

### 2. High-Risk Permission Grants
Use when: Detecting dangerous scopes granted.
```kql
AuditLogs
| where TimeGenerated > ago({{time_range}})
| where OperationName == "Add OAuth2PermissionGrant"
| extend Permissions = tostring(TargetResources[0].modifiedProperties)
| where Permissions has_any ("Mail.Read", "Mail.Send", "Mail.ReadWrite", "Files.ReadWrite.All", "Directory.ReadWrite.All")
| extend UserPrincipalName = tostring(InitiatedBy.user.userPrincipalName)
| extend AppDisplayName = tostring(TargetResources[0].displayName)
| project TimeGenerated, UserPrincipalName, AppDisplayName, Permissions
```

### 3. Admin Consent Events (Tenant-Wide)
Use when: Checking for high-impact grants.
```kql
AuditLogs
| where TimeGenerated > ago({{time_range}})
| where OperationName has "Consent to application"
| extend ConsentType = tostring(TargetResources[0].modifiedProperties)
| where ConsentType has_any ("AllPrincipals", "adminConsent")
| extend AdminUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend AppDisplayName = tostring(TargetResources[0].displayName)
| project TimeGenerated, AdminUPN, AppDisplayName, ConsentType
```

### 4. Service Principal Activity Post-Consent
Use when: Checking app behavior after access granted.
```kql
AADServicePrincipalSignInLogs
| where TimeGenerated > ago({{time_range}})
| where AppId == "{{app_id}}"
| summarize SignInCount = count(), Resources = make_set(ResourceDisplayName), IPs = make_set(IPAddress) by ServicePrincipalName, ResultType
```
