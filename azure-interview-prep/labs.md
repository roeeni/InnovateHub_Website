# Azure Interview Preparation - 10 Comprehensive Labs
## Microsoft Israel | Azure Customer Engineer / Architect

> **מטרת המסמך**: מעבדות מעשיות מלאות (Step-by-Step) לתרגול אינטנסיבי לפני הראיון.
> כל מעבדה כוללת: מטרה, שלבים, KQL לניטור, ושאלות "מה אם?" לעמקי ההבנה.

---

## Lab 1: The "Zero Trust" Lab - Private Endpoints Only

**Level**: Advanced | **Duration**: ~3 hours | **Pillars**: Security, Reliability

### Goal
הקמת סביבה מאובטחת מלאה בה כל השירותים נגישים אך ורק דרך Private Endpoints, ללא שום חשיפה ציבורית.

### Architecture Diagram
```
Internet
    │ (BLOCKED - No public access)
    │
VNET (10.0.0.0/16)
├── Subnet: app-subnet (10.0.1.0/24)
│   └── App Service (VNET Integration)
├── Subnet: data-subnet (10.0.2.0/24)
│   ├── Private Endpoint → Azure SQL
│   └── Private Endpoint → Key Vault
└── Subnet: mgmt-subnet (10.0.3.0/24)
    └── Bastion Host (Admin access only)
```

### Step-by-Step

```bash
# Step 1: Create Resource Group & VNET
az group create --name rg-zerotrust-lab --location israelcentral

az network vnet create \
  --resource-group rg-zerotrust-lab \
  --name vnet-zerotrust \
  --address-prefix 10.0.0.0/16 \
  --subnet-name app-subnet \
  --subnet-prefix 10.0.1.0/24

# Add additional subnets
az network vnet subnet create \
  --resource-group rg-zerotrust-lab \
  --vnet-name vnet-zerotrust \
  --name data-subnet \
  --address-prefix 10.0.2.0/24

az network vnet subnet create \
  --resource-group rg-zerotrust-lab \
  --vnet-name vnet-zerotrust \
  --name mgmt-subnet \
  --address-prefix 10.0.3.0/24

# Step 2: Create App Service Plan & Web App
az appservice plan create \
  --name asp-zerotrust \
  --resource-group rg-zerotrust-lab \
  --sku P1v3 \
  --is-linux

az webapp create \
  --resource-group rg-zerotrust-lab \
  --plan asp-zerotrust \
  --name app-zerotrust-$(date +%s) \
  --runtime "NODE:18-lts"

# Step 3: Enable VNET Integration for App Service
az webapp vnet-integration add \
  --resource-group rg-zerotrust-lab \
  --name <your-app-name> \
  --vnet vnet-zerotrust \
  --subnet app-subnet

# Step 4: Create Azure SQL with Private Endpoint
az sql server create \
  --name sql-zerotrust-$(date +%s) \
  --resource-group rg-zerotrust-lab \
  --location israelcentral \
  --admin-user sqladmin \
  --admin-password "P@ssw0rd!2026"

az sql db create \
  --resource-group rg-zerotrust-lab \
  --server <your-sql-server-name> \
  --name db-app

# Disable public access on SQL
az sql server update \
  --resource-group rg-zerotrust-lab \
  --name <your-sql-server-name> \
  --enable-public-network false

# Create Private Endpoint for SQL
az network private-endpoint create \
  --name pe-sql \
  --resource-group rg-zerotrust-lab \
  --vnet-name vnet-zerotrust \
  --subnet data-subnet \
  --private-connection-resource-id $(az sql server show -g rg-zerotrust-lab -n <sql-name> --query id -o tsv) \
  --group-id sqlServer \
  --connection-name sql-connection

# Step 5: Create Key Vault with Private Endpoint
az keyvault create \
  --name kv-zerotrust-$(date +%s) \
  --resource-group rg-zerotrust-lab \
  --location israelcentral \
  --default-action Deny \
  --bypass None

az network private-endpoint create \
  --name pe-keyvault \
  --resource-group rg-zerotrust-lab \
  --vnet-name vnet-zerotrust \
  --subnet data-subnet \
  --private-connection-resource-id $(az keyvault show -g rg-zerotrust-lab -n <kv-name> --query id -o tsv) \
  --group-id vault \
  --connection-name kv-connection

# Step 6: Configure Private DNS Zones
az network private-dns zone create \
  --resource-group rg-zerotrust-lab \
  --name "privatelink.vaultcore.azure.net"

az network private-dns link vnet create \
  --resource-group rg-zerotrust-lab \
  --zone-name "privatelink.vaultcore.azure.net" \
  --name dns-link-kv \
  --virtual-network vnet-zerotrust \
  --registration-enabled false

# Repeat for SQL: privatelink.database.windows.net

# Step 7: Enable Managed Identity & Grant Access
az webapp identity assign \
  --resource-group rg-zerotrust-lab \
  --name <your-app-name>

# Grant Key Vault Secrets User role to App's Managed Identity
az keyvault set-policy \
  --name <kv-name> \
  --object-id $(az webapp identity show -g rg-zerotrust-lab -n <app-name> --query principalId -o tsv) \
  --secret-permissions get list

# Step 8: Store connection string in Key Vault
az keyvault secret set \
  --vault-name <kv-name> \
  --name "sql-connection-string" \
  --value "Server=<pe-sql-fqdn>;Database=db-app;Authentication=Active Directory Managed Identity"

# Step 9: Configure App Settings to use Key Vault Reference
az webapp config appsettings set \
  --resource-group rg-zerotrust-lab \
  --name <app-name> \
  --settings "SQL_CONNECTION=@Microsoft.KeyVault(SecretUri=https://<kv-name>.vault.azure.net/secrets/sql-connection-string/)"
```

### Monitoring KQL
```kql
// Verify Private Endpoint connections
AzureDiagnostics
| where ResourceType == "VAULTS" and Category == "AuditEvent"
| where OperationName == "SecretGet"
| project TimeGenerated, CallerIPAddress, ResultSignature, requestUri_s
| order by TimeGenerated desc

// Key Vault Access Audit
KeyVaultAuditLogs
| where OperationName == "SecretGet"
| summarize AccessCount = count() by CallerObjectId, bin(TimeGenerated, 1h)
| order by AccessCount desc
```

### What-If Questions
- **מה אם** האפליקציה צריכה לקרוא ל-External API? (Azure Firewall + NAT Gateway)
- **מה אם** מפתח צריך גישה לניפוי שגיאות ב-Database? (Bastion + JIT Access)
- **מה אם** ה-Compliance דורש רישום של כל גישה לנתונים? (SQL Auditing + Log Analytics)
- **מה אם** ה-App צריך גישה ל-Storage Account? (Private Endpoint + same pattern)

---

## Lab 2: The "Resilient App" Lab - Multi-Region with Azure Front Door

**Level**: Advanced | **Duration**: ~2.5 hours | **Pillars**: Reliability, Performance

### Goal
פריסת אפליקציה ב-2 Regions עם Azure Front Door, Health Probes, ו-Automatic Failover.

### Architecture Diagram
```
                    ┌──────────────────────┐
                    │   Azure Front Door   │
                    │  WAF Policy + Routes │
                    └──────────┬───────────┘
                               │
               ┌───────────────┴───────────────┐
               │                               │
    ┌──────────▼──────────┐        ┌──────────▼──────────┐
    │ Israel Central      │        │ West Europe         │
    │ App Service         │        │ App Service         │
    │ (PRIMARY - P1)      │        │ (SECONDARY - P2)    │
    └─────────────────────┘        └─────────────────────┘
```

### Step-by-Step

```bash
# Step 1: Create App Services in two regions
az group create --name rg-resilient-il --location israelcentral
az group create --name rg-resilient-eu --location westeurope

# Primary - Israel
az appservice plan create --name asp-il --resource-group rg-resilient-il --sku P1v3 --is-linux
az webapp create --resource-group rg-resilient-il --plan asp-il --name webapp-il-$(date +%s) --runtime "NODE:18-lts"

# Secondary - West Europe
az appservice plan create --name asp-eu --resource-group rg-resilient-eu --sku P1v3 --is-linux
az webapp create --resource-group rg-resilient-eu --plan asp-eu --name webapp-eu-$(date +%s) --runtime "NODE:18-lts"

# Step 2: Create Azure Front Door
az afd profile create \
  --resource-group rg-resilient-il \
  --profile-name afd-resilient \
  --sku Standard_AzureFrontDoor

# Create endpoint
az afd endpoint create \
  --resource-group rg-resilient-il \
  --profile-name afd-resilient \
  --endpoint-name app-endpoint \
  --enabled-state Enabled

# Step 3: Add Origin Group with Health Probes
az afd origin-group create \
  --resource-group rg-resilient-il \
  --profile-name afd-resilient \
  --origin-group-name og-webapps \
  --probe-request-type GET \
  --probe-protocol Https \
  --probe-interval-in-seconds 30 \
  --probe-path "/health" \
  --sample-size 4 \
  --successful-samples-required 3 \
  --additional-latency-in-milliseconds 50

# Step 4: Add Origins (Primary & Secondary)
az afd origin create \
  --resource-group rg-resilient-il \
  --profile-name afd-resilient \
  --origin-group-name og-webapps \
  --origin-name origin-il \
  --host-name <webapp-il-hostname>.azurewebsites.net \
  --priority 1 \
  --weight 1000 \
  --enabled-state Enabled

az afd origin create \
  --resource-group rg-resilient-il \
  --profile-name afd-resilient \
  --origin-group-name og-webapps \
  --origin-name origin-eu \
  --host-name <webapp-eu-hostname>.azurewebsites.net \
  --priority 2 \
  --weight 1000 \
  --enabled-state Enabled

# Step 5: Create WAF Policy
az network front-door waf-policy create \
  --resource-group rg-resilient-il \
  --name waf-policy-afd \
  --sku Standard_AzureFrontDoor \
  --mode Prevention

# Add OWASP managed rule set
az network front-door waf-policy managed-rules add \
  --resource-group rg-resilient-il \
  --policy-name waf-policy-afd \
  --type Microsoft_DefaultRuleSet \
  --version 2.1

# Step 6: Simulate Failover - Stop Primary App Service
az webapp stop --resource-group rg-resilient-il --name <webapp-il-name>
# Wait 30-60 seconds, then verify traffic goes to EU
curl -I https://<afd-endpoint-hostname>.z01.azurefd.net
```

### Monitoring KQL
```kql
// Front Door - Request Distribution by Origin
AzureDiagnostics
| where ResourceType == "FRONTDOORS"
| where Category == "FrontdoorAccessLog"
| summarize Requests = count() by backendHostname_s, bin(TimeGenerated, 5m)
| render timechart

// Health Probe Failures
AzureDiagnostics
| where ResourceType == "FRONTDOORS"
| where Category == "FrontdoorHealthProbeLog"
| where httpStatusCode_d != 200
| project TimeGenerated, backendHostname_s, httpStatusCode_d, result_s
| order by TimeGenerated desc
```

### What-If Questions
- **מה אם** אתה צריך Session Affinity? (AFD - Session Affinity setting)
- **מה אם** ה-Failover איטי מדי עבור ה-RTO? (Reduce probe interval + increase failure threshold)
- **מה אם** צריך Geo-Filtering (חסימת גישה ממדינות מסוימות)? (WAF Geo-filter rule)
- **מה אם** ה-App Service ב-Israel חזר? האם AFD חוזר אוטומטית? (כן - Priority-based failback)

---

## Lab 3: The "KQL Ninja" Lab - Security Detection & Alerting

**Level**: Advanced | **Duration**: ~2 hours | **Pillars**: Security, Monitoring

### Goal
כתיבת שאילתות KQL מתקדמות לזיהוי איומי אבטחה ב-Real-time, יצירת Alert Rules, וחיבורם ל-Teams.

### Step-by-Step

```bash
# Step 1: Create Log Analytics Workspace
az group create --name rg-kql-lab --location israelcentral

az monitor log-analytics workspace create \
  --resource-group rg-kql-lab \
  --workspace-name law-security-lab

# Step 2: Enable Microsoft Sentinel
az sentinel onboarding-state create \
  --resource-group rg-kql-lab \
  --workspace-name law-security-lab \
  --name default

# Step 3: Connect Data Sources (done in Portal - Sentinel → Data connectors)
# - Azure Active Directory (Sign-in logs, Audit logs)
# - Azure Activity
# - Microsoft Defender for Cloud
# - Office 365 (if applicable)
```

### Detection KQL Queries

**Query 1: Brute Force Attack Detection**
```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != "0"  // Failed logins only
| summarize
    FailedCount = count(),
    DistinctUsers = dcount(UserPrincipalName),
    DistinctApps = dcount(AppDisplayName),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
  by IPAddress, bin(TimeGenerated, 5m)
| where FailedCount > 5
| extend AttackDuration = LastAttempt - FirstAttempt
| extend SeverityLevel = iff(FailedCount > 50, "Critical", iff(FailedCount > 20, "High", "Medium"))
| project-reorder IPAddress, FailedCount, DistinctUsers, SeverityLevel, AttackDuration
| order by FailedCount desc
```

**Query 2: Impossible Travel Detection**
```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == "0"  // Successful logins
| project TimeGenerated, UserPrincipalName, IPAddress, Location, CountryOrRegion
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(1h)
    | where ResultType == "0"
    | project TimeGenerated2 = TimeGenerated, UserPrincipalName, IPAddress2 = IPAddress, CountryOrRegion2 = CountryOrRegion
) on UserPrincipalName
| where TimeGenerated < TimeGenerated2
| where CountryOrRegion != CountryOrRegion2
| extend TimeDiff = TimeGenerated2 - TimeGenerated
| where TimeDiff < 1h  // Two countries within 1 hour = impossible!
| project UserPrincipalName, FirstCountry = CountryOrRegion, SecondCountry = CountryOrRegion2, TimeDiff
```

**Query 3: Privileged Role Assignment**
```kql
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName == "Add member to role"
| where TargetResources[0].displayName has_any ("Global Administrator", "Security Administrator", "Privileged Role Administrator")
| project
    TimeGenerated,
    InitiatedBy = tostring(InitiatedBy.user.userPrincipalName),
    TargetUser = tostring(TargetResources[0].userPrincipalName),
    Role = tostring(TargetResources[0].displayName)
| order by TimeGenerated desc
```

**Query 4: Mass Data Download Alert**
```kql
OfficeActivity
| where TimeGenerated > ago(1h)
| where Operation in ("FileDownloaded", "FileAccessed")
| summarize DownloadCount = count() by UserId, ClientIP, bin(TimeGenerated, 10m)
| where DownloadCount > 100  // More than 100 files in 10 minutes
| extend RiskLevel = "High - Possible Data Exfiltration"
| order by DownloadCount desc
```

**Query 5: Azure Resource Deletion Spike**
```kql
AzureActivity
| where TimeGenerated > ago(2h)
| where OperationNameValue contains "delete"
| where ActivityStatusValue == "Success"
| summarize DeleteCount = count() by Caller, ResourceGroup, bin(TimeGenerated, 15m)
| where DeleteCount > 5
| project TimeGenerated, Caller, ResourceGroup, DeleteCount
| order by DeleteCount desc
```

### Creating Alert Rules

```bash
# Create Alert Rule from KQL query
az monitor scheduled-query create \
  --resource-group rg-kql-lab \
  --name "BruteForceAlert" \
  --scopes $(az monitor log-analytics workspace show -g rg-kql-lab -n law-security-lab --query id -o tsv) \
  --condition-query "SigninLogs | where ResultType != '0' | summarize FailedCount = count() by IPAddress, bin(TimeGenerated, 5m) | where FailedCount > 5" \
  --condition-time-aggregation Count \
  --condition-threshold 0 \
  --condition-operator GreaterThan \
  --evaluation-frequency 5m \
  --window-size 5m \
  --severity 2 \
  --description "Brute force attack detected - more than 5 failed logins from same IP in 5 minutes"

# Create Action Group for Teams notification
az monitor action-group create \
  --resource-group rg-kql-lab \
  --name ag-security-team \
  --short-name SecTeam \
  --webhook-receiver name=TeamsWebhook serviceUri=<teams-webhook-url>
```

### What-If Questions
- **מה אם** ה-Query מחזיר False Positives רבים? (Fine-tune threshold + whitelist known IPs)
- **מה אם** צריך לשמור את ה-Incident ב-SIEM חיצוני? (Sentinel - Playbook + Logic App)
- **מה אם** KQL איטית מדי על טבלאות גדולות? (Partitioning by bin(), use let statements, limit time ranges)

---

## Lab 4: The "Hub & Spoke" Lab - Enterprise Networking

**Level**: Advanced | **Duration**: ~3 hours | **Pillars**: Security, Reliability, Manageability

### Goal
הקמת ארכיטקטורת Hub & Spoke עם Azure Firewall שמרכז כל ה-Traffic, כולל חיבור VPN ל-On-Premises.

### Architecture Diagram
```
On-Premises (192.168.0.0/24)
         │
    VPN Connection
         │
┌────────▼────────────────────┐
│        HUB VNET              │
│       10.0.0.0/16            │
│                              │
│  ┌──────────────────────┐   │
│  │   Azure Firewall     │   │
│  │   10.0.1.4 (private) │   │
│  └──────────────────────┘   │
│  ┌──────────────────────┐   │
│  │   VPN Gateway        │   │
│  │   GatewaySubnet      │   │
│  └──────────────────────┘   │
└──────────┬──────────────────┘
     VNET Peering
    ┌───────┴───────┐
    │               │
┌───▼────┐     ┌───▼────┐
│ SPOKE1 │     │ SPOKE2 │
│Prod    │     │ Dev    │
│10.1.x  │     │10.2.x  │
└────────┘     └────────┘
```

### Step-by-Step

```bash
# Step 1: Create Hub VNET
az group create --name rg-hub-spoke --location israelcentral

az network vnet create \
  --resource-group rg-hub-spoke \
  --name vnet-hub \
  --address-prefix 10.0.0.0/16

# Create required subnets in Hub
for subnet in "AzureFirewallSubnet:10.0.1.0/26" "GatewaySubnet:10.0.2.0/27" "AzureBastionSubnet:10.0.3.0/27"; do
  name="${subnet%%:*}"
  prefix="${subnet##*:}"
  az network vnet subnet create \
    --resource-group rg-hub-spoke \
    --vnet-name vnet-hub \
    --name "$name" \
    --address-prefix "$prefix"
done

# Step 2: Create Spoke VNETs
az network vnet create \
  --resource-group rg-hub-spoke \
  --name vnet-spoke-prod \
  --address-prefix 10.1.0.0/16 \
  --subnet-name workload-subnet \
  --subnet-prefix 10.1.1.0/24

az network vnet create \
  --resource-group rg-hub-spoke \
  --name vnet-spoke-dev \
  --address-prefix 10.2.0.0/16 \
  --subnet-name workload-subnet \
  --subnet-prefix 10.2.1.0/24

# Step 3: Create VNET Peering (Hub <-> Spokes)
# Hub to Spoke-Prod
az network vnet peering create \
  --resource-group rg-hub-spoke \
  --name hub-to-prod \
  --vnet-name vnet-hub \
  --remote-vnet vnet-spoke-prod \
  --allow-forwarded-traffic true \
  --allow-gateway-transit true

az network vnet peering create \
  --resource-group rg-hub-spoke \
  --name prod-to-hub \
  --vnet-name vnet-spoke-prod \
  --remote-vnet vnet-hub \
  --allow-forwarded-traffic true \
  --use-remote-gateways true

# Repeat for Spoke-Dev...

# Step 4: Deploy Azure Firewall
az network public-ip create \
  --resource-group rg-hub-spoke \
  --name pip-firewall \
  --sku Standard \
  --allocation-method Static

az network firewall create \
  --resource-group rg-hub-spoke \
  --name azfw-hub \
  --location israelcentral \
  --sku-name AZFW_VNet \
  --sku-tier Standard

az network firewall ip-config create \
  --firewall-name azfw-hub \
  --resource-group rg-hub-spoke \
  --name fw-ip-config \
  --public-ip-address pip-firewall \
  --vnet-name vnet-hub

# Step 5: Create Route Tables to force traffic through Firewall
FW_PRIVATE_IP=$(az network firewall show -g rg-hub-spoke -n azfw-hub --query "ipConfigurations[0].privateIPAddress" -o tsv)

az network route-table create \
  --resource-group rg-hub-spoke \
  --name rt-spoke-to-fw

az network route-table route create \
  --resource-group rg-hub-spoke \
  --route-table-name rt-spoke-to-fw \
  --name route-to-internet \
  --address-prefix 0.0.0.0/0 \
  --next-hop-type VirtualAppliance \
  --next-hop-ip-address $FW_PRIVATE_IP

# Associate route table with spoke subnets
az network vnet subnet update \
  --resource-group rg-hub-spoke \
  --vnet-name vnet-spoke-prod \
  --name workload-subnet \
  --route-table rt-spoke-to-fw

# Step 6: Create Firewall Policy & Rules
az network firewall policy create \
  --resource-group rg-hub-spoke \
  --name fw-policy-hub

az network firewall policy rule-collection-group create \
  --resource-group rg-hub-spoke \
  --policy-name fw-policy-hub \
  --name DefaultRules \
  --priority 100

# Allow HTTP/HTTPS outbound from Prod spoke
az network firewall policy rule-collection-group collection add-filter-collection \
  --resource-group rg-hub-spoke \
  --policy-name fw-policy-hub \
  --rule-collection-group-name DefaultRules \
  --name allow-web \
  --collection-priority 100 \
  --action Allow \
  --rule-name allow-https \
  --rule-type NetworkRule \
  --source-addresses "10.1.0.0/16" \
  --destination-addresses "*" \
  --ip-protocols TCP \
  --destination-ports 443 80
```

### Monitoring KQL
```kql
// Azure Firewall - Denied Traffic Analysis
AzureDiagnostics
| where Category == "AzureFirewallNetworkRule"
| where msg_s contains "Deny"
| parse msg_s with * "from " SourceIP ":" SourcePort " to " DestIP ":" DestPort ". " Action
| summarize DeniedConnections = count() by SourceIP, DestIP, DestPort, bin(TimeGenerated, 1h)
| order by DeniedConnections desc

// Spoke-to-Spoke Traffic (Should be blocked without explicit allow)
AzureDiagnostics
| where Category == "AzureFirewallNetworkRule"
| where SourceIP startswith "10.1." and DestinationIP_s startswith "10.2."
| project TimeGenerated, msg_s
```

### What-If Questions
- **מה אם** ה-Spokes צריכים לתקשר ישירות? (Transitive routing requires going through Firewall - configure explicit rules)
- **מה אם** ה-Firewall עצמו הוא Single Point of Failure? (Active-Active Azure Firewall with load balancer)
- **מה אם** לקוח On-Premises צריך גישה רק ל-Spoke-Prod ולא ל-Dev? (Firewall rules + NSG)
- **מה אם** הצוות צריך לנטר כל טרפיק בין Spokes? (Enable Firewall Diagnostic logs to Log Analytics)

---

## Lab 5: The "AKS Zero Trust" Lab - Kubernetes with Enterprise Security

**Level**: Expert | **Duration**: ~4 hours | **Pillars**: Security, Reliability, Manageability

### Goal
הקמת AKS Private Cluster עם Azure CNI, Azure AD integration, OPA Gatekeeper, ו-Key Vault CSI Driver.

### Step-by-Step

```bash
# Step 1: Prerequisites
az group create --name rg-aks-lab --location israelcentral

# Create dedicated VNET for AKS (Azure CNI requires enough IP space)
az network vnet create \
  --resource-group rg-aks-lab \
  --name vnet-aks \
  --address-prefix 10.10.0.0/8

az network vnet subnet create \
  --resource-group rg-aks-lab \
  --vnet-name vnet-aks \
  --name aks-node-subnet \
  --address-prefix 10.10.0.0/16

az network vnet subnet create \
  --resource-group rg-aks-lab \
  --vnet-name vnet-aks \
  --name aks-pod-subnet \
  --address-prefix 10.20.0.0/16

# Step 2: Create Private Container Registry
az acr create \
  --resource-group rg-aks-lab \
  --name acrakslab$(date +%s) \
  --sku Premium \
  --public-network-enabled false

# Step 3: Create Private AKS Cluster with Azure CNI Overlay
NODE_SUBNET_ID=$(az network vnet subnet show -g rg-aks-lab --vnet-name vnet-aks -n aks-node-subnet --query id -o tsv)
ACR_ID=$(az acr show --resource-group rg-aks-lab --name <acr-name> --query id -o tsv)

az aks create \
  --resource-group rg-aks-lab \
  --name aks-private-cluster \
  --location israelcentral \
  --node-count 3 \
  --node-vm-size Standard_D4s_v3 \
  --enable-private-cluster \
  --network-plugin azure \
  --network-plugin-mode overlay \
  --pod-cidr 192.168.0.0/16 \
  --vnet-subnet-id $NODE_SUBNET_ID \
  --enable-aad \
  --enable-azure-rbac \
  --enable-oidc-issuer \
  --enable-workload-identity \
  --attach-acr $ACR_ID \
  --enable-addons monitoring,azure-policy \
  --workspace-resource-id $(az monitor log-analytics workspace show -g rg-aks-lab -n <law-name> --query id -o tsv) \
  --enable-secret-rotation \
  --enable-azure-keyvault-secrets-provider

# Step 4: Enable Workload Identity for Key Vault access
# Create Managed Identity
az identity create --resource-group rg-aks-lab --name id-aks-workload

# Federate the identity with AKS service account
AKS_OIDC_ISSUER=$(az aks show -g rg-aks-lab -n aks-private-cluster --query "oidcIssuerProfile.issuerUrl" -o tsv)

az identity federated-credential create \
  --name fc-aks-workload \
  --identity-name id-aks-workload \
  --resource-group rg-aks-lab \
  --issuer $AKS_OIDC_ISSUER \
  --subject system:serviceaccount:default:workload-sa

# Grant Key Vault access to the identity
az keyvault set-policy \
  --name <kv-name> \
  --object-id $(az identity show -g rg-aks-lab -n id-aks-workload --query principalId -o tsv) \
  --secret-permissions get list

# Step 5: Deploy SecretProviderClass for Key Vault CSI
cat <<EOF | kubectl apply -f -
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: azure-kvname-workload-identity
  namespace: default
spec:
  provider: azure
  parameters:
    usePodIdentity: "false"
    useVMManagedIdentity: "false"
    clientID: "$(az identity show -g rg-aks-lab -n id-aks-workload --query clientId -o tsv)"
    keyvaultName: "<kv-name>"
    objects: |
      array:
        - |
          objectName: sql-connection-string
          objectType: secret
    tenantId: "$(az account show --query tenantId -o tsv)"
EOF

# Step 6: Apply Azure Policy - OPA Gatekeeper Constraints
# Example: Deny privileged containers
cat <<EOF | kubectl apply -f -
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sAzureContainerNoPrivilege
metadata:
  name: container-no-privilege
spec:
  enforcementAction: deny
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces: ["production"]
EOF

# Step 7: Create Network Policy to restrict pod-to-pod traffic
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-ingress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress: []
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
EOF
```

### Monitoring KQL
```kql
// AKS - Failed/Crashing Pods
KubePodInventory
| where ClusterName == "aks-private-cluster"
| where PodStatus in ("Failed", "CrashLoopBackOff", "OOMKilled")
| summarize count() by PodStatus, Namespace, Name, ContainerName
| order by count_ desc

// AKS - Node Resource Pressure
KubeNodeInventory
| where ClusterName == "aks-private-cluster"
| where Status contains "Pressure"
| project TimeGenerated, Computer, Status
| order by TimeGenerated desc

// Container Registry Pull Failures
ContainerRegistryLoginEvents
| where ResultDescription != "Login Succeeded"
| project TimeGenerated, Identity, IPAddress, ResultDescription
| order by TimeGenerated desc
```

### What-If Questions
- **מה אם** Node אחד מגיע ל-100% CPU? (HPA + Cluster Autoscaler)
- **מה אם** Pod צריך גישה ל-Azure SQL? (Workload Identity + Private Endpoint)
- **מה אם** Image ב-Registry נמצאה כ-Vulnerable? (Defender for Containers + admission control)
- **מה אם** צריך לעדכן את ה-Cluster? (Blue-Green node pool strategy)

---

## Lab 6: The "Backup & DR" Lab - Business Continuity

**Level**: Intermediate | **Duration**: ~2 hours | **Pillars**: Reliability, Manageability

### Goal
הקמת סביבת Backup ו-Disaster Recovery עם Azure Site Recovery (ASR) ו-Azure Backup, כולל בדיקת Failover.

### Step-by-Step

```bash
# Step 1: Create Recovery Services Vault
az group create --name rg-dr-lab --location israelcentral
az group create --name rg-dr-secondary --location westeurope

az backup vault create \
  --resource-group rg-dr-lab \
  --name rsv-backup-lab \
  --location israelcentral

# Set Storage Redundancy to GRS (for DR scenario)
az backup vault backup-properties set \
  --resource-group rg-dr-lab \
  --name rsv-backup-lab \
  --backup-storage-redundancy GeoRedundant

# Step 2: Create Test VM to protect
az vm create \
  --resource-group rg-dr-lab \
  --name vm-to-protect \
  --image Ubuntu2204 \
  --size Standard_D2s_v3 \
  --admin-username azureuser \
  --generate-ssh-keys

# Step 3: Configure Azure Backup for the VM
az backup protection enable-for-vm \
  --resource-group rg-dr-lab \
  --vault-name rsv-backup-lab \
  --vm vm-to-protect \
  --policy-name DefaultPolicy

# Step 4: Trigger manual backup
az backup protection backup-now \
  --resource-group rg-dr-lab \
  --vault-name rsv-backup-lab \
  --container-name $(az backup container show -g rg-dr-lab -v rsv-backup-lab --name "iaasvmcontainer;iaasvmcontainerv2;rg-dr-lab;vm-to-protect" --query name -o tsv) \
  --item-name vm-to-protect \
  --backup-management-type AzureIaasVM \
  --retain-until 15-02-2026

# Step 5: Configure Azure Site Recovery (ASR)
# Create vault in secondary region
az backup vault create \
  --resource-group rg-dr-secondary \
  --name rsv-asr-lab \
  --location westeurope

# Enable Replication (done via Azure Portal or PowerShell - CLI has limited ASR support)
# PowerShell alternative:
# New-AzRecoveryServicesAsrReplicationProtectedItem \
#   -AzureToAzure \
#   -AzureVmId (Get-AzVM -ResourceGroupName rg-dr-lab -Name vm-to-protect).Id \
#   -Name "vm-to-protect-asr" \
#   -ProtectionContainerMapping $mapping \
#   -AzureToAzureDiskReplicationConfiguration $diskConfig \
#   -RecoveryResourceGroupId $targetRGId

# Step 6: Define Backup Policy with Retention
az backup policy set \
  --resource-group rg-dr-lab \
  --vault-name rsv-backup-lab \
  --name EnterprisePolicy \
  --policy '{
    "schedulePolicy": {
      "schedulePolicyType": "SimpleSchedulePolicy",
      "scheduleRunFrequency": "Daily",
      "scheduleRunTimes": ["2026-02-01T22:00:00Z"]
    },
    "retentionPolicy": {
      "retentionPolicyType": "LongTermRetentionPolicy",
      "dailySchedule": {"retentionTimes": ["2026-02-01T22:00:00Z"], "retentionDuration": {"count": 30, "durationType": "Days"}},
      "weeklySchedule": {"daysOfTheWeek": ["Sunday"], "retentionTimes": ["2026-02-01T22:00:00Z"], "retentionDuration": {"count": 12, "durationType": "Weeks"}},
      "monthlySchedule": {"retentionScheduleFormatType": "Weekly", "retentionDuration": {"count": 12, "durationType": "Months"}},
      "yearlySchedule": {"retentionScheduleFormatType": "Weekly", "retentionDuration": {"count": 5, "durationType": "Years"}}
    }
  }'
```

### RPO/RTO Planning Table

| Workload | RPO Target | RTO Target | Solution |
|----------|-----------|-----------|----------|
| Mission Critical DB | < 15 min | < 1 hour | ASR continuous replication |
| Production Web App | < 1 hour | < 4 hours | ASR daily snapshot |
| Dev/Test VMs | < 24 hours | < 8 hours | Azure Backup (daily) |
| Archive Data | < 24 hours | < 48 hours | Geo-Redundant Storage |

### Monitoring KQL
```kql
// Backup Job Status - Last 24 Hours
AddonAzureBackupJobs
| where TimeGenerated > ago(24h)
| where JobOperation == "Backup"
| summarize
    TotalJobs = count(),
    Succeeded = countif(JobStatus == "Completed"),
    Failed = countif(JobStatus == "Failed"),
    InProgress = countif(JobStatus == "InProgress")
  by VaultName
| extend SuccessRate = round(100.0 * Succeeded / TotalJobs, 2)

// ASR Replication Health
AzureActivity
| where OperationNameValue contains "replicationProtectedItems"
| where ActivityStatusValue != "Succeeded"
| project TimeGenerated, OperationNameValue, ActivityStatusValue, Properties
| order by TimeGenerated desc
```

### What-If Questions
- **מה אם** ה-RTO הנדרש הוא 15 דקות? (Hot Standby + ASR with near-sync replication)
- **מה אם** ה-Backup עצמו נפגע (ransomware)? (Soft Delete + Immutable Vault)
- **מה אם** צריך לשחזר קובץ בודד מ-VM? (File-level recovery from Recovery Services Vault)
- **מה אם** ה-Failover Test גרם ל-Production Outage? (Test Failover to isolated VNET - never use production network!)

---

## Lab 7: The "Governance at Scale" Lab - Azure Policy & Management Groups

**Level**: Intermediate-Advanced | **Duration**: ~2 hours | **Pillars**: Manageability, Security

### Goal
הקמת היררכיית Management Groups עם Azure Policy שאוכפת תקני Compliance, כולל Auto-remediation.

### Management Group Hierarchy
```
Tenant Root
└── MG-Enterprise
    ├── MG-Platform
    │   ├── MG-Connectivity (Hub VNETs)
    │   └── MG-Management (Log Analytics, Backup)
    └── MG-LandingZones
        ├── MG-Production
        └── MG-NonProduction
```

### Step-by-Step

```bash
# Step 1: Create Management Group Hierarchy
az account management-group create --name MG-Enterprise --display-name "Enterprise Root"
az account management-group create --name MG-Platform --display-name "Platform" --parent MG-Enterprise
az account management-group create --name MG-LandingZones --display-name "Landing Zones" --parent MG-Enterprise
az account management-group create --name MG-Production --display-name "Production" --parent MG-LandingZones
az account management-group create --name MG-NonProduction --display-name "NonProduction" --parent MG-LandingZones

# Move subscription to appropriate Management Group
az account management-group subscription add \
  --name MG-Production \
  --subscription <subscription-id>

# Step 2: Assign Built-in Policies

# Policy 1: Require tags on all resources
az policy assignment create \
  --name "require-resource-tags" \
  --display-name "Require Environment and CostCenter tags" \
  --policy "/providers/Microsoft.Authorization/policyDefinitions/96670d01-0a4d-4649-9c89-2d3abc0a5025" \
  --scope "/providers/Microsoft.Management/managementGroups/MG-LandingZones" \
  --params '{"tagName": {"value": "Environment"}}' \
  --enforcement-mode DoNotEnforce  # Start with audit, then switch to Deny

# Policy 2: Deny public IP creation in Production
az policy definition create \
  --name "deny-public-ip-prod" \
  --display-name "Deny creation of Public IP in Production" \
  --description "No public IPs allowed in production environment" \
  --rules '{
    "if": {
      "field": "type",
      "equals": "Microsoft.Network/publicIPAddresses"
    },
    "then": {
      "effect": "Deny"
    }
  }' \
  --mode All

az policy assignment create \
  --name "deny-public-ip-prod" \
  --policy "deny-public-ip-prod" \
  --scope "/providers/Microsoft.Management/managementGroups/MG-Production"

# Policy 3: Auto-deploy Log Analytics agent (DeployIfNotExists with remediation)
az policy assignment create \
  --name "deploy-law-agent" \
  --display-name "Deploy Log Analytics agent to VMs" \
  --policy "/providers/Microsoft.Authorization/policyDefinitions/0868462e-646c-4fe3-9ced-a733534b6a2c" \
  --scope "/providers/Microsoft.Management/managementGroups/MG-LandingZones" \
  --identity-scope "/providers/Microsoft.Management/managementGroups/MG-LandingZones" \
  --mi-user-assigned "/subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.ManagedIdentity/userAssignedIdentities/<identity>" \
  --location israelcentral \
  --params "{\"logAnalytics\": {\"value\": \"<law-resource-id>\"}}"

# Step 3: Create Policy Initiative (Blueprint equivalent)
az policy set-definition create \
  --name "enterprise-compliance-initiative" \
  --display-name "Enterprise Compliance Baseline" \
  --description "Set of policies required for all enterprise workloads" \
  --definitions '[
    {"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/0a914e76-4921-4c19-b460-a2d36003525a"},
    {"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8"}
  ]'

# Step 4: Create Remediation Task for non-compliant resources
az policy remediation create \
  --resource-group rg-compliance \
  --policy-assignment /subscriptions/<sub-id>/providers/Microsoft.Authorization/policyAssignments/deploy-law-agent \
  --name remediation-deploy-law-agent
```

### Monitoring KQL
```kql
// Policy Compliance Dashboard
PolicyStates
| where TimeGenerated > ago(1d)
| where PolicyAssignmentName != ""
| summarize
    TotalResources = count(),
    Compliant = countif(ComplianceState == "Compliant"),
    NonCompliant = countif(ComplianceState == "NonCompliant")
  by PolicyDefinitionName
| extend ComplianceRate = round(100.0 * Compliant / TotalResources, 1)
| order by NonCompliant desc

// Resources Created Without Required Tags
AzureActivity
| where OperationNameValue contains "write"
| where ActivityStatusValue == "Succeeded"
| where isempty(Properties.requestBody.tags.Environment)
| project TimeGenerated, Caller, ResourceGroup, Resource = ResourceId
| order by TimeGenerated desc
```

### What-If Questions
- **מה אם** Policy חוסמת פעולה לגיטימית דחופה? (Policy Exemption - time-limited)
- **מה אם** צריך לאכוף Policy על 500 Subscriptions? (Management Group scope)
- **מה אם** Remediation נכשלת? (Check Managed Identity permissions + resource state)

---

## Lab 8: The "Defender for Cloud" Lab - Security Posture Management

**Level**: Advanced | **Duration**: ~2 hours | **Pillars**: Security, Manageability

### Goal
הפעלת Microsoft Defender for Cloud, שיפור ה-Secure Score, וחקירת Security Recommendations.

### Step-by-Step

```bash
# Step 1: Enable Defender for Cloud (Standard tier) on subscription
az security auto-provisioning-setting update \
  --auto-provision On \
  --name mma

# Enable Defender plans for key services
for plan in VirtualMachines AppServices SqlServers Containers KeyVaults Arm; do
  az security pricing create \
    --name "$plan" \
    --tier Standard
done

# Step 2: Configure Security Contact
az security contact create \
  --name "security-contact" \
  --email "security-team@company.com" \
  --phone "+972-XX-XXXXXXX" \
  --alert-severity High \
  --alerts-admins On

# Step 3: Enable Continuous Export to Log Analytics
az security automation create \
  --resource-group rg-security \
  --name "export-to-law" \
  --location israelcentral \
  --scopes "[{\"description\": \"Subscription scope\", \"scopePath\": \"/subscriptions/<sub-id>\"}]" \
  --sources "[{\"eventSource\": \"Alerts\"}, {\"eventSource\": \"Assessments\"}]" \
  --actions "[{\"actionType\": \"Workspace\", \"workspaceResourceId\": \"<law-id>\"}]"

# Step 4: Investigate and Remediate Top Recommendations
# View current recommendations
az security assessment list --query "[?status.code!='Healthy']" -o table

# Example: Enable Just-in-Time VM Access
az security jit-policy create \
  --resource-group rg-security \
  --location israelcentral \
  --name JIT-Policy \
  --virtual-machines "[{
    \"id\": \"<vm-id>\",
    \"ports\": [
      {\"number\": 22, \"protocol\": \"TCP\", \"allowedSourceAddressPrefix\": \"*\", \"maxRequestAccessDuration\": \"PT3H\"},
      {\"number\": 3389, \"protocol\": \"TCP\", \"allowedSourceAddressPrefix\": \"*\", \"maxRequestAccessDuration\": \"PT3H\"}
    ]
  }]"

# Request JIT access when needed
az security jit-policy initiate \
  --resource-group rg-security \
  --location israelcentral \
  --name JIT-Policy \
  --virtual-machines "[{
    \"id\": \"<vm-id>\",
    \"ports\": [{\"number\": 22, \"duration\": \"PT1H\", \"allowedSourceAddressPrefix\": \"<your-ip>\"}]
  }]"

# Step 5: Set up Regulatory Compliance Dashboard
az security regulatory-compliance-standards list -o table
# Assign specific standards (PCI-DSS, ISO 27001, etc.) through Azure Portal
```

### Secure Score Improvement Checklist

```
Priority 1 (Quick Wins - High Impact):
[ ] Enable MFA for all admin accounts
[ ] Enable JIT VM access (removes management ports from internet)
[ ] Enable Azure Defender for VMs
[ ] Apply system updates to VMs
[ ] Remediate vulnerabilities found by Qualys (built into Defender)

Priority 2 (Medium Effort):
[ ] Encrypt all disks with CMK (Customer Managed Keys)
[ ] Enable disk encryption on all VMs
[ ] Restrict access to storage accounts (remove public access)
[ ] Enable audit logging on SQL servers
[ ] Enable network security groups on all subnets

Priority 3 (Architecture Changes):
[ ] Implement Private Endpoints for all PaaS services
[ ] Migrate to Managed Identities (remove stored credentials)
[ ] Enable Azure DDoS Protection Standard
```

### Monitoring KQL
```kql
// Secure Score History
SecurityRegulatoryCompliance
| where TimeGenerated > ago(30d)
| summarize AvgScore = avg(PassedControls * 100.0 / (PassedControls + FailedControls)) by bin(TimeGenerated, 1d)
| render timechart

// High Severity Security Alerts
SecurityAlert
| where TimeGenerated > ago(24h)
| where AlertSeverity in ("High", "Critical")
| project TimeGenerated, AlertName, AlertSeverity, Description, RemediationSteps
| order by TimeGenerated desc

// Defender for Cloud Recommendations - Non-Healthy
SecurityRecommendation
| where RecommendationState == "Unhealthy"
| summarize count() by RecommendationDisplayName, RecommendationSeverity
| order by RecommendationSeverity asc, count_ desc
```

### What-If Questions
- **מה אם** Secure Score ירד פתאום? (Check new resources not following policies)
- **מה אם** False Positive Alert מ-Defender? (Suppress rule + feedback to Microsoft)
- **מה אם** לקוח ממשלתי דורש ISO 27001 Compliance? (Regulatory Compliance dashboard + remediation)

---

## Lab 9: The "Serverless Integration" Lab - Logic Apps & Function Apps

**Level**: Intermediate | **Duration**: ~2 hours | **Pillars**: Reliability, Manageability, Cost

### Goal
בניית Pipeline אוטומטי: Azure Monitor Alert → Logic App → Function App → Slack/Teams Notification עם enrichment data.

### Architecture Diagram
```
Azure Monitor Alert (Metric or Log-based)
         │
         ▼
    Action Group
         │ HTTP Webhook
         ▼
    Logic App (Orchestrator)
    ├── Parse Alert JSON
    ├── Enrich data (Resource details)
    ├── Call Function App (Custom logic)
    └── Send Teams notification
         │
         ▼
    Function App (Business Logic)
    ├── Determine severity
    ├── Look up on-call schedule
    └── Return enriched payload
```

### Step-by-Step

```bash
# Step 1: Create Function App
az group create --name rg-serverless-lab --location israelcentral

az storage account create \
  --resource-group rg-serverless-lab \
  --name stserverlesslab$(date +%s) \
  --sku Standard_LRS

az functionapp create \
  --resource-group rg-serverless-lab \
  --consumption-plan-location israelcentral \
  --runtime python \
  --runtime-version 3.11 \
  --functions-version 4 \
  --name func-alert-enricher \
  --storage-account <storage-account-name> \
  --os-type Linux

# Deploy sample function code
mkdir alert-function && cd alert-function

cat > __init__.py << 'EOF'
import azure.functions as func
import json
import logging

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Alert enricher function triggered')

    try:
        alert_data = req.get_json()
    except ValueError:
        return func.HttpResponse("Invalid JSON", status_code=400)

    # Business logic: determine severity and on-call
    severity = alert_data.get('data', {}).get('essentials', {}).get('severity', 'Unknown')
    resource = alert_data.get('data', {}).get('essentials', {}).get('alertTargetIDs', ['Unknown'])[0]

    # On-call rotation logic (simplified)
    on_call_map = {
        'Sev0': 'oncall-primary@company.com',
        'Sev1': 'oncall-secondary@company.com',
        'Sev2': 'team@company.com'
    }

    enriched_response = {
        'original_severity': severity,
        'on_call_contact': on_call_map.get(severity, 'team@company.com'),
        'resource_id': resource,
        'dashboard_url': f'https://portal.azure.com/#resource{resource}/overview',
        'runbook_url': f'https://wiki.company.com/runbooks/{severity.lower()}'
    }

    return func.HttpResponse(
        json.dumps(enriched_response),
        status_code=200,
        mimetype="application/json"
    )
EOF

# Step 2: Create Logic App (Standard)
az logicapp create \
  --resource-group rg-serverless-lab \
  --name lapp-alert-handler \
  --storage-account <storage-account-name> \
  --plan $(az appservice plan create -g rg-serverless-lab -n asp-logic --sku WS1 --query id -o tsv)

# Step 3: Create Action Group pointing to Logic App
LOGIC_APP_URL=$(az logicapp show -g rg-serverless-lab -n lapp-alert-handler --query "properties.endpointConfiguration.workflow.accessEndpoint" -o tsv)

az monitor action-group create \
  --resource-group rg-serverless-lab \
  --name ag-serverless-demo \
  --short-name ServerlessDm \
  --webhook-receiver \
    name="LogicAppWebhook" \
    service-uri="$LOGIC_APP_URL/api/alert-trigger" \
    use-aad-auth false

# Step 4: Create Test Alert Rule
az monitor metrics alert create \
  --resource-group rg-serverless-lab \
  --name "high-cpu-alert" \
  --scopes $(az vm show -g <vm-rg> -n <vm-name> --query id -o tsv) \
  --condition "avg Percentage CPU > 80" \
  --window-size 5m \
  --evaluation-frequency 1m \
  --action $(az monitor action-group show -g rg-serverless-lab -n ag-serverless-demo --query id -o tsv) \
  --severity 2 \
  --description "CPU over 80% for 5 minutes"
```

### Logic App Workflow (JSON Definition)
```json
{
  "definition": {
    "triggers": {
      "When_an_HTTP_request_is_received": {
        "type": "Request",
        "kind": "Http"
      }
    },
    "actions": {
      "Parse_Alert_JSON": {
        "type": "ParseJson",
        "inputs": {
          "content": "@triggerBody()",
          "schema": {}
        }
      },
      "Call_Function_App": {
        "type": "Http",
        "inputs": {
          "method": "POST",
          "uri": "https://func-alert-enricher.azurewebsites.net/api/enrich",
          "body": "@body('Parse_Alert_JSON')"
        }
      },
      "Send_Teams_Notification": {
        "type": "Http",
        "inputs": {
          "method": "POST",
          "uri": "@parameters('teams_webhook_url')",
          "body": {
            "@type": "MessageCard",
            "text": "🚨 Alert: @{body('Parse_Alert_JSON')?['data']?['essentials']?['alertRule']}",
            "sections": [{
              "facts": [
                {"name": "Severity", "value": "@{body('Call_Function_App')?['original_severity']}"},
                {"name": "On-Call", "value": "@{body('Call_Function_App')?['on_call_contact']}"},
                {"name": "Runbook", "value": "@{body('Call_Function_App')?['runbook_url']}"}
              ]
            }]
          }
        }
      }
    }
  }
}
```

### Monitoring KQL
```kql
// Logic App Run History - Failed Runs
AzureDiagnostics
| where ResourceType == "WORKFLOWS" and Category == "WorkflowRuntime"
| where status_s == "Failed"
| project TimeGenerated, resource_runId_s, startTime_t, endTime_t, error_message_s
| order by TimeGenerated desc

// Function App Exceptions
exceptions
| where timestamp > ago(24h)
| where cloud_RoleName == "func-alert-enricher"
| summarize count() by type, outerMessage
| order by count_ desc
```

### What-If Questions
- **מה אם** ה-Function App לא זמין בזמן Alert? (Retry policy in Logic App + Dead Letter queue)
- **מה אם** יש עלויות גבוהות מ-Logic App? (Standard tier vs Consumption - trade-offs)
- **מה אם** ה-Alert מופעל 1000 פעם בשעה? (Alert deduplication + suppression rules)

---

## Lab 10: The "Full Stack Observability" Lab - Azure Workbook & Dashboard

**Level**: Intermediate | **Duration**: ~2 hours | **Pillars**: Monitoring, Manageability, Reliability

### Goal
בניית Azure Workbook מקיף שמציג Health מלא של מערכת Production ב-Real-time, כולל Availability, Performance, Security, ו-Cost.

### Workbook Structure

```
┌─────────────────────────────────────────────────────────┐
│           PRODUCTION HEALTH DASHBOARD                    │
├─────────────────────────────────────────────────────────┤
│  Overview Strip                                          │
│  [Availability: 99.8%] [Error Rate: 0.2%] [P95: 180ms] │
│  [Active Alerts: 3]    [Secure Score: 82%] [Cost: $12k] │
├─────────────────────────────────────────────────────────┤
│  Tab 1: Availability & Performance                       │
│  ┌────────────────┐  ┌──────────────────────┐          │
│  │ Success Rate   │  │  Response Time Chart │          │
│  │ (Last 24h)     │  │  P50 / P95 / P99     │          │
│  └────────────────┘  └──────────────────────┘          │
├─────────────────────────────────────────────────────────┤
│  Tab 2: Infrastructure Health                            │
│  ┌─────────────────────────────────────────┐           │
│  │ VM Grid: Name | CPU | Memory | Disk | Status│       │
│  └─────────────────────────────────────────┘           │
├─────────────────────────────────────────────────────────┤
│  Tab 3: Security Events                                  │
│  ┌────────────────┐  ┌──────────────────────┐          │
│  │Failed Logins   │  │ Alert Timeline       │          │
│  │ by IP/User     │  │ by Severity          │          │
│  └────────────────┘  └──────────────────────┘          │
└─────────────────────────────────────────────────────────┘
```

### Step-by-Step (Workbook Queries)

```bash
# Step 1: Create Workbook via Azure CLI (or Portal)
az group create --name rg-monitoring-lab --location israelcentral

# Workbooks are best created via Portal or ARM template
# Below is the ARM template approach:
cat > workbook-template.json << 'TEMPLATE'
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [{
    "type": "microsoft.insights/workbooks",
    "apiVersion": "2022-04-01",
    "name": "[newGuid()]",
    "location": "israelcentral",
    "kind": "shared",
    "properties": {
      "displayName": "Production Health Dashboard",
      "category": "workbook",
      "sourceId": "[resourceId('microsoft.operationalinsights/workspaces', 'law-production')]",
      "serializedData": "..."
    }
  }]
}
TEMPLATE

az deployment group create \
  --resource-group rg-monitoring-lab \
  --template-file workbook-template.json
```

### Tab 1: Availability & Performance Queries

```kql
// Overall Availability Rate (Last 24 hours)
requests
| where timestamp > ago(24h)
| summarize
    TotalRequests = count(),
    SuccessRequests = countif(success == true),
    FailedRequests = countif(success == false)
| extend AvailabilityRate = round(100.0 * SuccessRequests / TotalRequests, 2)

// Response Time Percentiles - Timechart
requests
| where timestamp > ago(24h)
| summarize
    P50 = percentile(duration, 50),
    P95 = percentile(duration, 95),
    P99 = percentile(duration, 99)
  by bin(timestamp, 15m)
| render timechart

// Error Rate by Operation
requests
| where timestamp > ago(24h)
| where success == false
| summarize ErrorCount = count() by name, resultCode
| order by ErrorCount desc
| take 10
```

### Tab 2: Infrastructure Health Queries

```kql
// VM Performance Grid
Perf
| where TimeGenerated > ago(30m)
| where ObjectName in ("Processor", "Memory", "LogicalDisk")
| where CounterName in ("% Processor Time", "% Used Memory", "% Free Space")
| summarize AvgValue = avg(CounterValue) by Computer, CounterName
| evaluate pivot(CounterName, avg(AvgValue))
| extend CPUStatus = iff(['% Processor Time'] > 90, "Critical", iff(['% Processor Time'] > 70, "Warning", "Healthy"))
| project Computer, CPU = round(['% Processor Time'], 1), Memory = round(['% Used Memory'], 1), CPUStatus

// Active Alerts by Severity
AlertsManagementResources
| where type == "microsoft.alertsmanagement/alerts"
| where properties.essentials.alertState == "New"
| extend Severity = tostring(properties.essentials.severity)
| summarize ActiveAlerts = count() by Severity
| order by Severity asc

// Resource Health Status
HealthResources
| where type == "microsoft.resourcehealth/availabilitystatuses"
| extend HealthStatus = tostring(properties.availabilityState)
| summarize count() by HealthStatus, type
```

### Tab 3: Security Events Queries

```kql
// Failed Login Heatmap
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != "0"
| summarize FailedAttempts = count() by UserPrincipalName, bin(TimeGenerated, 1h)
| render heatmap

// Security Alert Timeline
SecurityAlert
| where TimeGenerated > ago(7d)
| project TimeGenerated, AlertName, AlertSeverity, CompromisedEntity
| order by TimeGenerated desc
| take 20

// Top Source IPs for Failed Logins
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != "0"
| summarize FailedCount = count() by IPAddress, Location
| order by FailedCount desc
| take 10
```

### Tab 4: Cost Optimization Queries

```kql
// Resource Cost by Service (requires Cost Management tables)
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue contains "write"
| summarize ResourceChanges = count() by ResourceType, ResourceGroup
| order by ResourceChanges desc

// Unused Resources Detection
Heartbeat
| where TimeGenerated > ago(24h)
| summarize LastSeen = max(TimeGenerated) by Computer
| where LastSeen < ago(72h)
| project Computer, LastSeen, DaysSinceLastSeen = datetime_diff('hour', now(), LastSeen) / 24
| order by DaysSinceLastSeen desc
```

### Advanced Workbook Features

```bash
# Create Alert Rule directly from Workbook query
az monitor scheduled-query create \
  --resource-group rg-monitoring-lab \
  --name "availability-drop-alert" \
  --scopes $(az monitor log-analytics workspace show -g rg-monitoring-lab -n law-production --query id -o tsv) \
  --condition-query "requests | where timestamp > ago(5m) | summarize AvailRate = 100.0 * countif(success==true) / count() | where AvailRate < 99" \
  --condition-time-aggregation Count \
  --condition-threshold 0 \
  --condition-operator GreaterThan \
  --evaluation-frequency 5m \
  --window-size 5m \
  --severity 1 \
  --description "Availability dropped below 99% threshold"

# Create Azure Dashboard from Workbook
# (Done via Azure Portal - Pin tiles from Workbook to Dashboard)
```

### Monitoring KQL (Meta - Monitoring the Monitor)
```kql
// Log Analytics Workspace Health
Usage
| where TimeGenerated > ago(7d)
| summarize IngestionGB = sum(Quantity) / 1024 by DataType, bin(TimeGenerated, 1d)
| render columnchart

// Alert Processing Latency
AlertsManagementResources
| where type == "microsoft.alertsmanagement/alerts"
| extend FiredTime = todatetime(properties.essentials.startDateTime)
| extend AcknowledgedTime = todatetime(properties.essentials.lastModifiedDateTime)
| extend ProcessingLatency = AcknowledgedTime - FiredTime
| summarize avg(ProcessingLatency) by tostring(properties.essentials.severity)
```

### What-If Questions
- **מה אם** הנתונים ב-Dashboard מתעדכנים לאט מדי? (Reduce auto-refresh interval)
- **מה אם** ה-Workbook צריך להציג נתונים מ-5 Subscriptions שונים? (Cross-workspace queries)
- **מה אם** Executive רוצה Dashboard פשוט יותר? (Create separate Executive Dashboard with aggregated KPIs)
- **מה אם** ה-Log Analytics Workspace מגיע ל-Daily Cap? (Alert on ingestion + review verbose logging sources)

---

## Summary - Labs Completion Tracker

| Lab | Topic | Level | Duration | WAF Pillars |
|-----|-------|-------|----------|-------------|
| 1 | Zero Trust - Private Endpoints | Advanced | 3h | Security, Reliability |
| 2 | Multi-Region with Front Door | Advanced | 2.5h | Reliability, Performance |
| 3 | KQL Security Detection | Advanced | 2h | Security, Monitoring |
| 4 | Hub & Spoke Networking | Advanced | 3h | Security, Reliability |
| 5 | AKS Zero Trust | Expert | 4h | Security, Reliability |
| 6 | Backup & Disaster Recovery | Intermediate | 2h | Reliability, Manageability |
| 7 | Governance & Azure Policy | Intermediate | 2h | Manageability, Security |
| 8 | Defender for Cloud | Advanced | 2h | Security, Manageability |
| 9 | Serverless Integration | Intermediate | 2h | Reliability, Cost |
| 10 | Full Stack Observability | Intermediate | 2h | Monitoring, Manageability |

### Recommended Completion Order
```
Week 1-2: Labs 4 → 1 → 2  (Networking foundation + Security)
Week 3-4: Labs 5 → 6 → 7  (PaaS + Reliability + Governance)
Week 5-6: Labs 8 → 3 → 9  (Security posture + KQL + Automation)
Week 7:   Lab 10           (Bring it all together - Observability)
```

---

*Last Updated: 2026-02-26*
*Target Role: Azure Customer Engineer / Architect - Microsoft Israel*
*Branch: claude/azure-interview-prep-aUKHp*
