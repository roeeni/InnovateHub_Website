# Azure Customer Engineer / Architect - Interview Preparation Plan
## Microsoft Israel | Security Cleared Path

---

## Custom AI Mentor Instructions

### Context (Who You Are)
> Use this as context when working with any AI assistant during your preparation.

"אני מתכונן למשרה בכירה ב-Microsoft Israel בתפקיד Azure Customer Engineer / Architect.
התפקיד דורש מומחיות עמוקה ב-Azure IaaS (Networking, Storage, Compute) וב-PaaS (AKS, App Services).
העבודה שלי מתמקדת בלקוחות אסטרטגיים עם דרישות אבטחה מחמירות (Security Clearance).

העקרונות המנחים שלי הם:
- Reliability
- Security
- Supportability
- Manageability
- Monitoring and Observability

אני צריך שתשמש כמנטור טכני בכיר ממחלקת ה-CxP (Customer Experience) של מייקרוסופט, שעוזר לי להתכונן לראיונות, לבנות מעבדות מורכבות, לנתח תקלות (RCAs) וללמוד איך לנהל קשרים אסטרטגיים עם לקוחות ו-CSAMs."

### Response Style (How the Mentor Should Respond)
> Instruct any AI assistant to respond in this style.

"בתשובות שלך, הקפד על הדברים הבאים:

1. **חשיבה ארכיטקטונית**: בכל פתרון טכני שאתה מציע, התייחס תמיד ל-5 עמודי התווך של ה-Well-Architected Framework (WAF).

2. **דגש על Monitoring**: כשאתה מסביר על שירות ב-Azure, ציין תמיד:
   - איך מנטרים אותו
   - אילו Metrics חשובים
   - איך נראית שאילתת ה-KQL הרלוונטית ב-Log Analytics

3. **פתרון בעיות (Troubleshooting)**: כשנשאל על תקלה, הנחה אותי בשיטה של 'צמצום מרחב הבעיה' (Isolation) והצג איך מגיעים ל-Root Cause.

4. **שפה מקצועית**: השתמש במושגים של Microsoft (כמו CxP, CSAM, RCA, KnowMe, Unified Support).

5. **תרגול מעשי**: כשאתה מציע מעבדה, בנה אותה בשלבים (Step-by-Step) וכלול שאלות 'מה אם?' כדי לבחון את ההבנה שלי.

6. **אבטחת מידע**: תמיד תן עדיפות ל:
   - גישת Zero Trust
   - שימוש ב-Private Endpoints
   - ניהול זהויות מבוסס RBAC ו-Managed Identities

7. **איזון טכני-עסקי**: עזור לי לתרגם פתרונות טכניים מורכבים לשפה עסקית שמתאימה למנהלים (Executives)."

---

## 🚀 Job Preparation Plan: Azure Cloud Excellence (Security Cleared Path)

### 📌 Overview

תוכנית זו נועדה להכשיר אותך מקצה לקצה עבור משרת Azure מורכבת, תוך התמקדות ב-5 עמודי התווך:

| עמוד | תיאור |
|------|--------|
| **Reliability** | זמינות גבוהה, DR, Failover |
| **Security** | Zero Trust, RBAC, Private Endpoints |
| **Supportability** | יכולת תמיכה ועבודה עם CxP |
| **Manageability** | Policy, Governance, Automation |
| **Monitoring & Observability** | Alerts, KQL, Dashboards |

---

## 🛠 Phase 1: The Foundations (The "Well-Architected" Mindset)

**המטרה**: להבין לא רק איך בונים, אלא איך בונים נכון לפי הסטנדרטים של Microsoft.

### Tasks
- [ ] לימוד ה-Azure Well-Architected Framework (WAF): התמקדות ב-5 ה-Pillars
- [ ] Governance & Hierarchy: ניהול Management Groups, Subscriptions, ו-Azure Policy
- [ ] תרגיל: בנה סביבה שבה לא ניתן להקים VM ללא Tagging ספציפי וללא חיבור ל-Log Analytics

### Key Concepts
- Management Group Hierarchy
- Azure Policy (Deny, Audit, DeployIfNotExists)
- Initiative Definitions (Blueprints)
- Landing Zone Architecture

### WAF Pillars Deep Dive

```
Cost Optimization ─────────┐
Operational Excellence ────┤
Performance Efficiency ────┼──► Well-Architected Review Score
Reliability ───────────────┤
Security ──────────────────┘
```

### Relevant KQL - Policy Compliance Check
```kql
PolicyStates
| where ComplianceState == "NonCompliant"
| summarize count() by PolicyDefinitionName, ResourceType
| order by count_ desc
```

---

## 🏗 Phase 2: Deep Dive IaaS & Networking (Core Requirement)

**המטרה**: שליטה מוחלטת בתשתית (Compute, Storage, Network).

### 2.1 Networking
- [ ] תכנון VNET Peering, Hub & Spoke Architecture
- [ ] עבודה עם Azure Firewall, NSGs, ו-Application Gateway (WAF)
- [ ] **Lab**: הקמת Hub & Spoke עם VPN Gateway ו-Firewall שמרכז את כל ה-Traffic

#### Hub & Spoke Architecture
```
                    ┌─────────────────┐
                    │   HUB VNET      │
                    │  10.0.0.0/16    │
                    │                 │
                    │  ┌───────────┐  │
          ┌─────────┤  │  Azure    │  ├─────────┐
          │         │  │ Firewall  │  │         │
          │         │  └───────────┘  │         │
          │         │  ┌───────────┐  │         │
          │         │  │   VPN GW  │  │         │
          │         │  └───────────┘  │         │
          │         └─────────────────┘         │
          │                                     │
   ┌──────┴──────┐                    ┌──────┴──────┐
   │  SPOKE 1    │                    │  SPOKE 2    │
   │ 10.1.0.0/16 │                    │ 10.2.0.0/16 │
   │  (Prod)     │                    │  (Dev)      │
   └─────────────┘                    └─────────────┘
```

#### Networking KQL - Firewall Logs
```kql
AzureDiagnostics
| where Category == "AzureFirewallNetworkRule"
| where Action_s == "Deny"
| summarize count() by SourceIP_s, DestinationIP_s, DestinationPort_d
| order by count_ desc
| take 20
```

#### "What If" Questions
- **מה אם** שני ה-Spokes צריכים לתקשר ישירות? (Transitive Routing problem)
- **מה אם** ה-Firewall עצמו נפל? איך מגנים עליו? (Active-Active AZFW)
- **מה אם** לקוח צריך לגשת ממשרד On-Premises? (VPN vs ExpressRoute)

### 2.2 Compute & High Availability
- [ ] הגדרת Virtual Machine Scale Sets (VMSS)
- [ ] מימוש Disaster Recovery (ASR) ו-Azure Backup

#### DR - RPO vs RTO Matrix
| Scenario | RPO | RTO | Solution |
|----------|-----|-----|----------|
| Critical Workload | < 1hr | < 4hr | ASR + Hot Standby |
| Standard Workload | < 4hr | < 8hr | ASR + Warm Standby |
| Dev/Test | < 24hr | < 24hr | Azure Backup only |

#### Backup KQL - Monitor Backup Jobs
```kql
AddonAzureBackupJobs
| where JobOperation == "Backup"
| where JobStatus != "Completed"
| project TimeGenerated, JobStatus, BackupItemUniqueId, ErrorCode
| order by TimeGenerated desc
```

### 2.3 Storage
- [ ] הבדלים בין Blob, Files, ו-Disks
- [ ] דגש על Redundancy: LRS vs ZRS vs GRS vs GZRS

| Redundancy | Copies | Durability | Use Case |
|------------|--------|------------|----------|
| LRS | 3 (same DC) | 11 nines | Dev/Test |
| ZRS | 3 (diff zones) | 12 nines | Prod (same region) |
| GRS | 6 (2 regions) | 16 nines | DR |
| GZRS | 6 (zones+regions) | 16 nines | Mission Critical |

---

## ☸️ Phase 3: Modern Apps & PaaS (The "Preferred" Skills)

**המטרה**: להוכיח יכולת תמיכה באפליקציות מודרניות.

### 3.1 Containers & AKS
- [ ] הקמת Cluster של AKS (Azure Kubernetes Service)
- [ ] הבנת ה-Networking של AKS: Azure CNI vs Kubenet

#### AKS Networking Comparison
| Feature | Kubenet | Azure CNI |
|---------|---------|-----------|
| IP per Pod | NAT'd | Dedicated VNET IP |
| Network Policies | Limited | Full support |
| Performance | Good | Better |
| Scale | Up to 400 nodes | Up to 1000 nodes |
| Use Case | Dev/Small | Enterprise/Prod |

#### AKS Security Checklist (Zero Trust)
- [ ] Private Cluster (no public API server)
- [ ] Azure AD integration + RBAC
- [ ] Azure Policy for AKS (OPA Gatekeeper)
- [ ] Container Registry with Private Endpoint
- [ ] Secrets via Key Vault (CSI Driver)
- [ ] Network Policies enforced
- [ ] Image scanning with Defender for Containers

#### AKS KQL - Node & Pod Health
```kql
KubePodInventory
| where ClusterName == "your-cluster-name"
| where PodStatus != "Running"
| summarize count() by PodStatus, Namespace, Name
| order by count_ desc
```

### 3.2 Serverless
- [ ] בניית Logic App שמתממשקת עם Function App

### 3.3 Security & Identity
- [ ] שימוש ב-Managed Identity (במקום סיסמאות)
- [ ] ניהול סודות ב-Azure Key Vault
- [ ] הבנה עמוקה של RBAC

#### Identity Flow - Zero Trust
```
Application
    │
    ▼
Managed Identity (System or User Assigned)
    │
    ▼
Azure AD Token
    │
    ▼
Key Vault (RBAC: Key Vault Secrets User)
    │
    ▼
Secret Retrieved (NO password in code!)
```

#### RBAC Principle of Least Privilege
```
Owner          ─── Full access (Emergency only)
Contributor    ─── Manage resources (No RBAC changes)
Reader         ─── View only
Custom Role    ─── Exactly what's needed (Preferred!)
```

---

## 📉 Phase 4: Monitoring & Incident Resolution (The "Meat" of the Job)

**המטרה**: להפוך למומחה ב-Observability ופתרון תקלות.

### 4.1 KQL (Kusto Query Language)
**זוהי השפה הכי חשובה ב-Azure. עליך לדעת לשלוף לוגים מ-Log Analytics.**

#### Essential KQL Patterns

**1. Exception Tracking**
```kql
exceptions
| where timestamp > ago(1h)
| summarize count() by type, outerMessage
| order by count_ desc
```

**2. Performance Degradation Detection**
```kql
requests
| where timestamp > ago(4h)
| summarize p50=percentile(duration, 50), p95=percentile(duration, 95), p99=percentile(duration, 99) by bin(timestamp, 5m)
| render timechart
```

**3. Failed Login / Brute Force Detection**
```kql
SigninLogs
| where ResultType != "0"
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 5
| order by FailedAttempts desc
```

**4. VM CPU/Memory Alert**
```kql
Perf
| where ObjectName == "Processor"
| where CounterName == "% Processor Time"
| where CounterValue > 90
| summarize AvgCPU = avg(CounterValue) by Computer, bin(TimeGenerated, 5m)
| order by AvgCPU desc
```

**5. Network Latency Between VMs**
```kql
VMConnection
| where TimeGenerated > ago(1h)
| where RemoteIp != ""
| summarize AvgLatency = avg(ResponseTimeMs), MaxLatency = max(ResponseTimeMs) by Computer, RemoteIp
| where AvgLatency > 100
| order by AvgLatency desc
```

### 4.2 Azure Monitor & Insights
- [ ] הגדרת Alerts מבוססי Metric ו-Log
- [ ] Action Groups: Email, SMS, Webhook, Logic App

#### Alert Severity Matrix
| Severity | Meaning | Response Time |
|----------|---------|---------------|
| Sev 0 | Critical - Production Down | Immediate |
| Sev 1 | High - Major Impact | < 1 hour |
| Sev 2 | Medium - Partial Impact | < 4 hours |
| Sev 3 | Low - Minor Impact | < 1 business day |
| Sev 4 | Informational | Scheduled |

### 4.3 RCA Practice (Root Cause Analysis)

**תרגיל סימולציה: "האתר למטה"**

#### Isolation Methodology (מרחב הבעיה)

```
Incident Reported: Website Down
           │
           ▼
    ┌──────────────┐
    │ Layer 1:     │── DNS resolving? ──► nslookup / dig
    │ DNS & Network│── Route reachable? ──► traceroute / Network Watcher
    └──────┬───────┘
           │ Network OK
           ▼
    ┌──────────────┐
    │ Layer 2:     │── Load Balancer healthy? ──► Azure Monitor Metrics
    │ Infra Layer  │── VM/App Service running? ──► Resource Health
    └──────┬───────┘
           │ Infra OK
           ▼
    ┌──────────────┐
    │ Layer 3:     │── App exceptions? ──► App Insights / KQL
    │ Application  │── Response codes? ──► requests table
    └──────┬───────┘
           │ App OK
           ▼
    ┌──────────────┐
    │ Layer 4:     │── DB connection? ──► Connection strings / Firewall
    │ Database     │── Query timeouts? ──► Query Performance Insight
    └──────────────┘
```

#### RCA KQL Workflow
```kql
// Step 1: What happened and when?
AppServiceHTTPLogs
| where TimeGenerated > ago(2h)
| summarize Requests = count(), Errors = countif(ScStatus >= 500) by bin(TimeGenerated, 1m)
| render timechart

// Step 2: Which specific errors?
AppServiceHTTPLogs
| where ScStatus >= 500
| where TimeGenerated > ago(2h)
| summarize count() by ScStatus, CsUriStem
| order by count_ desc

// Step 3: App-level exceptions at same time?
exceptions
| where timestamp > ago(2h)
| summarize count() by type, outerMessage, bin(timestamp, 1m)
| order by timestamp desc
```

### 4.4 Dashboarding
- [ ] יצירת Azure Workbook שמציג את ה-Health של המערכת ב-Real-time

#### Recommended Workbook Tiles
1. **Availability Rate** - % של Successful requests
2. **Error Rate Trend** - Timechart של Sev 4xx/5xx
3. **P95 Latency** - Response time percentile
4. **Active Alerts** - Current open alerts by severity
5. **Resource Health** - VM/App status grid
6. **Security Events** - Failed logins / anomalies

---

## 🤝 Phase 5: Soft Skills & Strategy

**המטרה**: לדעת לדבר עם מנהלים (CSAM) ולקוחות.

### 5.1 Role Understanding

| Role | Responsibility | Who They Talk To |
|------|---------------|-----------------|
| **CSAM** | Customer Success Account Manager | C-Level, Business |
| **CE (Customer Engineer)** | Deep technical support & guidance | IT Teams, Architects |
| **CxP Engineer** | Internal escalation, Product feedback | Engineering Teams |
| **Support Engineer** | Incident resolution | IT Operations |

### 5.2 STAR Method Stories

Prepare detailed answers for these scenarios:

#### Scenario 1: Critical Incident Under Pressure
```
Situation: Production down, 3AM, customer losing $50k/hour
Task: Diagnose and resolve within SLA
Action: [Your RCA process, team coordination, communication]
Result: Restored in X minutes, root cause found, prevention plan delivered
```

#### Scenario 2: Angry Customer
```
Situation: Customer frustrated after 3rd recurrence of same issue
Task: Restore trust, provide permanent solution
Action: Acknowledged impact, escalated internally, presented RCA + Prevention Plan
Result: Customer signed 3-year expansion deal
```

#### Scenario 3: Technical Change Leadership
```
Situation: Customer running legacy on-prem SQL, facing compliance risk
Task: Migrate to Azure SQL with zero downtime
Action: Designed migration plan, ran PoC, trained their team
Result: Migration completed, 40% cost reduction, passed compliance audit
```

### 5.3 Executive Communication

#### Translating Technical → Business

| Technical | Business Language |
|-----------|------------------|
| "RTO is 4 hours" | "We can resume operations within half a workday" |
| "GRS Redundancy" | "Your data is protected in two geographic locations" |
| "RBAC enforced" | "Only authorized personnel can access sensitive systems" |
| "P99 latency < 200ms" | "99% of customers experience fast response times" |
| "Zero Trust model" | "We verify every access request, even from inside the network" |

---

## 🧪 Labs to Complete

### Lab 1: The "Zero Trust" Lab
**Goal**: הקמת סביבה מאובטחת ללא גישה ציבורית (Private Endpoints בלבד)

```
Steps:
1. Create VNET with 3 subnets (app, data, management)
2. Deploy App Service with VNET Integration
3. Deploy Azure SQL with Private Endpoint
4. Deploy Key Vault with Private Endpoint
5. Configure Private DNS Zones for each service
6. Assign Managed Identity to App Service
7. Grant Key Vault Secrets User role to Managed Identity
8. Disable all public access
9. Validate: access only from within VNET

What-If Questions:
- What if the app needs to call an external API?
- What if a developer needs to debug the database?
- What if compliance requires audit logs of all data access?
```

### Lab 2: The "Resilient App" Lab
**Goal**: פריסת אפליקציה בשני Regions עם Traffic Manager או Front Door

```
Steps:
1. Deploy App Service in Israel Central + West Europe
2. Configure Azure Front Door with health probes
3. Set priority routing (Israel primary, EU secondary)
4. Simulate region failure → validate auto-failover
5. Add WAF policy to Front Door
6. Configure geo-filtering rules

What-If Questions:
- What if you need session affinity?
- What if the failover is too slow for your RTO?
- What is the difference between Traffic Manager and Front Door?
```

### Lab 3: The "KQL Ninja" Lab
**Goal**: כתיבת שאילתות שמזהות ניסיונות Brute Force ב-Sign-in logs

```
Steps:
1. Enable Microsoft Sentinel (or Log Analytics)
2. Connect Azure AD Sign-in logs
3. Write KQL to detect:
   a. > 5 failed logins within 5 minutes from same IP
   b. Login from impossible location (country jump)
   c. First-time access to sensitive resource
4. Create Alert Rule from each KQL
5. Configure Action Group → Teams notification

KQL for Brute Force Detection:
```
```kql
SigninLogs
| where ResultType != "0"  // Failed logins
| summarize
    FailedCount = count(),
    DistinctUsers = dcount(UserPrincipalName),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
  by IPAddress, bin(TimeGenerated, 5m)
| where FailedCount > 5
| extend AttackDuration = LastAttempt - FirstAttempt
| project IPAddress, FailedCount, DistinctUsers, AttackDuration
| order by FailedCount desc
```

---

## ❓ Sample Interview Questions & Model Answers

### Technical Questions

**Q1**: "איך היית מאבחן Latency גבוה בין שני Virtual Machines ב-Regions שונים?"

```
Model Answer Framework:
1. Confirm the latency (Network Watcher - Connection Monitor)
2. Check routing (Effective Routes - is it going through Firewall?)
3. Check NSG rules (is traffic being inspected unnecessarily?)
4. Measure at each hop (Network Watcher - IP Flow Verify)
5. Check VM SKU (Premium vs Standard networking)
6. Consider ExpressRoute vs VPN path differences

KQL to support:
VMConnection
| where RemoteIp == "target-ip"
| summarize avg(ResponseTimeMs) by Computer, bin(TimeGenerated, 5m)
| render timechart
```

**Q2**: "מהם השיקולים בבחירה בין Azure SQL לבין SQL על VM?"

| Consideration | Azure SQL (PaaS) | SQL on VM (IaaS) |
|--------------|------------------|-----------------|
| Manageability | Microsoft manages patches, HA | Full control, full responsibility |
| Supportability | Built-in diagnostics, QPI | Need to configure monitoring |
| Cost | Predictable, pay for DTU/vCore | Pay for VM + license |
| Compliance | Limited OS access | Full OS access |
| Features | Latest SQL features auto-applied | Specific version pinned |
| **Recommendation** | **Default choice for new workloads** | **Only for legacy or specific requirements** |

### Operational Questions

**Q3**: "לקוח חווה Incident קריטי. ה-RCA מצביע על טעות אנוש של הצוות שלך. איך אתה מנגיש את זה ללקוח?"

```
CxP Best Practice Approach:
1. Never hide the truth - transparency builds trust
2. Lead with impact acknowledgment: "We understand this caused X hours of downtime"
3. Present clear timeline of events (factual, no blame language)
4. Root cause: "A configuration change was applied without proper change control"
5. Immediate fix: already in place
6. Prevention plan:
   - Change Advisory Board (CAB) process implemented
   - Automated validation before deployment
   - Rollback procedures tested
7. Ask: "What else do you need from us to restore confidence?"

Remember: Microsoft's goal is Unified Support excellence - the RCA is a trust-building tool, not a blame document.
```

---

## 🎓 Certification Roadmap

```
Now ──────────────────────────────────────────────────► 6 months

AZ-104 (Month 1-2)        AZ-500 (Month 3-4)        AZ-305 (Month 5-6)
Azure Administrator   →   Security Engineer      →   Solutions Architect
     [MANDATORY]              [CRITICAL for              [MAJOR
                              Security Clearance]         ADVANTAGE]
```

### Study Resources per Cert
- **AZ-104**: Microsoft Learn + John Savill's Master Class (YouTube)
- **AZ-500**: Microsoft Learn + CloudBrew + Practice labs in Security Center
- **AZ-305**: Microsoft Learn + Case studies from Azure Architecture Center

---

## 💡 Israel Security Clearance Context

מאחר והמשרה דורשת סיווג ביטחוני ואזרחות ישראלית:

### Key Focus Areas

**Azure Israel Central Region Specifics**:
- Data Residency requirements: all data stays in Israel
- Compliance frameworks: ISO 27001, SOC 2, Israeli privacy law (PDPA)
- Sovereign cloud considerations

**Deep Knowledge Required**:
- [ ] **Azure Policy & Blueprints** - Compliance enforcement at scale
- [ ] **Microsoft Defender for Cloud** - Security posture management
- [ ] **Azure Purview** - Data governance and classification
- [ ] **Confidential Computing** - For highest sensitivity workloads

**Compliance KQL - Audit Everything**
```kql
AzureActivity
| where OperationNameValue has_any ("write", "delete", "action")
| where ActivityStatusValue == "Success"
| where Caller !contains "Microsoft"
| project TimeGenerated, Caller, OperationNameValue, ResourceGroup, Resource
| order by TimeGenerated desc
```

### Security Clearance Interview Tips
- Emphasize Zero Trust as your default architecture approach
- Demonstrate knowledge of air-gapped and disconnected scenarios
- Show familiarity with least-privilege access patterns
- Discuss defense-in-depth strategies

---

## 📅 Recommended Study Schedule

| Week | Phase | Focus |
|------|-------|-------|
| 1-2 | Phase 1 | WAF, Governance, Azure Policy |
| 3-5 | Phase 2 | Networking Deep Dive + Hub & Spoke Lab |
| 6-7 | Phase 2 | Compute HA, ASR, Storage |
| 8-9 | Phase 3 | AKS + Zero Trust Lab |
| 10-11 | Phase 4 | KQL Mastery + RCA Simulations |
| 12 | Phase 5 | STAR Stories + Mock Interviews |

---

## 🔄 Progress Tracker

### Phase 1: Foundations
- [ ] WAF 5 Pillars - Theory complete
- [ ] Management Groups configured
- [ ] Azure Policy - Deny VM without tags
- [ ] Log Analytics workspace enforced via Policy

### Phase 2: IaaS & Networking
- [ ] Hub & Spoke Lab deployed
- [ ] Azure Firewall configured with policy
- [ ] VPN Gateway connected
- [ ] VMSS deployed and tested
- [ ] ASR configured for test VM
- [ ] Storage redundancy understood

### Phase 3: PaaS & Modern Apps
- [ ] AKS private cluster deployed
- [ ] Azure CNI configured
- [ ] Managed Identity end-to-end tested
- [ ] Key Vault integration complete
- [ ] Zero Trust Lab complete

### Phase 4: Monitoring
- [ ] 5 core KQL queries mastered
- [ ] Alert rules configured
- [ ] RCA simulation completed
- [ ] Azure Workbook built
- [ ] Brute Force KQL Lab complete

### Phase 5: Soft Skills
- [ ] 3 STAR stories prepared and practiced
- [ ] Technical-to-business translations ready
- [ ] Mock interview conducted
- [ ] RCA communication practiced

---

*Last Updated: 2026-02-25*
*Target Role: Azure Customer Engineer / Architect - Microsoft Israel*
*Branch: claude/azure-interview-prep-aUKHp*
