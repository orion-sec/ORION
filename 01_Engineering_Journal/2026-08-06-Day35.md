# ORION Engineering Journal
## Day 35 – Azure Monitor, Log Analytics & Microsoft Sentinel Foundation

**Date:** 06 August 2026

---

# Objective

Today's objective was to begin the Microsoft Sentinel integration by first building the Azure infrastructure required to support it.

Rather than connecting directly to Sentinel, I decided to build reusable Azure Management and Azure Log Analytics connectors that will become the foundation for every Azure-based provider inside ORION.

This follows the same architectural approach used for Microsoft Graph where providers never communicate directly with external APIs.

---

# Major Accomplishments

## 1. Azure Monitor Connector Created

Designed and implemented a dedicated Azure Monitor client responsible for communicating with Azure Management APIs and Azure Log Analytics APIs.

The connector now provides:

- Azure Management authentication
- Subscription discovery
- Log Analytics query execution
- Standardized Azure error handling
- Reusable authentication using the existing GraphAuthenticator

This connector will become the central Azure communication layer for ORION.

---

## 2. Azure Management API Successfully Integrated

Implemented support for Azure Resource Manager.

Successfully retrieved:

- Azure Subscription
- Subscription ID
- Subscription State

using the Azure Management REST API.

Live validation confirmed:

- Authentication successful
- Azure Management endpoint reachable
- Subscription enumeration working correctly

---

## 3. Microsoft Sentinel Environment Created

Provisioned ORION's first Azure Log Analytics Workspace.

Workspace Details

Name:
ORION-LAW

Region:
UK South

Resource Group:
ORION-RG

Pricing:
Pay-as-you-go

---

## 4. Azure IAM Configuration

Configured Azure permissions for the ORION application.

Granted Reader role to the ORION Security Platform Service Principal.

Validated successful role assignment.

---

## 5. Azure Log Analytics API Integrated

Extended AzureMonitorClient with Log Analytics support.

Implemented reusable:

run_kql()

method.

The connector now performs:

- OAuth authentication
- Bearer token generation
- KQL execution
- JSON parsing
- Error validation

---

## 6. Live KQL Validation

Executed the first live Kusto Query Language (KQL) query against ORION's Log Analytics workspace.

Query

Heartbeat
| take 5

Result

Azure successfully accepted the request and returned a valid PrimaryResult table.

Although the workspace is currently empty (expected for a new workspace), the successful execution proves:

- Authentication works
- Workspace access works
- KQL execution works
- JSON parsing works

---

## 7. Microsoft Cloud Integration Status

ORION now communicates successfully with three Microsoft cloud platforms.

Microsoft Graph

- Microsoft Entra ID
- Exchange Online
- Microsoft Defender

Azure Management

- Subscription Discovery
- Resource Management

Azure Monitor

- Log Analytics
- KQL Execution

---

# Engineering Decisions

Instead of embedding Azure REST calls inside SentinelProvider, I introduced AzureMonitorClient as a reusable infrastructure component.

This keeps providers lightweight while centralizing:

- Authentication
- HTTP communication
- Azure Management
- Log Analytics

Future Azure providers will simply consume AzureMonitorClient.

---

# Challenges

Azure permissions initially prevented Log Analytics access.

Resolution:

Assigned Reader role to the ORION Service Principal and validated access using a live Log Analytics query.

---

# Lessons Learned

Microsoft Sentinel is fundamentally built on top of Azure Log Analytics.

Building Log Analytics support first provides a reusable architecture that can later support:

- Microsoft Sentinel
- Azure Monitor
- Azure Security Center
- Azure Resource Graph
- Azure Operational Insights

without rewriting authentication logic.

---

# Architecture Status

Completed

✓ Graph Authentication

✓ Graph Client

✓ Entra Provider

✓ Exchange Provider

✓ Defender Provider

✓ Azure Management Client

✓ Azure Log Analytics Client

In Progress

→ Microsoft Sentinel Provider

---

# Next Session Goals

Build the production Microsoft Sentinel Provider.

Planned capabilities:

- get_recent_incidents()
- get_incident_by_id()
- get_recent_alerts()
- run_custom_query()

using AzureMonitorClient as the backend.

---

# End of Day Reflection

Today marks the point where ORION expanded beyond Microsoft Graph into Azure-native security services.

The successful implementation of Azure Management and Azure Log Analytics creates the reusable foundation required for Microsoft Sentinel integration and future Azure security capabilities.