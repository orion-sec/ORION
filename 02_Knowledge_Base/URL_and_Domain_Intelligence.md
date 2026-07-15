# URL and Domain Intelligence

## Purpose

This document explains how ORION currently analyses URLs and domains during an investigation.

ORION now supports:

- URL extraction
- URL enrichment
- URL risk scoring
- Domain extraction
- Domain keyword inspection
- Domain reputation classification
- Confidence assignment

---

## URL Enrichment

Implemented in:

`11_Modules/url_enrich.py`

The module parses a URL and extracts:

- Original URL
- Scheme
- Hostname
- Port
- Path
- Query string

Example:

`https://login.example.com:443/account/reset?user=sam`

Produces:

- Scheme: `https`
- Hostname: `login.example.com`
- Port: `443`
- Path: `/account/reset`
- Query: `user=sam`

---

## URL Risk Scoring

Implemented in:

`11_Modules/url_score.py`

The URL scoring engine currently evaluates:

### Unencrypted HTTP

URLs using:

`http`

receive additional risk.

### Non-Standard Ports

Ports outside common web ports may increase risk.

Common ports currently treated as standard:

- 80
- 443

### Suspicious Keywords

Current suspicious keywords include:

- login
- signin
- verify
- account
- reset
- password
- secure
- update

Each detected keyword contributes to the URL score.

---

## Current URL Risk Levels

The current scoring logic maps scores to:

- `Informational`
- `Low`
- `Medium`
- `High`

The scoring engine is heuristic.

A suspicious keyword does not automatically mean a URL is malicious.

The purpose is to provide investigation context and support analyst decision-making.

---

## Domain Intelligence

Implemented in:

`11_Modules/domain_intel.py`

The domain intelligence module currently inspects domain names for suspicious keywords.

Current keywords include:

- login
- signin
- verify
- secure
- account
- update
- password
- support

Example:

`login.example.com`

Matches:

`login`

The module returns:

- Domain
- Status
- Reputation
- Confidence
- Matched keywords

Example result:

- Status: `Reviewed`
- Reputation: `Suspicious`
- Confidence: `40`
- Matched Keywords: `login`

---

## Current Domain Classification Logic

If one or more suspicious keywords are detected:

- Status: `Reviewed`
- Reputation: `Suspicious`
- Confidence: `40`

If no suspicious keyword is detected:

- Status: `Reviewed`
- Reputation: `Unknown`
- Confidence: `0`

---

## Important Limitation

Keyword-based detection is not sufficient to determine whether a domain is malicious.

For example:

`login.microsoftonline.com`

contains the keyword:

`login`

but may be completely legitimate.

Therefore, the current domain intelligence logic should be treated as:

**Preliminary contextual analysis**

rather than:

**Final malicious classification**

Future versions should combine additional intelligence such as:

- Domain age
- WHOIS information
- DNS records
- Certificate information
- Domain reputation services
- Passive DNS
- VirusTotal
- URLScan
- Threat intelligence feeds
- Organisational allowlists
- Historical activity

---

## Multi-Signal Correlation

The long-term design should avoid making decisions from a single signal.

A stronger investigation model combines:

- IP reputation
- URL characteristics
- Domain reputation
- Threat intelligence
- Historical activity
- User context
- Device context
- Authentication behaviour

Example:

```text
Clean IP
+
Suspicious URL structure
+
Newly registered domain
+
Known phishing reputation
=
High-confidence malicious assessment