# KB-035 — ORION Common Security Incident Architecture

**Category:** Architecture  
**Component:** Security Incident Normalization  
**Status:** Active  
**Introduced:** Day 37 — 08 August 2026

---

## Purpose

ORION requires a common representation of security incidents because different security platforms expose different schemas.

For example:

```text
Microsoft Sentinel -> Sentinel incident schema
Microsoft Defender -> Defender incident schema
CrowdStrike        -> Falcon detection/incident schema
Google SecOps      -> Google security event/detection schema
Splunk             -> Splunk notable/event schema
Darktrace          -> Darktrace model breach schema