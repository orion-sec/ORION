# Pipeline Architecture and System Evolution

## Introduction

As software systems grow, responsibilities naturally expand.

A script that initially performs a single task often becomes responsible for orchestrating multiple independent components.

When this occurs, introducing a processing pipeline improves maintainability and scalability.

---

## Script-Based Architecture

Traditional execution:

Main Script

↓

Module A

↓

Module B

↓

Module C

↓

Output

The main script is responsible for both orchestration and business logic.

As additional modules are added, the script continually increases in complexity.

---

## Pipeline Architecture

Pipeline execution separates orchestration from implementation.

Pipeline

↓

Stage 1

↓

Stage 2

↓

Stage 3

↓

Stage N

↓

Output

The pipeline knows only the execution order.

Individual stages remain responsible for their own processing.

---

## Pipeline Contract

Every processing stage should follow the same interface.

Input:

- Investigation
- Shared Results Dictionary

Output:

- Updated Results Dictionary

This allows stages to be inserted, removed or reordered without affecting unrelated modules.

---

## Separation of Responsibilities

Pipeline

Responsible for:

- Stage execution
- Execution order
- Shared investigation state

Individual Modules

Responsible for:

- Business logic
- Investigation analysis
- Decision making
- Intelligence processing

Display Engine

Responsible for:

- Rendering investigation results

---

## ORION V1 vs ORION V2

### ORION V1

Characteristics:

- Script-based
- Investigation orchestration contained within ioc_extractor.py
- Fully operational
- Stable implementation

---

### ORION V2

Characteristics:

- Pipeline-driven
- Modular architecture
- Independent investigation stages
- Easier testing
- Easier future integrations
- Improved maintainability

---

## Benefits of Parallel Evolution

Developing ORION V2 alongside V1 provides several advantages.

- Existing functionality remains available.
- Migration occurs incrementally.
- Outputs from both implementations can be compared.
- Regression testing becomes easier.
- Architectural improvements remain isolated until validated.

---

## Future Expansion

The pipeline architecture enables straightforward integration of future capabilities including:

- Microsoft Graph
- Microsoft Defender XDR
- Microsoft Sentinel
- CrowdStrike
- Splunk
- ServiceNow
- Threat Intelligence APIs
- AI Reasoning Engine
- Automation Engine
- Security Copilot

Each integration becomes an independent processing stage rather than requiring significant modification to the investigation engine.

---

## Engineering Principle

A processing pipeline should coordinate work.

Processing stages should perform work.

Keeping orchestration separate from business logic improves modularity, maintainability and long-term scalability.