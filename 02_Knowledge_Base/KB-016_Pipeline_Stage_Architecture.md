# Pipeline Stage Architecture

## Overview

A pipeline stage represents a single unit of work performed during an investigation.

Rather than embedding all investigation logic inside one script, ORION V2 divides investigations into small independent stages that execute sequentially.

---

## Characteristics of a Good Stage

Each stage should:

- Perform one responsibility
- Consume existing pipeline data
- Produce new pipeline data
- Avoid interacting directly with unrelated stages
- Return the updated results dictionary

Example:

```
Investigation
↓

IOC Extraction
↓

Identity Extraction
↓

Identity Enrichment
↓

Business Impact
```

Each stage depends only on data produced by earlier stages.

---

## Benefits

Using independent stages provides:

- Modular design
- Easier debugging
- Simpler testing
- Better code reuse
- Clear execution order
- Enterprise scalability

New capabilities can be added simply by creating another stage and registering it with the pipeline.

Example:

```
pipeline.add_stage(threat_intelligence_stage)
```

No existing stages need to be modified.

---

## Pipeline as an Orchestrator

The pipeline engine should never perform investigation work itself.

Its responsibilities are limited to:

- Executing stages
- Tracking execution order
- Measuring execution time
- Capturing failures
- Producing execution summaries

Investigation logic remains inside individual stage functions.

This separation of concerns is a common architectural pattern used in enterprise software engineering.

---

## Current ORION V2 Pipeline

Current execution order:

Initialize Investigation
↓

IOC Extraction
↓

Identity Extraction
↓

Identity Enrichment
↓

Business Impact Assessment

Future stages will continue extending this pipeline without changing the execution engine itself.