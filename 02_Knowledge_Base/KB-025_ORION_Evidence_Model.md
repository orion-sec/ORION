# KB-025 – ORION Evidence Model

## Principle

Represent evidence as structured data rather than plain text.

---

## Previous Design

Evidence was previously stored as simple strings.

Example:

"The IP address is publicly routable."

Although suitable for display, plain strings are difficult to classify, filter, correlate, or extend.

---

## Current Design

Evidence is now represented as standardized objects.

Example:

{
    "category": "Network",
    "statement": "The IP address is publicly routable."
}

This separates the meaning of the evidence from its textual representation.

---

## Evidence Categories

Current categories include:

- Source
- Infrastructure
- Network
- Historical
- Reputation

These categories may expand as additional ORION modules are developed.

---

## Centralized Evidence Creation

Evidence objects should not be manually constructed throughout the codebase.

Instead, modules should use:

create_evidence(category, statement)

from:

11_Modules/evidence.py

This establishes a single source of truth for evidence creation.

---

## Benefits

- Consistent evidence structure
- Reduced duplicated code
- Easier future schema changes
- Improved maintainability
- Supports filtering by category
- Supports future AI reasoning
- Supports richer reporting and visualization

---

## Engineering Principle

All ORION modules should produce structured evidence before performing reasoning or decision making.

Evidence should become the common language used throughout the platform.