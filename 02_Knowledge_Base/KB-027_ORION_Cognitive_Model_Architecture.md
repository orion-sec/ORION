# KB-027 — ORION Cognitive Model Architecture

## Overview

ORION has evolved beyond simply transforming investigation data.

It now represents internal investigative reasoning using dedicated cognitive models.

This introduces a new architectural layer responsible for modelling uncertainty and investigative thinking.

---

# Problem

Investigation outputs such as evidence and findings describe what is already known.

They cannot represent information that is missing.

Without a dedicated model, ORION cannot express investigative uncertainty.

---

# Solution

Introduce a dedicated Models package.

Location:

11_Modules/models/

This package contains reusable cognitive objects.

Current implementation:

- BaseModel
- Question

---

# BaseModel

Purpose:

Provide a common parent class for future ORION cognitive objects.

Current implementation intentionally contains no functionality.

Future enhancements may include:

- IDs
- Serialization
- Traceability
- Metadata
- Audit information

---

# Question Model

Purpose:

Represents information ORION still requires before making stronger investigative decisions.

Current fields:

- question
- reason

Example:

Question(
    question="Was MFA satisfied?",
    reason="Authentication context is incomplete."
)

---

# Architectural Benefits

- Standardised cognitive objects.
- Clear separation between investigation data and investigative reasoning.
- Shared inheritance for future models.
- Simplified expansion of the cognitive engine.

---

# Design Principles

- Keep models intentionally minimal.
- Add complexity only when justified.
- Use inheritance to reduce duplication.
- Treat cognitive objects as first-class architectural components.

---

# Future Models

Potential future cognitive objects include:

- Finding
- Hypothesis
- Entity
- Recommendation
- Decision
- Timeline Event
- Memory Record
- Investigation State

---

# Key Takeaway

Today's architecture establishes the foundation for ORION's cognitive engine.

Instead of only processing evidence, ORION can now begin representing unknown information through structured cognitive models.