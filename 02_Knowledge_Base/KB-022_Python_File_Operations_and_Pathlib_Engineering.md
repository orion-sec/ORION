# KB-022 — Python File Operations and Pathlib Engineering

## Purpose

This article documents the engineering principles and implementation techniques learned while building ORION Engineering Tool #001 (`rename_kb_files.py`).

---

# Why pathlib?

Python's `pathlib` module provides an object-oriented way to work with files and directories.

Instead of manipulating file paths as strings, `Path` objects provide a safer, cleaner, and more readable approach.

Example:

```python
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]