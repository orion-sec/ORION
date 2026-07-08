# Python Modules

---

# What is a Python Module?

A module is a Python file that contains reusable code.

Instead of placing every function inside one file, related functions are grouped together inside their own modules.

Example:

display.py

contains only display functions.

extract.py

contains only IOC extraction functions.

---

# Why Use Modules?

Modules make software easier to understand and maintain.

Benefits include:

• Smaller files

• Better organisation

• Reusable code

• Easier debugging

• Easier testing

• Cleaner architecture

Professional applications are almost always built using modules.

---

# Importing Modules

Import an entire module

```python
import math
```

Import a specific function

```python
from math import sqrt
```

Import a custom module

```python
from extract import extract_iocs
```

---

# Module Search Path

Python searches specific locations for modules.

Custom folders can be added using:

```python
import sys
import os

sys.path.append(os.path.abspath("../11_Modules"))
```

This allows Python to import files stored in custom directories.

---

# Separation of Concerns

Each module should have one responsibility.

Example:

extract.py

↓

Extract IOC information

display.py

↓

Display reports

ioc_extractor.py

↓

Control application workflow

Keeping responsibilities separate makes applications easier to expand.

---

# Returning Dictionaries

Instead of returning many separate variables:

```python
return urls, ips, emails
```

Return one dictionary:

```python
return {
    "URLs": urls,
    "IPs": ips,
    "Emails": emails
}
```

Advantages:

• Easier to extend

• Cleaner code

• Fewer function parameters

• Simpler function calls

---

# Data Flow

Good software follows a predictable flow.

ORION now follows this structure:

User Input

↓

extract_iocs()

↓

Dictionary of IOC Results

↓

display_report()

↓

Console Output

---

# Professional Software Architecture

Large software projects rarely contain one huge file.

Instead they are organised into modules.

Typical project structure:

Main Program

↓

Extraction Module

↓

Display Module

↓

Utilities

↓

Configuration

↓

Logging

↓

Automation

↓

External APIs

This approach improves readability, scalability and long-term maintenance.

---

# Key Takeaways

• Modules improve organisation.

• Functions should be reusable.

• Each module should have one responsibility.

• Dictionaries simplify passing related data.

• Clean architecture makes future development easier.