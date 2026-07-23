"""
ORION V2

Enterprise Investigation Platform

Entry point for the ORION processing pipeline.
"""

import sys
import os

sys.path.append(os.path.abspath("../11_Modules"))

from pipeline import OrionPipeline, initialise_results_stage
from pipeline import (
    OrionPipeline,
    initialise_results_stage,
    ioc_extraction_stage,
    identity_extraction_stage
)

def main():

    print("==============================")
    print("      ORION V2")
    print("==============================")

    investigation = input(
        "Paste investigation text here: "
    )

    pipeline = OrionPipeline()

    pipeline.load_default_pipeline()

    results = pipeline.run(
        investigation
    )

    print(results)


if __name__ == "__main__":
    main()