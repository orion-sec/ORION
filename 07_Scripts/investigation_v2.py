"""
ORION V2

Enterprise Investigation Platform

Entry point for the ORION processing pipeline.
"""

import os
import sys

sys.path.append(os.path.abspath("../11_Modules"))

from pipeline import OrionPipeline


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