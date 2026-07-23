"""
import time
ORION Processing Pipeline

Responsible for executing investigation stages
in the correct order.
"""


def initialise_results_stage(investigation, results):
    """
    Initialise shared investigation state for the pipeline.
    """

    results["Investigation"] = investigation

    return results

import time

from extract import extract_iocs
from identity_entities import extract_identity_entities

STAGE_NAMES = {
    "initialise_results_stage": "Initializing Investigation",
    "ioc_extraction_stage": "Extracting Indicators of Compromise",
    "identity_extraction_stage": "Extracting Identity Entities",
}


def ioc_extraction_stage(investigation, results):
    """
    Extract IOCs from the investigation narrative.
    """

    ioc_results = extract_iocs(investigation)

    results.update(ioc_results)

    return results

def identity_extraction_stage(investigation, results):
    """
    Extract identity entities from the investigation narrative.
    """

    results["Identity Entities"] = extract_identity_entities(
        investigation
    )

    return results

class OrionPipeline:

    def __init__(self):
        self.stages = []

    def add_stage(self, stage):
        self.stages.append(stage)

    def load_default_pipeline(self):
        """
        Load the default ORION investigation workflow.
        """

        self.add_stage(initialise_results_stage)
        self.add_stage(ioc_extraction_stage)
        self.add_stage(identity_extraction_stage)
        
    def run(self, investigation, results=None):

        if results is None:
            results = {}

        successful = 0
        failed = 0
        failed_stage = None

        total_stages = len(self.stages)

        for index, stage in enumerate(self.stages, start=1):

            stage_name = STAGE_NAMES.get(
                stage.__name__,
                stage.__name__
            )

            start_time = time.perf_counter()

            print(
                f"[PIPELINE] [{index}/{total_stages}] "
                f"Starting: {stage_name}"
            )

            try:
                results = stage(investigation, results)

                duration_ms = (
                    time.perf_counter() - start_time
                ) * 1000

                print(
                    f"[PIPELINE] [{index}/{total_stages}] "
                    f"Completed: {stage_name} "
                    f"({duration_ms:.2f} ms)"
                )

                successful += 1

            except Exception as error:

                duration_ms = (
                    time.perf_counter() - start_time
                ) * 1000

                print(
                    f"[PIPELINE] [{index}/{total_stages}] "
                    f"Failed: {stage_name} "
                    f"({duration_ms:.2f} ms)"
                )

                print(f"[PIPELINE] Error: {error}")

                failed += 1
                failed_stage = stage_name

                raise

        print()
        print("===================================")
        print("PIPELINE EXECUTION SUMMARY")
        print("===================================")

        print(f"Stages Executed : {len(self.stages)}")
        print(f"Successful      : {successful}")
        print(f"Failed          : {failed}")

        if failed_stage:
            print(f"Failed Stage    : {failed_stage}")
            print("Execution Status: FAILED")
        else:
            print("Execution Status: SUCCESS")

        print("===================================")

        return results  
