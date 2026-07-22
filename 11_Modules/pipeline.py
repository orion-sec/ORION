"""
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


class OrionPipeline:

    def __init__(self):
        self.stages = []

    def add_stage(self, stage):
        self.stages.append(stage)

    def run(self, investigation, results=None):

        if results is None:
            results = {}

        for stage in self.stages:
            results = stage(investigation, results)

        return results