from cognitive.finding_pipeline import generate_findings
from cognitive.question_pipeline import generate_questions
from models.pipeline_run import PipelineRun


"""
ORION Cognitive Pipeline

Coordinates ORION's cognitive reasoning stages.
"""


def execute(evidence):
    """
    Executes ORION's cognitive pipeline.
    """

    findings = generate_findings(evidence)

    questions = generate_questions(findings)

    return PipelineRun(
        findings=findings,
        questions=questions,
        status="Completed"
    )