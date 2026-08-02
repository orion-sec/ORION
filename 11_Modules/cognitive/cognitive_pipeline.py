from cognitive.finding_pipeline import generate_findings
from cognitive.question_pipeline import generate_questions
from cognitive.hypothesis_pipeline import generate_hypotheses

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

    hypotheses = generate_hypotheses(findings)

    return PipelineRun(
        findings=findings,
        questions=questions,
        hypotheses=hypotheses,
        status="Completed"
    )