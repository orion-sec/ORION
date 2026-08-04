from cognitive.finding_pipeline import generate_findings
from cognitive.question_pipeline import generate_questions
from cognitive.hypothesis_pipeline import generate_hypotheses
from decision_engine.investigation_decision import determine_outcome

from models.pipeline_run import PipelineRun

"""
ORION Cognitive Pipeline

Coordinates ORION's cognitive reasoning stages.
"""


def execute(evidence, signals=None, decision_context=None):
    """
    Executes ORION's complete cognitive pipeline.
    """

    signals = signals or {}
    decision_context = decision_context or {}

    findings = generate_findings(evidence)
    questions = generate_questions(findings)
    hypotheses = generate_hypotheses(findings)

    outcome = determine_outcome(
        hypotheses,
        signals,
        decision_context
    )

    return PipelineRun(
        findings=findings,
        questions=questions,
        hypotheses=hypotheses,
        outcome=outcome,
        status="Completed"
    )