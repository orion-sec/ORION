from models.question import Question


def test_question_supports_investigation_context() -> None:
    question = Question(
        question="Was the malicious file executed?",
        reason=(
            "Execution confirmation determines whether "
            "active compromise occurred."
        ),
        category="Execution",
        evidence_gap=(
            "No process-execution telemetry confirms "
            "execution of the file."
        ),
        priority="High",
        status="Unresolved",
    )

    assert question.question == (
        "Was the malicious file executed?"
    )
    assert question.category == "Execution"
    assert question.priority == "High"
    assert question.status == "Unresolved"
    assert "process-execution" in question.evidence_gap


def test_question_remains_backward_compatible() -> None:
    question = Question(
        question="Is this activity expected?",
        reason="Additional validation is required.",
    )

    assert question.category == "General"
    assert question.evidence_gap == ""
    assert question.priority == "Medium"
    assert question.status == "Unresolved"