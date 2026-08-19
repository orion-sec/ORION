from factories.question_factory import (
    generate_malware_questions,
)
from models.finding import Finding


def test_malware_questions_declare_evidence_gaps() -> None:
    finding = Finding(
        category="Malware",
        finding="Malicious file activity detected.",
    )

    questions = generate_malware_questions(
        finding
    )

    assert len(questions) == 4

    assert questions[0].category == (
        "Threat Intelligence"
    )
    assert (
        "indicator-reputation"
        in questions[0].evidence_gap
    )

    assert questions[1].category == "Execution"
    assert (
        "process-execution"
        in questions[1].evidence_gap
    )

    assert questions[2].category == "Process"
    assert (
        "parent-process"
        in questions[2].evidence_gap
    )

    assert questions[3].category == "Blast Radius"
    assert (
        "indicator-prevalence"
        in questions[3].evidence_gap
    )

    assert all(
        question.status == "Unresolved"
        for question in questions
    )

def test_malware_questions_have_distinct_reasons() -> None:
    finding = Finding(
        category="Malware",
        finding="Potential malware activity was identified.",
    )

    questions = generate_malware_questions(
        finding
    )

    reasons = [
        question.reason
        for question in questions
    ]

    assert len(set(reasons)) == 4

    assert "reputation" in reasons[0].lower()
    assert "execution" in reasons[1].lower()
    assert "process lineage" in reasons[2].lower()
    assert "blast radius" in reasons[3].lower()