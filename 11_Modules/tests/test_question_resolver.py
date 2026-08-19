from cognitive.question_resolver import (
    filter_resolved_questions,
    resolved_evidence_gaps,
)
from models.indicator_profile import (
    IndicatorClassification,
    IndicatorProfile,
    IndicatorType,
)
from models.question import Question


def test_confirmed_malicious_resolves_indicator_reputation() -> None:
    profile = IndicatorProfile(
        indicator_type=IndicatorType.FILE_HASH,
        value="a" * 64,
        classification=(
            IndicatorClassification.CONFIRMED_MALICIOUS
        ),
        provider="VirusTotal",
        confidence=95,
    )

    resolved = resolved_evidence_gaps(
        [profile]
    )

    assert "indicator-reputation" in resolved


def test_unknown_indicator_does_not_resolve_reputation() -> None:
    profile = IndicatorProfile(
        indicator_type=IndicatorType.FILE_HASH,
        value="a" * 64,
        classification=(
            IndicatorClassification.UNKNOWN
        ),
        provider="VirusTotal",
    )

    resolved = resolved_evidence_gaps(
        [profile]
    )

    assert "indicator-reputation" not in resolved


def test_resolved_reputation_question_is_suppressed() -> None:
    questions = [
        Question(
            question="Is this hash malicious?",
            reason="File intelligence is required.",
            category="Threat Intelligence",
            evidence_gap="indicator-reputation",
            priority="High",
        ),
        Question(
            question="Was the file executed?",
            reason="Execution remains unknown.",
            category="Execution",
            evidence_gap="process-execution",
            priority="High",
        ),
    ]

    filtered = filter_resolved_questions(
        questions,
        {"indicator-reputation"},
    )

    assert len(filtered) == 1
    assert filtered[0].evidence_gap == (
        "process-execution"
    )