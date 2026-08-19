from models.indicator_profile import (
    IndicatorClassification,
    IndicatorProfile,
)
from models.question import Question


def resolved_evidence_gaps(
    indicator_intelligence: list[object] | None = None,
) -> set[str]:
    """
    Determine which investigation evidence gaps have already
    been resolved by available structured intelligence.
    """

    resolved: set[str] = set()

    if not indicator_intelligence:
        return resolved

    for profile in indicator_intelligence:
        if not isinstance(profile, IndicatorProfile):
            continue

        if profile.classification in {
            IndicatorClassification.CONFIRMED_MALICIOUS,
            IndicatorClassification.SUSPICIOUS,
            IndicatorClassification.BENIGN,
        }:
            resolved.add(
                "indicator-reputation"
            )

    return resolved


def filter_resolved_questions(
    questions: list[Question],
    resolved_gaps: set[str],
) -> list[Question]:
    """
    Return only investigation questions whose evidence gaps
    remain unresolved.
    """

    unresolved = []

    for question in questions:
        evidence_gap = question.evidence_gap.strip()

        if (
            evidence_gap
            and evidence_gap in resolved_gaps
        ):
            continue

        unresolved.append(question)

    return unresolved