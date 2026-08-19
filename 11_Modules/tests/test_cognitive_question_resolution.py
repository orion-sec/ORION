from cognitive.cognitive_pipeline import execute
from models.indicator_profile import (
    IndicatorClassification,
    IndicatorProfile,
    IndicatorType,
)


def test_cognitive_pipeline_suppresses_resolved_reputation_question() -> None:
    profile = IndicatorProfile(
        indicator_type=IndicatorType.FILE_HASH,
        value="a" * 64,
        classification=(
            IndicatorClassification.CONFIRMED_MALICIOUS
        ),
        provider="VirusTotal",
        confidence=95,
        category="Malware",
    )

    evidence = [
        {
            "category": "Malware",
            "finding": (
                "Potential malware activity was identified."
            ),
            "evidence": (
                "A suspicious file hash was observed."
            ),
            "source": "Microsoft Sentinel",
        }
    ]

    cognitive_run = execute(
        evidence=evidence,
        decision_context={
            "indicator_intelligence": [
                profile
            ],
        },
    )

    question_texts = [
        question.question
        for question in cognitive_run.questions
    ]

    assert (
        "Is the detected file or hash known "
        "to be malicious?"
        not in question_texts
    )

    assert (
        "Was the suspicious executable actually "
        "executed on the endpoint?"
        in question_texts
    )

    assert (
        "What process launched the suspicious file?"
        in question_texts
    )

    assert (
        "Has the same file or hash been observed "
        "on other endpoints?"
        in question_texts
    )