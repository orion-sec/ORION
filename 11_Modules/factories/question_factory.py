from models.question import Question

"""
Question Factory

Creates Question cognitive objects from investigation findings.

Factories create objects.
They do not perform investigation logic.
"""


def create_question(
    question: str,
    reason: str,
    *,
    category: str = "General",
    evidence_gap: str = "",
    priority: str = "Medium",
) -> Question:
    """
    Creates a Question cognitive model.

    The evidence_gap identifies the specific investigation
    fact that must still be established.
    """

    return Question(
        question=question,
        reason=reason,
        category=category,
        evidence_gap=evidence_gap,
        priority=priority,
        status="Unresolved",
    )


def generate_infrastructure_questions(finding):
    """
    Generates questions from infrastructure findings.
    """

    return [
        create_question(
            question=(
                "Is this infrastructure expected "
                "for this environment?"
            ),
            reason=finding.finding,
        ),
        create_question(
            question=(
                "Has this infrastructure or IP been "
                "observed elsewhere in the environment?"
            ),
            reason=finding.finding,
        ),
    ]


def generate_malware_questions(finding):
    """
    Generates evidence-aware questions from malware findings.
    """

    return [
        create_question(
            question=(
                "Is the detected file or hash known "
                "to be malicious?"
            ),
            reason=(
                "The investigation contains a file or hash "
                "associated with suspected malware, but its "
                "reputation must be established before the "
                "artifact can be classified confidently."
            ),
            category="Threat Intelligence",
            evidence_gap="indicator-reputation",
            priority="High",
        ),
        create_question(
            question=(
                "Was the suspicious executable actually "
                "executed on the endpoint?"
            ),
            reason=(
                "A suspicious artifact was identified, but "
                "current evidence does not establish whether "
                "it executed. Execution evidence is required "
                "to distinguish file presence from active "
                "endpoint compromise."
            ),
            category="Execution",
            evidence_gap="process-execution",
            priority="High",
        ),
        create_question(
            question=(
                "What process launched the suspicious file?"
            ),
            reason=(
                "The investigation does not yet establish "
                "the process lineage associated with the "
                "suspicious artifact. Identifying the parent "
                "or launching process will help determine "
                "how execution occurred."
            ),
            category="Process",
            evidence_gap="parent-process",
            priority="High",
        ),
        create_question(
            question=(
                "Has the same file or hash been observed "
                "on other endpoints?"
            ),
            reason=(
                "The artifact has been identified in the "
                "current investigation, but its prevalence "
                "across the environment is not yet known. "
                "Environment-wide occurrence is required "
                "to assess potential blast radius."
            ),
            category="Blast Radius",
            evidence_gap="indicator-prevalence",
            priority="Medium",
        ),
    ]


def generate_endpoint_questions(finding):
    """
    Generates questions from endpoint findings.
    """

    return [
        create_question(
            question=(
                "Is the affected endpoint behaving "
                "outside its normal baseline?"
            ),
            reason=finding.finding,
        ),
        create_question(
            question=(
                "Are there related alerts or suspicious "
                "events on this endpoint?"
            ),
            reason=finding.finding,
        ),
        create_question(
            question=(
                "Has this endpoint communicated with "
                "known suspicious infrastructure?"
            ),
            reason=finding.finding,
        ),
    ]


def generate_file_questions(finding):
    """
    Generates questions from file evidence.
    """

    return [
        create_question(
            question=(
                "What is the reputation of the observed "
                "file or hash?"
            ),
            reason=finding.finding,
        ),
        create_question(
            question=(
                "Where else has this file or hash "
                "been observed?"
            ),
            reason=finding.finding,
        ),
        create_question(
            question=(
                "What process created, downloaded, "
                "or executed this file?"
            ),
            reason=finding.finding,
        ),
    ]


def generate_process_questions(finding):
    """
    Generates questions from process and execution findings.
    """

    return [
        create_question(
            question=(
                "What command line was executed?"
            ),
            reason=finding.finding,
        ),
        create_question(
            question=(
                "Which user or service account launched "
                "the process?"
            ),
            reason=finding.finding,
        ),
        create_question(
            question=(
                "What was the parent process?"
            ),
            reason=finding.finding,
        ),
        create_question(
            question=(
                "Did the process create child processes "
                "or network connections?"
            ),
            reason=finding.finding,
        ),
        create_question(
            question=(
                "Is this process activity expected "
                "for the affected host?"
            ),
            reason=finding.finding,
        ),
    ]


def generate_identity_questions(finding):
    """
    Generates questions from identity findings.
    """

    return [
        create_question(
            question=(
                "Is the sign-in location expected "
                "for this user?"
            ),
            reason=finding.finding,
        ),
        create_question(
            question=(
                "Is the source IP familiar for this identity?"
            ),
            reason=finding.finding,
        ),
        create_question(
            question=(
                "Was MFA successfully satisfied?"
            ),
            reason=finding.finding,
        ),
        create_question(
            question=(
                "Is the device known, managed, "
                "and compliant?"
            ),
            reason=finding.finding,
        ),
        create_question(
            question=(
                "Has this account shown similar suspicious "
                "activity elsewhere in the environment?"
            ),
            reason=finding.finding,
        ),
    ]


def generate_authentication_questions(finding):
    """
    Generates questions from authentication findings.
    """

    return [
        create_question(
            question=(
                "Were there repeated authentication "
                "failures before or after this event?"
            ),
            reason=finding.finding,
        ),
        create_question(
            question=(
                "Was the authentication attempt successful?"
            ),
            reason=finding.finding,
        ),
        create_question(
            question=(
                "Does the authentication pattern match "
                "the user's normal behaviour?"
            ),
            reason=finding.finding,
        ),
    ]


def generate_identity_risk_questions(finding):
    """
    Generates questions from identity-risk findings.
    """

    return [
        create_question(
            question=(
                "Why did Microsoft Entra assign risk "
                "to this sign-in?"
            ),
            reason=finding.finding,
        ),
        create_question(
            question=(
                "Are there additional risky sign-ins "
                "for this identity?"
            ),
            reason=finding.finding,
        ),
        create_question(
            question=(
                "Has the user's risk state changed "
                "recently?"
            ),
            reason=finding.finding,
        ),
    ]


def generate_device_trust_questions(finding):
    """
    Generates questions from device-trust findings.
    """

    return [
        create_question(
            question=(
                "Is this device registered to the user?"
            ),
            reason=finding.finding,
        ),
        create_question(
            question=(
                "Is the device managed by the organisation?"
            ),
            reason=finding.finding,
        ),
        create_question(
            question=(
                "Has this device been involved in "
                "other suspicious activity?"
            ),
            reason=finding.finding,
        ),
    ]


QUESTION_GENERATORS = {
    "Infrastructure": generate_infrastructure_questions,
    "Malware": generate_malware_questions,
    "Endpoint": generate_endpoint_questions,
    "File": generate_file_questions,
    "Process": generate_process_questions,
    "Identity": generate_identity_questions,
    "Authentication": generate_authentication_questions,
    "Identity Risk": generate_identity_risk_questions,
    "Device Trust": generate_device_trust_questions,
    "Device Compliance": generate_device_trust_questions,
    "Conditional Access": generate_identity_questions,
}


def create_questions_from_findings(findings):
    """
    Creates Question objects from investigation findings.
    """

    questions = []
    seen_questions = set()

    for finding in findings:
        category = getattr(
            finding,
            "category",
            "",
        )

        handler = QUESTION_GENERATORS.get(
            category
        )

        if handler is None:
            continue

        generated_questions = handler(
            finding
        )

        for question in generated_questions:
            question_text = question.question.strip()

            if not question_text:
                continue

            if question_text in seen_questions:
                continue

            seen_questions.add(
                question_text
            )

            questions.append(
                question
            )

    return questions
