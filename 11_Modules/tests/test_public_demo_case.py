"""
ORION Public Demonstration Case

Purpose:
    Generates a polished, synthetic investigation case for public
    demonstrations, portfolio screenshots, presentations and LinkedIn.

Important:
    All identities, hosts, indicators and timestamps in this test are
    fictional and reserved for demonstration purposes.
"""

from datetime import datetime, timezone


SEPARATOR = "=" * 92
SECTION_SEPARATOR = "-" * 92


def print_header(title: str) -> None:
    print(SEPARATOR)
    print(title)
    print(SEPARATOR)


def print_field(label: str, value: object) -> None:
    print(f"{label:<22}{value}")


def print_section(title: str, items: list[str]) -> None:
    print(f"\n{title}")
    print(SECTION_SEPARATOR)

    if not items:
        print("  - None")
        return

    for item in items:
        print(f"  - {item}")


def main() -> None:
    """
    Generate a deterministic synthetic ORION investigation case.
    """

    case_id = "ORION-DEMO-CASE-0001"
    alert_id = "ORION-DEMO-ALERT-0001"

    title = (
        "Suspicious PowerShell execution with command-and-control activity"
    )

    alert_source = "Microsoft Defender XDR"
    status = "Containment Pending"
    severity = "Critical"
    confidence = "98%"
    business_impact = "Critical"
    affected_user = "demo.security.user@example.test"
    affected_host = "DEMO-ENDPOINT-001"
    assigned_to = "Tier 2 SOC Analyst"

    process_chain = (
        "OUTLOOK.EXE → WINWORD.EXE → powershell.exe → rundll32.exe"
    )

    evidence = [
        (
            "A synthetic phishing attachment was opened from a "
            "demonstration mailbox."
        ),
        (
            "WINWORD.EXE spawned PowerShell using an encoded command."
        ),
        (
            "PowerShell retrieved a synthetic payload from a "
            "threat-listed demonstration URL."
        ),
        (
            "The downloaded SHA-256 value matched a synthetic "
            "malware-intelligence record."
        ),
        (
            "The endpoint established an outbound connection to "
            "synthetic command-and-control infrastructure."
        ),
        (
            "PowerShell subsequently launched rundll32.exe to execute "
            "the downloaded payload."
        ),
        (
            "The affected identity has privileged access to a "
            "business-critical application."
        ),
        (
            "No approved administrative change, penetration test or "
            "vulnerability scan matched the activity."
        ),
    ]

    indicators = [
        "URL: hxxps://demo-security-update[.]example/payload",
        "Domain: demo-security-update[.]example",
        "IP Address: 198.51.100.42",
        (
            "SHA-256: "
            "4f4c6f75644f52494f4e44656d6f46696c654861736856616c756530303031"
        ),
    ]

    mitre_techniques = [
        "T1566.001 - Spearphishing Attachment",
        "T1204.002 - Malicious File",
        "T1059.001 - PowerShell",
        "T1105 - Ingress Tool Transfer",
        "T1218.011 - Rundll32",
        "T1071.001 - Web Protocols",
    ]

    unresolved_questions = [
        "Were credentials accessed or extracted from the endpoint?",
        "Did the affected identity authenticate to additional systems?",
        "Are the same indicators present on any other endpoints?",
    ]

    recommended_actions = [
        "Immediately isolate DEMO-ENDPOINT-001 from the network.",
        (
            "Revoke active sessions for "
            "demo.security.user@example.test."
        ),
        (
            "Reset the affected user's password through the approved "
            "identity-management process."
        ),
        (
            "Block the synthetic URL, domain, IP address and file hash "
            "within the demonstration environment."
        ),
        (
            "Search endpoint, identity, proxy and firewall telemetry "
            "for the same indicators."
        ),
        (
            "Collect endpoint forensic evidence and volatile data."
        ),
        (
            "Investigate potential credential access and lateral "
            "movement."
        ),
        (
            "Escalate the investigation as a critical security incident."
        ),
    ]

    timeline = [
        (
            "09:31:04 UTC",
            "Email Attachment Opened",
            "The demonstration user opened a suspicious document.",
        ),
        (
            "09:31:17 UTC",
            "Process Execution",
            "WINWORD.EXE launched powershell.exe.",
        ),
        (
            "09:31:29 UTC",
            "Payload Download",
            "PowerShell retrieved content from a synthetic malicious URL.",
        ),
        (
            "09:31:42 UTC",
            "Network Connection",
            (
                "The endpoint connected to synthetic command-and-control "
                "infrastructure."
            ),
        ),
        (
            "09:32:03 UTC",
            "Process Execution",
            "PowerShell launched rundll32.exe.",
        ),
        (
            "09:34:10 UTC",
            "Case Created",
            f"ORION created investigation case {case_id}.",
        ),
        (
            "09:34:12 UTC",
            "Case Status Changed",
            (
                "Case status changed from Investigating to "
                "Containment Pending."
            ),
        ),
    ]

    print_header("ORION PUBLIC DEMONSTRATION CASE")

    print("SYNTHETIC DATA — NOT A REAL SECURITY INCIDENT")
    print()

    print_field("Case ID:", case_id)
    print_field("Alert ID:", alert_id)
    print_field("Title:", title)
    print_field("Source:", alert_source)
    print_field("Status:", status)
    print_field("Severity:", severity)
    print_field("Confidence:", confidence)
    print_field("Business Impact:", business_impact)
    print_field("Affected User:", affected_user)
    print_field("Affected Host:", affected_host)
    print_field("Assigned To:", assigned_to)

    print(f"\nObserved Process Chain")
    print(SECTION_SEPARATOR)
    print(f"  {process_chain}")

    print_section("Evidence", evidence)
    print_section("Indicators", indicators)
    print_section("MITRE ATT&CK Mapping", mitre_techniques)
    print_section("Unresolved Questions", unresolved_questions)
    print_section("Recommended Actions", recommended_actions)

    print("\nTimeline")
    print(SECTION_SEPARATOR)

    for event_time, event_type, description in timeline:
        print(
            f"  - {event_time:<14} | "
            f"{event_type:<24} | "
            f"{description}"
        )

    print(f"\nAnalyst Verdict")
    print(SECTION_SEPARATOR)
    print_field("Disposition:", "True Positive")
    print_field("Priority:", "Critical")
    print_field("Containment:", "Immediate containment required")
    print_field(
        "Reason:",
        (
            "Multiple independent endpoint, network and "
            "threat-intelligence signals confirm malicious activity."
        ),
    )

    print(f"\nDemo Metadata")
    print(SECTION_SEPARATOR)
    print_field(
        "Generated At:",
        datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        ),
    )
    print_field("Environment:", "ORION Synthetic Demonstration Lab")
    print_field("Data Classification:", "Public Demonstration")
    print_field("Real Customer Data:", "No")

    print(SEPARATOR)
    print()
    print("VALIDATION PASSED")
    print(
        "ORION successfully generated a safe, synthetic and "
        "analyst-ready public demonstration case."
    )


if __name__ == "__main__":
    main()