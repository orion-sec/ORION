from intelligence.virustotal_normalizer import (
    normalise_virustotal_result,
)


def test_normalise_malicious_virustotal_result() -> None:
    payload = {
        "data": {
            "type": "file",
            "id": "example-sha256",
            "attributes": {
                "type_description": "Win32 EXE",
                "first_submission_date": 1700000000,
                "last_analysis_date": 1700100000,
                "reputation": -25,
                "tags": [
                    "peexe",
                    "malware",
                ],
                "meaningful_name": "payload.exe",
                "last_analysis_stats": {
                    "malicious": 45,
                    "suspicious": 2,
                    "harmless": 0,
                    "undetected": 23,
                    "timeout": 0,
                },
            },
        }
    }

    result = normalise_virustotal_result(
        payload
    )

    assert result["provider"] == "VirusTotal"
    assert result["reputation"] == "Malicious"
    assert result["confirmed_malicious"] is True
    assert result["suspicious"] is False
    assert result["known_benign"] is False

    assert result["confidence"] > 0

    assert (
        result["metadata"]["virustotal"]
        ["analysis_stats"]["malicious"]
        == 45
    )

    assert (
        result["metadata"]["virustotal"]
        ["analysis_stats"]["suspicious"]
        == 2
    )

    assert (
        result["metadata"]["virustotal"]
        ["meaningful_name"]
        == "payload.exe"
    )


def test_normalise_clean_virustotal_result() -> None:
    payload = {
        "data": {
            "type": "domain",
            "id": "example.com",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 65,
                    "undetected": 5,
                    "timeout": 0,
                },
            },
        }
    }

    result = normalise_virustotal_result(
        payload
    )

    assert result["reputation"] == "Clean"
    assert result["confirmed_malicious"] is False
    assert result["suspicious"] is False
    assert result["known_benign"] is True
    assert result["confidence"] == 0


def test_normalise_suspicious_virustotal_result() -> None:
    payload = {
        "data": {
            "type": "url",
            "id": "example-url-id",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 1,
                    "suspicious": 2,
                    "harmless": 40,
                    "undetected": 27,
                    "timeout": 0,
                },
            },
        }
    }

    result = normalise_virustotal_result(
        payload
    )

    assert result["reputation"] == "Suspicious"
    assert result["confirmed_malicious"] is False
    assert result["suspicious"] is True
    assert result["known_benign"] is False