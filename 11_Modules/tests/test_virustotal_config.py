import os
from unittest.mock import patch

import pytest

from connectors.config import (
    VirusTotalConfig,
    load_virustotal_config,
)


def test_load_virustotal_config() -> None:
    with patch.dict(
        os.environ,
        {
            "ORION_VIRUSTOTAL_API_KEY": "test-api-key",
            "ORION_VIRUSTOTAL_BASE_URL":
                "https://www.virustotal.com/api/v3",
            "ORION_VIRUSTOTAL_TIMEOUT": "20",
        },
    ):
        config = load_virustotal_config()

    assert isinstance(config, VirusTotalConfig)
    assert config.api_key == "test-api-key"

    assert (
        config.base_url
        == "https://www.virustotal.com/api/v3"
    )

    assert config.timeout == 20


def test_load_virustotal_config_requires_api_key() -> None:
    with (
        patch.dict(
            os.environ,
            {
                "ORION_VIRUSTOTAL_API_KEY": "",
            },
        ),
        pytest.raises(ValueError),
    ):
        load_virustotal_config()