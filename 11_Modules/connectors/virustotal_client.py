from typing import Any
from urllib.parse import urlparse

import requests

from connectors.config import VirusTotalConfig


class VirusTotalError(RuntimeError):
    """
    Raised when a VirusTotal API request fails.
    """


class VirusTotalClient:
    """
    Client for retrieving IOC intelligence from VirusTotal.
    """

    def __init__(
        self,
        config: VirusTotalConfig,
    ) -> None:
        self.config = config

    @property
    def headers(self) -> dict[str, str]:
        return {
            "accept": "application/json",
            "x-apikey": self.config.api_key,
        }

    def _request(
        self,
        endpoint: str,
    ) -> dict[str, Any]:
        url = (
            f"{self.config.base_url}/"
            f"{endpoint.lstrip('/')}"
        )

        try:
            response = requests.get(
                url,
                headers=self.headers,
                timeout=self.config.timeout,
            )

            response.raise_for_status()

        except requests.RequestException as error:
            raise VirusTotalError(
                f"VirusTotal request failed: {error}"
            ) from error

        payload = response.json()

        if not isinstance(payload, dict):
            raise VirusTotalError(
                "VirusTotal returned an invalid response."
            )

        return payload

    def lookup_ip(
        self,
        ip_address: str,
    ) -> dict[str, Any]:
        """
        Retrieve intelligence for an IP address.
        """

        value = ip_address.strip()

        if not value:
            raise ValueError(
                "IP address cannot be empty."
            )

        return self._request(
            f"ip_addresses/{value}"
        )

    def lookup_domain(
        self,
        domain: str,
    ) -> dict[str, Any]:
        """
        Retrieve intelligence for a domain.
        """

        value = domain.strip()

        if not value:
            raise ValueError(
                "Domain cannot be empty."
            )

        return self._request(
            f"domains/{value}"
        )

    def lookup_file_hash(
        self,
        file_hash: str,
    ) -> dict[str, Any]:
        """
        Retrieve intelligence for a file hash.
        """

        value = file_hash.strip()

        if not value:
            raise ValueError(
                "File hash cannot be empty."
            )

        return self._request(
            f"files/{value}"
        )

    def lookup_url(
        self,
        url: str,
    ) -> dict[str, Any]:
        """
        Retrieve intelligence for a URL.

        VirusTotal URL objects require a URL identifier.
        The identifier is generated separately before
        requesting the URL object.
        """

        value = url.strip()

        if not value:
            raise ValueError(
                "URL cannot be empty."
            )

        parsed = urlparse(value)

        if not parsed.scheme or not parsed.netloc:
            raise ValueError(
                "URL must include a valid scheme and host."
            )

        import base64

        url_id = (
            base64.urlsafe_b64encode(
                value.encode("utf-8")
            )
            .decode("ascii")
            .strip("=")
        )

        return self._request(
            f"urls/{url_id}"
        )