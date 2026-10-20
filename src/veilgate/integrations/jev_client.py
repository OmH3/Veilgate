"""Asynchronous HTTP client for the Jev probabilistic system-1 inference API.

Implements ADR-8 (shape-only metadata payloads to prevent cloud data leakage)
and provides fail-open degradation via JevUnavailableError when the service is unreachable.
"""

import asyncio
from collections.abc import Mapping
from typing import Any

import httpx
from pydantic import ValidationError

from veilgate.config.policy_models import (
    JevDecisionRequest,
    JevDecisionResponse,
)
from veilgate.exceptions.types import JevUnavailableError
from veilgate.utils.logging_utils import setup_logger

logger = setup_logger("veilgate.integrations.jev_client")


class ShapeRedactor:
    """Utility to convert raw JSON payloads into value-free structural shapes.

    In accordance with ADR-8, ensures cloud APIs only receive metadata regarding
    key names, data types, nullability, and lengths without sensitive data leakage.
    """

    @classmethod
    def extract_shape(cls, data: Any) -> Any:
        """Recursively transform data into its structural type shape.

        Args:
            data: Arbitrary Python JSON-compatible object.

        Returns:
            Redacted shape dictionary or type description.
        """
        if isinstance(data, Mapping):
            return {str(k): cls.extract_shape(v) for k, v in data.items()}
        if isinstance(data, list):
            sample = cls.extract_shape(data[0]) if data else None
            return {
                "_type": "list",
                "length": len(data),
                "item_shape": sample,
            }
        if isinstance(data, str):
            return {"_type": "string", "length": len(data)}
        if isinstance(data, bool):
            return {"_type": "boolean"}
        if isinstance(data, (int, float)):
            return {"_type": "number"}
        if data is None:
            return {"_type": "null"}
        return {"_type": type(data).__name__}


class JevClient:
    """Asynchronous client for Jev system-1 decision requests.

    Responsibilities:
    - Enforce request-level concurrency limits using asyncio.Semaphore.
    - Bound request latency to configured timeout (default 3.0 seconds).
    - Provide 1 automatic retry on transient network failures.
    - Convert all communication and HTTP failures into JevUnavailableError.
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = "https://jevmodel.net",
        timeout_s: float = 3.0,
        max_concurrency: int = 4,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        """Initialize Jev client.

        Args:
            api_key: Jev or TypeSafe API bearer token.
            base_url: Base endpoint URL for Jev service.
            timeout_s: Maximum request wait time before timeout.
            max_concurrency: Maximum parallel in-flight HTTP requests.
            http_client: Optional pre-configured httpx.AsyncClient for testing/mocking.
        """
        self.api_key: str | None = api_key
        self.base_url: str = base_url.rstrip("/")
        self.timeout_s: float = timeout_s
        self._semaphore: asyncio.Semaphore = asyncio.Semaphore(max_concurrency)
        self._client: httpx.AsyncClient | None = http_client

    async def decide(self, request: JevDecisionRequest) -> JevDecisionResponse:
        """Submit a batched shape decision request to Jev.

        Args:
            request: Validated JevDecisionRequest with shape-only state and <= 8 questions.

        Returns:
            JevDecisionResponse containing parsed model answers.

        Raises:
            JevUnavailableError: If service is unconfigured, unreachable, or times out.
        """
        if not self.api_key:
            raise JevUnavailableError(
                safe_message="Jev API key is not configured; degrading to deterministic rules.",
                details={"configured": False},
            )

        if len(request.questions) > 8:
            raise JevUnavailableError(
                safe_message="Jev question batch exceeded maximum limit of 8 questions.",
                details={"count": len(request.questions)},
            )

        url = f"{self.base_url}/v1/systemone"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "Veilgate-Gateway/1.0",
        }
        payload = request.model_dump(exclude_none=True)

        async with self._semaphore:
            attempts = 2
            last_err: Exception | None = None

            for attempt in range(1, attempts + 1):
                try:
                    client = self._client or httpx.AsyncClient(timeout=self.timeout_s)
                    try:
                        response = await client.post(url, json=payload, headers=headers)
                    finally:
                        if self._client is None:
                            await client.aclose()

                    if response.status_code >= 500:
                        raise httpx.HTTPStatusError(
                            f"Server returned status {response.status_code}",
                            request=response.request,
                            response=response,
                        )

                    response.raise_for_status()
                    data = response.json()
                    return JevDecisionResponse.model_validate(data)

                except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPStatusError) as e:
                    last_err = e
                    logger.warning(
                        "Jev request failed on attempt %d/%d: %s",
                        attempt,
                        attempts,
                        str(e),
                    )
                    if attempt < attempts:
                        await asyncio.sleep(0.1)
                except (ValidationError, ValueError) as e:
                    logger.error("Failed to parse Jev response structure: %s", str(e))
                    raise JevUnavailableError(
                        safe_message="Malformed response received from Jev API.",
                        details={"error": str(e)},
                    ) from e
                except Exception as e:
                    logger.error("Unexpected error during Jev decision request: %s", str(e))
                    raise JevUnavailableError(
                        safe_message=f"Unexpected failure contacting Jev: {e}",
                        details={"error": str(e)},
                    ) from e

            raise JevUnavailableError(
                safe_message=f"Jev service unavailable after {attempts} attempts: {last_err}",
                details={"error": str(last_err)},
            ) from last_err
