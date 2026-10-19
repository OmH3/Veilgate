"""Unit tests for JevClient and ShapeRedactor."""

import json
import httpx
import pytest

from veilgate.config.policy_models import (
    JevDecisionRequest,
    JevQuestion,
)
from veilgate.exceptions.types import JevUnavailableError
from veilgate.integrations.jev_client import JevClient, ShapeRedactor


def test_shape_redactor_adheres_to_adr8_canary_leakage_defense() -> None:
    """Verify that ShapeRedactor strips all raw scalar values and leaves zero canary traces."""
    canary_password = "CanarySecretPassword#999"
    canary_card = "4111-2222-3333-4444"
    canary_email = "victim@example.com"

    raw_payload = {
        "user_id": 1042,
        "email": canary_email,
        "credentials": {
            "password": canary_password,
            "card_number": canary_card,
        },
        "flags": [True, False],
        "metadata": None,
    }

    shape = ShapeRedactor.extract_shape(raw_payload)
    shape_json = json.dumps(shape)

    # Invariant: Zero canary values present anywhere in shape serialization
    assert canary_password not in shape_json
    assert canary_card not in shape_json
    assert canary_email not in shape_json
    assert "1042" not in shape_json

    # Structural metadata must be preserved
    assert shape["user_id"] == {"_type": "number"}
    assert shape["email"] == {"_type": "string", "length": len(canary_email)}
    assert shape["credentials"]["password"] == {"_type": "string", "length": len(canary_password)}
    assert shape["flags"]["_type"] == "list"
    assert shape["flags"]["length"] == 2
    assert shape["metadata"] == {"_type": "null"}


@pytest.mark.anyio
async def test_jev_client_decide_happy_path() -> None:
    """Verify successful response parsing with mock HTTP transport."""
    mock_response_data = {
        "model": "jev-latest",
        "answers": {
            "q1": {
                "type": "choice",
                "choice": "PII_HIGH",
                "confidence": 0.98,
            }
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("Authorization") == "Bearer test-key"
        body = json.loads(request.content.decode("utf-8"))
        assert body["model"] == "jev-latest"
        assert "q1" in body["questions"]
        return httpx.Response(200, json=mock_response_data)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        jev = JevClient(api_key="test-key", http_client=client)
        req = JevDecisionRequest(
            model="jev-latest",
            state={"tool": "invoicedb_get", "field": "account_number"},
            questions={
                "q1": JevQuestion(
                    type="choice",
                    instructions="Classify sensitivity",
                    criteria=["SECRET", "PII_HIGH", "PUBLIC", "BLOAT"],
                )
            },
        )
        res = await jev.decide(req)

    assert res.model == "jev-latest"
    assert "q1" in res.answers
    assert res.answers["q1"].choice == "PII_HIGH"
    assert res.answers["q1"].confidence == 0.98


@pytest.mark.anyio
async def test_jev_client_missing_api_key_raises_jev_unavailable() -> None:
    """Verify client raises JevUnavailableError when API key is missing."""
    jev = JevClient(api_key=None)
    req = JevDecisionRequest(
        state={"field": "test"},
        questions={"q1": JevQuestion(type="choice", instructions="test")},
    )
    with pytest.raises(JevUnavailableError) as exc_info:
        await jev.decide(req)

    assert "not configured" in exc_info.value.safe_message


@pytest.mark.anyio
async def test_jev_client_timeout_and_retries_fail_open() -> None:
    """Verify transient timeouts trigger 1 retry and raise JevUnavailableError."""
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        raise httpx.ReadTimeout("Connection timed out waiting for Jev response")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        jev = JevClient(api_key="test-key", http_client=client)
        req = JevDecisionRequest(
            state={"field": "test"},
            questions={"q1": JevQuestion(type="choice", instructions="test")},
        )
        with pytest.raises(JevUnavailableError) as exc_info:
            await jev.decide(req)

    # 1 initial attempt + 1 retry = 2 attempts total
    assert call_count == 2
    assert "unavailable" in exc_info.value.safe_message.lower()


@pytest.mark.anyio
async def test_jev_client_question_batch_limit() -> None:
    """Verify exceeding 8 questions per batch is rejected immediately."""
    jev = JevClient(api_key="test-key")
    questions = {
        f"q{i}": JevQuestion(type="choice", instructions=f"q{i}")
        for i in range(9)
    }
    req = JevDecisionRequest(state={}, questions=questions)

    with pytest.raises(JevUnavailableError) as exc_info:
        await jev.decide(req)

    assert "exceeded maximum limit of 8" in exc_info.value.safe_message
