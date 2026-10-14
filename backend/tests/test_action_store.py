"""
OpenSearchActionStore tests (backend/arm.py) - the fix for the in-memory
ActionStore silently losing pending-approval records on a restart, found
live 2026-09-29 (see planning/arm-deployment-progress.md's "Known
limitation" section).

No live OpenSearch access - every `requests` call is mocked. This tests
the store's own get/put/all HTTP-request-building logic, not a live
indexer, matching this project's existing precedent (RealWazuhEventSource
in backend/irdp/event_source.py is likewise never exercised against a real
indexer in this repo's own test suite - only in live deployment).
"""

from unittest.mock import MagicMock, patch

import pytest
import requests

from backend.arm import OpenSearchActionStore


@pytest.fixture
def store() -> OpenSearchActionStore:
    return OpenSearchActionStore(
        host="airdr-siem.example",
        username="irdp-writer",
        password="secret",
        index="ai-rdr-arm-action-state",
    )


def _fake_response(status_code=200, json_body=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body or {}
    resp.raise_for_status.side_effect = (
        requests.HTTPError() if status_code >= 400 else None
    )
    return resp


def test_put_sends_document_to_correct_id_and_index(store):
    record = {"action_id": "abc123", "status": "pending_approval", "playbook_id": "PB-01"}
    with patch("backend.arm.requests.put", return_value=_fake_response()) as mock_put:
        store.put(record)

    mock_put.assert_called_once()
    _, kwargs = mock_put.call_args
    url = mock_put.call_args[0][0]
    assert "ai-rdr-arm-action-state" in url
    assert "abc123" in url
    assert kwargs["json"] == record
    assert kwargs["auth"] == ("irdp-writer", "secret")


def test_get_returns_source_when_found(store):
    doc = {"_source": {"action_id": "abc123", "status": "executed"}}
    with patch("backend.arm.requests.get", return_value=_fake_response(200, doc)):
        result = store.get("abc123")
    assert result == {"action_id": "abc123", "status": "executed"}


def test_get_returns_none_on_404_not_error(store):
    with patch("backend.arm.requests.get", return_value=_fake_response(404)):
        result = store.get("does-not-exist")
    assert result is None


def test_all_returns_every_hit_source(store):
    search_result = {
        "hits": {
            "hits": [
                {"_source": {"action_id": "a1", "status": "pending_approval"}},
                {"_source": {"action_id": "a2", "status": "executed"}},
            ]
        }
    }
    with patch("backend.arm.requests.post", return_value=_fake_response(200, search_result)):
        result = store.all()
    assert result == [
        {"action_id": "a1", "status": "pending_approval"},
        {"action_id": "a2", "status": "executed"},
    ]


def test_put_raises_on_http_error(store):
    with patch("backend.arm.requests.put", return_value=_fake_response(500)):
        with pytest.raises(requests.HTTPError):
            store.put({"action_id": "x"})


def test_default_index_is_not_the_response_audit_glob(store):
    # Deliberately NOT ai-rdr-response-audit-* - see the class docstring for
    # why (that index is AuditLog's append-only log, a different shape).
    assert store.index == "ai-rdr-arm-action-state"
    assert not store.index.startswith("ai-rdr-response-audit")
