"""Shared data and offline HTTP responses for tests."""

import json
import sys
from pathlib import Path
from typing import Any

import pytest
import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def load(name: str) -> Any:
    """Read a recorded JSON response."""
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class FakeResponse:
    def __init__(self, payload: Any) -> None:
        self._payload = payload

    def json(self) -> Any:
        return self._payload

    def raise_for_status(self) -> None:
        pass


@pytest.fixture
def entry_response():
    return load("entry.json")


@pytest.fixture
def entry(entry_response):
    return next(iter(entry_response.values()))


@pytest.fixture
def latest_checkpoint():
    return load("latest_checkpoint.json")


@pytest.fixture
def old_checkpoint():
    return load("old_checkpoint.json")


@pytest.fixture
def consistency_proof():
    return load("consistency_proof.json")


@pytest.fixture
def artifact_path():
    return ROOT / "artifact.md"


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    """Fail if a test accidentally attempts a real HTTP request."""

    def blocked_request(*args, **kwargs):
        raise AssertionError("Tests must not make real HTTP requests.")

    monkeypatch.setattr(requests.sessions.Session, "request", blocked_request)


@pytest.fixture
def fake_rekor(monkeypatch, entry_response, latest_checkpoint, consistency_proof):
    """Replace Rekor requests with recorded responses."""
    import main

    def fake_get(url, params=None, timeout=None):
        if url.endswith("/log/entries"):
            return FakeResponse(entry_response)
        if url.endswith("/log/proof"):
            return FakeResponse(consistency_proof)
        if url.endswith("/log"):
            return FakeResponse(latest_checkpoint)
        raise AssertionError(f"Unexpected test URL: {url}")

    monkeypatch.setattr(main.requests, "get", fake_get)
    return fake_get
