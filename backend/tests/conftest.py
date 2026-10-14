import pytest

from backend import aicm
from backend.arm import ARM
from backend.tests.fakes import FakeHostController


@pytest.fixture(autouse=True)
def _reset_aicm_default_store():
    """AICM (task 4.6) keeps a process-wide default `CaseStore` so
    `backend.actions.notify_and_open_case()` and `backend.arm.ARM._execute()`
    share state without needing to be threaded through
    `backend.playbooks`'s step definitions (see backend/aicm.py's module
    docstring). That default is reset to a fresh `InMemoryCaseStore` before
    every test - including every pre-existing ARM/playbook/app test, not
    just backend/tests/test_aicm.py's own - so no test's cases leak into
    another's correlation window."""
    aicm.set_default_store(aicm.InMemoryCaseStore())
    yield


@pytest.fixture
def controller() -> FakeHostController:
    return FakeHostController()


@pytest.fixture
def arm(tmp_path, controller) -> ARM:
    """A fresh ARM instance per test, with the audit log/allow-list pointed at
    tmp_path so tests never touch the real backend/audit_log.jsonl or
    backend/critical_assets.yml."""
    return ARM(
        controller=controller,
        audit_log_path=tmp_path / "audit_log.jsonl",
        allow_list_path=tmp_path / "critical_assets.yml",  # doesn't exist -> empty allow-list
    )
