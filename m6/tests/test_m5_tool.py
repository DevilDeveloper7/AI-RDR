"""The read-only M5 command-line check (backend/m5_tool.py). MOCKED M5 transport."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
import m5_tool  # noqa: E402

from m5_fake_endpoint import KEY, FakeEndpoint, install_aicm_stub  # noqa: E402


@pytest.fixture()
def env(tmp_path, monkeypatch):
    install_aicm_stub(monkeypatch)
    key = tmp_path / "gw.key"
    key.write_bytes(KEY)
    key.chmod(0o600)
    return {"M5_SSH_HOST": "m5.example.test", "M5_SSH_USER": "m6svc", "M5_SSH_IDENTITY_FILE": str(tmp_path / "id"),
            "M5_SSH_KNOWN_HOSTS_FILE": str(tmp_path / "kh"), "M5_GATEWAY_KEY_FILE": str(key), "M5_AGENT_ID": "001",
            "M6_DATA_DIR": str(tmp_path / "data")}


def test_missing_configuration_is_explained_and_exits_2(capsys):
    assert m5_tool.main(["health"], env={}) == 2
    err = capsys.readouterr().err
    assert "M5_SSH_HOST" in err and "M5_GATEWAY_KEY_FILE" in err


def test_commands_work_against_the_mocked_transport(env, capsys):
    ep = FakeEndpoint()
    ep.store.add_case("c1")
    assert m5_tool.main(["health"], env=env, transport=ep.transport) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "Connected"
    assert m5_tool.main(["cases"], env=env, transport=ep.transport) == 0
    assert json.loads(capsys.readouterr().out)["items"][0]["case_id"] == "c1"
    assert m5_tool.main(["timeline", "c1"], env=env, transport=ep.transport) == 0
    assert m5_tool.main(["poll"], env=env, transport=ep.transport) == 0
    assert json.loads(capsys.readouterr().out.strip().splitlines()[-1])["acknowledged"] == 1


def test_a_controlled_failure_exits_1_without_a_traceback(env, capsys):
    ep = FakeEndpoint()
    assert m5_tool.main(["case", "nope"], env=env, transport=ep.transport) == 1
    err = capsys.readouterr().err
    assert "M5_NOT_FOUND" in err and "Traceback" not in err


def test_the_tool_has_no_action_command():
    assert "request_action" not in Path(m5_tool.__file__).read_text() and "submit_action" not in Path(m5_tool.__file__).read_text()
