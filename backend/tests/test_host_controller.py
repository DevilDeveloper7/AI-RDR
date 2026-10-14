"""
Tests for `backend.host_controller.SSHHostController`.

No file in this repo previously exercised `SSHHostController` directly (the
rest of the suite uses `backend.tests.fakes.FakeHostController` instead - see
host_controller.py's module docstring). This file does two jobs at once:

1. Pins every `SSHHostController` method's exact command string, `paramiko`
   call shape, and exception behavior as it exists today - the baseline that
   planning/ssh-connection-reuse-spec.md's connection-reuse fix must not
   disturb for any genuine command failure or any existing command string.
2. Exercises the connection-reuse/reconnect-on-failure/thread-safety
   behavior the spec adds on top of that baseline.

None of this touches real SSH or a real host: `paramiko.SSHClient` is
monkeypatched to a fake that records what was asked of it and lets each test
script exactly how it responds.
"""

from __future__ import annotations

import re
import threading
import time

import paramiko
import pytest

from backend.host_controller import SSHHostController


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeChannel:
    def __init__(self, exit_status: int):
        self._exit_status = exit_status

    def recv_exit_status(self):
        return self._exit_status


class _FakeStdout:
    def __init__(self, data: bytes, exit_status: int):
        self._data = data
        self.channel = _FakeChannel(exit_status)

    def read(self):
        return self._data


class _FakeStream:
    def __init__(self, data: bytes):
        self._data = data

    def read(self):
        return self._data


class FakeSSHClient:
    """Stand-in for `paramiko.SSHClient`.

    `default_output` is an (stdout: str, exit_status: int, stderr: str)
    tuple used for every `exec_command()` call unless `exec_side_effects`
    has a queued override (an `Exception` instance to raise, consumed once).
    """

    def __init__(self):
        self.connect_calls: list[dict] = []
        self.exec_calls: list[str] = []
        self.closed = False
        self.default_output = ("", 0, "")
        self.exec_side_effects: list[Exception] = []

    def set_missing_host_key_policy(self, policy):
        pass

    def connect(self, hostname, port, username, key_filename, timeout):
        self.connect_calls.append(
            dict(
                hostname=hostname,
                port=port,
                username=username,
                key_filename=key_filename,
                timeout=timeout,
            )
        )

    def exec_command(self, command, timeout=None):
        self.exec_calls.append(command)
        if self.exec_side_effects:
            effect = self.exec_side_effects.pop(0)
            raise effect
        out, status, err = self.default_output
        return None, _FakeStdout(out.encode(), status), _FakeStream(err.encode())

    def close(self):
        self.closed = True


class FakeParamikoFactory:
    """Callable that stands in for the `paramiko.SSHClient` class itself.

    Every client it creates starts out with `default_output`; tests that
    need a *specific* client to misbehave mutate that client's
    `exec_side_effects`/`default_output` directly after it's been created
    (e.g. after the connection-establishing first call).
    """

    def __init__(self):
        self.clients: list[FakeSSHClient] = []
        self.default_output = ("", 0, "")

    def __call__(self):
        client = FakeSSHClient()
        client.default_output = self.default_output
        self.clients.append(client)
        return client


@pytest.fixture
def fake_ssh(monkeypatch):
    factory = FakeParamikoFactory()
    monkeypatch.setattr(paramiko, "SSHClient", factory)
    return factory


@pytest.fixture
def controller():
    return SSHHostController()


# ---------------------------------------------------------------------------
# Baseline: every method's exact command string, unchanged.
# ---------------------------------------------------------------------------


def test_isolate_command(controller, fake_ssh):
    controller.isolate("airdr-target")
    cmd = fake_ssh.clients[0].exec_calls[0]
    assert cmd == (
        "sudo iptables -N airdr_isolate 2>/dev/null; "
        "sudo iptables -F airdr_isolate; "
        "sudo iptables -A airdr_isolate -p tcp --dport 22 -j ACCEPT; "
        "sudo iptables -A airdr_isolate -j DROP; "
        "sudo iptables -C INPUT -j airdr_isolate 2>/dev/null || "
        "sudo iptables -I INPUT -j airdr_isolate"
    )


def test_terminate_process_command(controller, fake_ssh):
    controller.terminate_process("airdr-target", 1234)
    assert fake_ssh.clients[0].exec_calls[0] == "sudo kill -9 1234"


def test_block_ip_hash_ip_command(controller, fake_ssh):
    controller.block_ip_hash("airdr-target", "10.0.0.5")
    assert fake_ssh.clients[0].exec_calls[0] == "sudo iptables -A INPUT -s 10.0.0.5 -j DROP"


def test_block_ip_hash_hash_command(controller, fake_ssh):
    controller.block_ip_hash("airdr-target", "deadbeef")
    assert fake_ssh.clients[0].exec_calls[0] == (
        "echo deadbeef | sudo tee -a /etc/airdr/blocklist.rules >/dev/null"
    )


def test_quarantine_file_command(controller, fake_ssh):
    controller.quarantine_file("airdr-target", "/tmp/evil.exe")
    assert fake_ssh.clients[0].exec_calls[0] == (
        "sudo mkdir -p /var/lib/airdr/quarantine && "
        "sudo mv /tmp/evil.exe /var/lib/airdr/quarantine/ && "
        "sudo chmod 000 /var/lib/airdr/quarantine/$(basename /tmp/evil.exe)"
    )


def test_lock_directory_command(controller, fake_ssh):
    controller.lock_directory("airdr-target", "/data/secrets")
    assert fake_ssh.clients[0].exec_calls[0] == "sudo chattr +i /data/secrets"


def test_snapshot_command_and_return_value(controller, fake_ssh):
    snapshot_id = controller.snapshot("airdr-target")
    cmd = fake_ssh.clients[0].exec_calls[0]
    assert re.match(r"^ssh-backup-\d+$", snapshot_id)
    assert cmd == (
        f"sudo mkdir -p /var/lib/airdr/backups/{snapshot_id} && "
        f"sudo cp -a /home/. /var/lib/airdr/backups/{snapshot_id}/ 2>/dev/null || true"
    )


def test_update_policy_command(controller, fake_ssh):
    controller.update_policy("airdr-target", "DENY ALL")
    assert fake_ssh.clients[0].exec_calls[0] == (
        "echo DENY ALL | sudo tee -a /etc/airdr/policy.rules >/dev/null"
    )


def test_list_directory_command_and_filtering(controller, fake_ssh):
    fake_ssh.default_output = (".\n..\n.bashrc\nfile.txt\n", 0, "")
    entries = controller.list_directory("airdr-target", "/home/user")
    assert fake_ssh.clients[0].exec_calls[0] == "ls -1a /home/user"
    assert entries == [".bashrc", "file.txt"]


def test_backup_file_command_and_return_value(controller, fake_ssh):
    result = controller.backup_file("airdr-target", "/etc/passwd")
    backup_id = result["backup_id"]
    assert re.match(r"^ssh-file-backup-\d+$", backup_id)
    assert fake_ssh.clients[0].exec_calls[0] == (
        f"sudo mkdir -p /var/lib/airdr/backups/{backup_id} && "
        "sudo cp -a /etc/passwd /var/lib/airdr/backups/" + backup_id + "/"
    )
    assert result == {
        "backup_id": backup_id,
        "source_path": "/etc/passwd",
        "backup_path": f"/var/lib/airdr/backups/{backup_id}/passwd",
    }


def test_release_host_command(controller, fake_ssh):
    controller.release_host("airdr-target")
    assert fake_ssh.clients[0].exec_calls[0] == (
        "sudo iptables -D INPUT -j airdr_isolate 2>/dev/null; "
        "sudo iptables -F airdr_isolate 2>/dev/null; "
        "sudo iptables -X airdr_isolate 2>/dev/null || true"
    )


def test_unblock_ip_hash_ip_command(controller, fake_ssh):
    controller.unblock_ip_hash("airdr-target", "10.0.0.5")
    assert fake_ssh.clients[0].exec_calls[0] == "sudo iptables -D INPUT -s 10.0.0.5 -j DROP"


def test_unblock_ip_hash_hash_command(controller, fake_ssh):
    controller.unblock_ip_hash("airdr-target", "deadbeef")
    assert fake_ssh.clients[0].exec_calls[0] == (
        "sudo sed -i '/^deadbeef$/d' /etc/airdr/blocklist.rules"
    )


def test_unquarantine_file_command(controller, fake_ssh):
    controller.unquarantine_file("airdr-target", "/tmp/evil.exe")
    assert fake_ssh.clients[0].exec_calls[0] == (
        "sudo chmod 644 /var/lib/airdr/quarantine/$(basename /tmp/evil.exe) && "
        "sudo mv /var/lib/airdr/quarantine/$(basename /tmp/evil.exe) /tmp/evil.exe"
    )


def test_unlock_directory_command(controller, fake_ssh):
    controller.unlock_directory("airdr-target", "/data/secrets")
    assert fake_ssh.clients[0].exec_calls[0] == "sudo chattr -i /data/secrets"


def test_remove_snapshot_command(controller, fake_ssh):
    controller.remove_snapshot("airdr-target", "ssh-backup-123")
    assert fake_ssh.clients[0].exec_calls[0] == (
        "sudo rm -rf /var/lib/airdr/backups/ssh-backup-123"
    )


def test_remove_snapshot_requires_snapshot_id(controller, fake_ssh):
    with pytest.raises(ValueError):
        controller.remove_snapshot("airdr-target", "")
    assert fake_ssh.clients == []  # never even tried to connect


def test_remove_policy_command(controller, fake_ssh):
    controller.remove_policy("airdr-target", "DENY ALL")
    assert fake_ssh.clients[0].exec_calls[0] == "sudo sed -i '/^DENY ALL$/d' /etc/airdr/policy.rules"


def test_remove_backup_command(controller, fake_ssh):
    controller.remove_backup("airdr-target", "ssh-file-backup-123")
    assert fake_ssh.clients[0].exec_calls[0] == (
        "sudo rm -rf /var/lib/airdr/backups/ssh-file-backup-123"
    )


def test_remove_backup_requires_backup_id(controller, fake_ssh):
    with pytest.raises(ValueError):
        controller.remove_backup("airdr-target", None)
    assert fake_ssh.clients == []


def test_command_failure_raises_runtime_error_unchanged(controller, fake_ssh):
    fake_ssh.default_output = ("", 1, "permission denied")
    with pytest.raises(RuntimeError) as exc_info:
        controller.terminate_process("airdr-target", 1234)
    assert str(exc_info.value) == (
        "SSH command failed (exit 1) on airdr-target: 'sudo kill -9 1234': permission denied"
    )
    # A genuine command failure is not a connection-level failure: no retry,
    # exactly one client, exactly one exec_command call.
    assert len(fake_ssh.clients) == 1
    assert fake_ssh.clients[0].exec_calls == ["sudo kill -9 1234"]


# ---------------------------------------------------------------------------
# Connection reuse / reconnect-on-failure / thread-safety
# (planning/ssh-connection-reuse-spec.md)
# ---------------------------------------------------------------------------


def test_connection_reused_across_calls(controller, fake_ssh):
    controller._exec("airdr-target", "cmd-one")
    controller._exec("airdr-target", "cmd-two")

    assert len(fake_ssh.clients) == 1
    client = fake_ssh.clients[0]
    assert len(client.connect_calls) == 1
    assert client.exec_calls == ["cmd-one", "cmd-two"]


def test_reconnect_on_connection_level_failure(controller, fake_ssh):
    # First call establishes the cached connection.
    controller._exec("airdr-target", "first")
    assert len(fake_ssh.clients) == 1
    first_client = fake_ssh.clients[0]

    # The *second* use of that cached connection hits a connection-level
    # failure exactly once (simulating a dead transport) - this must trigger
    # exactly one reconnect+retry, and the retried command must succeed.
    first_client.exec_side_effects.append(paramiko.SSHException("broken pipe"))

    result = controller._exec("airdr-target", "second")

    assert result == ""  # fake default successful output
    assert first_client.closed is True
    assert first_client.exec_calls == ["first", "second"]  # "second" is the failed attempt

    assert len(fake_ssh.clients) == 2  # reconnected to a fresh client
    second_client = fake_ssh.clients[1]
    assert len(second_client.connect_calls) == 1
    assert second_client.exec_calls == ["second"]  # exactly one retry, no more


@pytest.mark.parametrize("exc", [EOFError("eof"), OSError("socket closed")])
def test_reconnect_on_other_connection_level_exceptions(controller, fake_ssh, exc):
    controller._exec("airdr-target", "first")
    first_client = fake_ssh.clients[0]
    first_client.exec_side_effects.append(exc)

    result = controller._exec("airdr-target", "second")

    assert result == ""
    assert len(fake_ssh.clients) == 2


def test_two_different_hosts_get_independent_connections(controller, fake_ssh):
    controller._exec("host-a", "cmd-a1")
    controller._exec("host-b", "cmd-b1")
    controller._exec("host-a", "cmd-a2")

    assert len(fake_ssh.clients) == 2
    client_a, client_b = fake_ssh.clients
    assert client_a.connect_calls[0]["hostname"] == "host-a"
    assert client_b.connect_calls[0]["hostname"] == "host-b"
    assert client_a.exec_calls == ["cmd-a1", "cmd-a2"]
    assert client_b.exec_calls == ["cmd-b1"]
    assert len(client_a.connect_calls) == 1
    assert len(client_b.connect_calls) == 1

    # Breaking host-a's connection must never affect host-b's.
    client_a.exec_side_effects.append(paramiko.SSHException("broken pipe"))
    controller._exec("host-a", "cmd-a3")
    assert len(fake_ssh.clients) == 3  # only host-a reconnected
    assert fake_ssh.clients[-1].connect_calls[0]["hostname"] == "host-a"
    assert client_b.exec_calls == ["cmd-b1"]  # untouched


def test_close_all_closes_and_clears_every_cached_connection(controller, fake_ssh):
    controller._exec("host-a", "cmd-a")
    controller._exec("host-b", "cmd-b")
    assert len(fake_ssh.clients) == 2

    controller.close_all()

    assert all(c.closed for c in fake_ssh.clients)
    assert controller._connections == {}

    # A subsequent call reconnects cleanly (cache was actually cleared, not
    # just closed-in-place).
    controller._exec("host-a", "cmd-a-again")
    assert len(fake_ssh.clients) == 3


def test_concurrent_exec_calls_are_serialized_by_the_lock(controller, fake_ssh):
    """Smoke test that `_lock` is actually acquired around the critical
    section: many threads hammering the same cached connection must never
    overlap inside exec_command."""

    active = [0]
    max_concurrent = [0]
    lock_check = threading.Lock()

    class ProbingFakeSSHClient(FakeSSHClient):
        def exec_command(self, command, timeout=None):
            with lock_check:
                active[0] += 1
                max_concurrent[0] = max(max_concurrent[0], active[0])
            time.sleep(0.01)
            result = super().exec_command(command, timeout=timeout)
            with lock_check:
                active[0] -= 1
            return result

    clients: list[ProbingFakeSSHClient] = []

    def factory():
        client = ProbingFakeSSHClient()
        clients.append(client)
        return client

    fake_ssh_module_attr = paramiko.SSHClient
    paramiko.SSHClient = factory
    try:
        threads = [
            threading.Thread(target=controller._exec, args=("airdr-target", f"cmd-{i}"))
            for i in range(10)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        paramiko.SSHClient = fake_ssh_module_attr

    # The lock guarantees: never more than one thread inside exec_command at
    # once, exactly one connection ever created (lookup+connect was also
    # inside the lock), and every command actually ran (none lost/corrupted).
    assert max_concurrent[0] == 1
    assert len(clients) == 1
    assert sorted(clients[0].exec_calls) == sorted(f"cmd-{i}" for i in range(10))
