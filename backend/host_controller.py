"""
HostController abstraction (SDD S6.4.1; task-breakdown.md S4.5;
planning/arm-playbooks-spec.md S1/S "Proposed layout").

`HostController` is the execution channel ARM's actions (actions.py) run
against. One concrete implementation exists in this published tree
(`SSHHostController`), explicitly demo/test scope, not the production design
(arm-playbooks-spec.md S1 says this plainly):

- `SSHHostController` - runs guest-side actions over the already-provisioned
  `ansible-user` SSH channel (passwordless sudo, already on every `airdr-*`
  host for config management). This reuses the config-management channel as
  the action-execution channel for this demo's scope. A production deployment
  would use a dedicated in-guest agent daemon instead (task-breakdown.md
  S4.5's "in-guest agent" design, mirroring the Wazuh agent pattern) - a small
  authenticated daemon per host, not a repurposed Ansible SSH key. This is a
  deliberate, documented engineering tradeoff appropriate for a capstone demo
  on a shared homelab, not a hidden shortcut.

A second implementation calling a hypervisor's API directly for
`isolate`/`snapshot` only (task-breakdown.md S4.5 explains why: those two are
better done at the hypervisor level than trusting a possibly-compromised
guest to isolate or back itself up) exists in the private deployment but is
not part of this published tree.

This class is genuinely importable/instantiable with no live network
access or real credentials - credentials are constructor parameters with
harmless demo-only defaults, never hardcoded secrets. Only *calling* its
methods needs live infra; the test suite (backend/tests/) never does that -
it uses `backend.tests.fakes.FakeHostController` instead.
"""

from __future__ import annotations

import ipaddress
import os
import threading
import time
from abc import ABC, abstractmethod
from typing import Dict, List, Optional


def _looks_like_ip(value: str) -> bool:
    """Best-effort heuristic used to route block_ip_hash/unblock_ip_hash to an
    IP-based firewall rule vs. a plain blocklist-file line for a hash. Not
    meant to be a rigorous validator - just enough to pick a demo-scope
    execution path."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class HostController(ABC):
    """Abstract execution channel for ARM's atomic actions (SDD Table 6.4.1b).

    Forward actions correspond 1:1 to the 7 HostController-backed entries in
    Table 6.4.1b (the 8th, "Notify & open case", isn't a host action at all -
    see actions.notify_and_open_case). Reverse/undo methods exist only for the
    6 reversible actions; `terminate_process` has no reverse counterpart here,
    matching the SDD marking it non-reversible - callers must not fake one
    (see arm.py's undo() and actions.NON_REVERSIBLE_ACTIONS).

    Methods are expected to raise on failure; callers (actions.py) catch
    exceptions and turn them into status="failed" result records rather than
    letting them propagate.
    """

    # ---- forward actions ----
    @abstractmethod
    def isolate(self, host: str) -> None:
        """Quarantine the host from the network. Must preserve whatever
        control channel later steps (e.g. terminate_process) need to still
        reach the host - see PB-01's ordering fix in playbooks.py."""

    @abstractmethod
    def terminate_process(self, host: str, pid: int) -> None:
        """Kill the offending process. No reverse - SDD Table 6.4.1b marks
        this action non-reversible."""

    @abstractmethod
    def block_ip_hash(self, host: str, value: str) -> None:
        """Push a block for an IP or file hash to the firewall/EDR."""

    @abstractmethod
    def quarantine_file(self, host: str, path: str) -> None:
        """Move a suspect file to a secure quarantine store."""

    @abstractmethod
    def lock_directory(self, host: str, path: str) -> None:
        """Deny writes to a PathPredict-predicted target directory."""

    @abstractmethod
    def snapshot(self, host: str) -> str:
        """Create a restore point before encryption. Returns an
        implementation-defined snapshot identifier, needed later by
        remove_snapshot()/restore workflows."""

    @abstractmethod
    def update_policy(self, host: str, rule: str) -> None:
        """Push a detection/blocking rule to FW/EDR/IDS/SIEM."""

    # ---- PathPredict-only additions (task 3.4; planning/pathpredict-spec.md
    # S2/S5) - NOT part of Table 6.4.1b's original 7-action catalogue. Added
    # here rather than a separate interface because PathPredict runs its
    # observation/pre-emptive-backup work through the same execution-channel
    # abstraction as every other ARM action, per the spec's S4.1/S5. These
    # two are purely additive: no existing method's signature or behavior
    # changes, since SSHHostController is already live against a real host
    # on a different, deployed system (see this module's docstring) and must
    # keep working exactly as before.
    @abstractmethod
    def list_directory(self, host: str, path: str) -> List[str]:
        """Directory inventory for PathPredict's within-directory ranking
        (spec S4.1/S4.2) - a single readdir-equivalent call, read-only, cheap,
        safe to run even mid-incident. Returns bare entry names (matching
        `ls`/`os.listdir` semantics), not full paths - callers join with
        `path` themselves."""

    @abstractmethod
    def backup_file(self, host: str, path: str) -> Dict[str, str]:
        """Pre-emptive reversible backup of a PathPredict-predicted target
        (spec S5) - copies the file to a protected location. Reversible/
        additive per Table 6.4.1b's "Snapshot/back up target" reasoning (same
        as snapshot(), just file-scoped rather than host-scoped). Returns an
        implementation-defined dict describing the backup (must carry
        whatever remove_backup() needs to clean it up later, e.g. a
        `backup_id`)."""

    # ---- reverse actions (6 reversible actions in Table 6.4.1b) ----
    @abstractmethod
    def release_host(self, host: str) -> None:
        """Reverse of isolate(): restore normal network connectivity."""

    @abstractmethod
    def unblock_ip_hash(self, host: str, value: str) -> None:
        """Reverse of block_ip_hash()."""

    @abstractmethod
    def unquarantine_file(self, host: str, path: str) -> None:
        """Reverse of quarantine_file(): move the file back."""

    @abstractmethod
    def unlock_directory(self, host: str, path: str) -> None:
        """Reverse of lock_directory()."""

    @abstractmethod
    def remove_snapshot(self, host: str, snapshot_id: str) -> None:
        """'Reverse' of snapshot(): Table 6.4.1b marks snapshot reversible
        only in the additive sense (creating a restore point has no
        disruptive effect to undo) - this is cleanup of the created
        restore point, not undoing damage."""

    @abstractmethod
    def remove_policy(self, host: str, rule: str) -> None:
        """Reverse of update_policy()."""

    @abstractmethod
    def remove_backup(self, host: str, backup_id: str) -> None:
        """Reverse of backup_file(): cleanup of the created backup copy -
        like remove_snapshot(), this is cleanup of an additive artifact
        (nothing disruptive happened that needs undoing), not restoration of
        damage."""


class SSHHostController(HostController):
    """
    Executes actions over SSH using the existing `ansible-user`
    config-management channel as the action-execution channel for this demo
    scope (see module docstring). Uses paramiko rather than shelling out to
    the `ssh` binary: no external process/PATH dependency, structured
    exceptions instead of parsing stderr/exit codes, and one reusable
    connection object per call instead of forking a new `ssh` process each
    time.

    No real credentials are embedded here - `ssh_user`/`ssh_key_path` are
    constructor parameters with harmless-looking demo defaults; nothing
    connects anywhere until a method is actually called with a reachable
    host.

    `AutoAddPolicy` accepts any host key without verification - acceptable
    for a disposable homelab demo, NOT acceptable for a production system
    (which should pin known host keys instead).
    """

    def __init__(
        self,
        ssh_user: str = "ansible-user",
        ssh_key_path: str = "~/.ssh/id_ed25519",
        port: int = 22,
        quarantine_dir: str = "/var/lib/airdr/quarantine",
        policy_file: str = "/etc/airdr/policy.rules",
        blocklist_file: str = "/etc/airdr/blocklist.rules",
        backup_dir: str = "/var/lib/airdr/backups",
    ):
        self.ssh_user = ssh_user
        self.ssh_key_path = os.path.expanduser(ssh_key_path)
        self.port = port
        self.quarantine_dir = quarantine_dir
        self.policy_file = policy_file
        self.blocklist_file = blocklist_file
        self.backup_dir = backup_dir

        # Per-host connection cache (planning/ssh-connection-reuse-spec.md):
        # a fresh paramiko connection on every _exec() call was hammering
        # fail2ban on rapid-fire activity (e.g. PathPredict's per-touch-event
        # list_directory() calls). One instance may talk to multiple hosts
        # (airdr-target for both ARM and PathPredict, potentially others),
        # so this is keyed by host, not a single connection. Guarded by
        # `_lock` since backend/app.py is a multi-threaded Flask app - the
        # lookup/reconnect/exec_command sequence must be serialized per
        # instance so two concurrent requests can't race on the same cached
        # client.
        self._connections: Dict[str, "paramiko.SSHClient"] = {}
        self._lock = threading.Lock()

    def _connect(self, host: str, timeout: float):
        import paramiko

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=host,
            port=self.port,
            username=self.ssh_user,
            key_filename=self.ssh_key_path,
            timeout=timeout,
        )
        return client

    def _exec(self, host: str, command: str, timeout: float = 15.0) -> str:
        import paramiko  # imported lazily so this module stays importable
        # even if paramiko somehow isn't installed in a given environment.

        # Connection-level failures (dead/stale transport, network blip) are
        # transparently retried once on a fresh connection; a command-level
        # failure (real non-zero exit status) must propagate exactly as
        # before, unretried - see the spec's "never on a command-level
        # failure" requirement.
        connection_errors = (paramiko.SSHException, EOFError, OSError)

        with self._lock:
            client = self._connections.get(host)
            if client is None:
                client = self._connect(host, timeout)
                self._connections[host] = client

            try:
                return self._run(client, host, command, timeout)
            except connection_errors:
                # Stale/dead connection - drop it, reconnect once, retry the
                # same command on the fresh connection. If this second
                # attempt also fails (connection-level or command-level),
                # let it raise normally; we only get one retry.
                try:
                    client.close()
                except Exception:
                    pass
                client = self._connect(host, timeout)
                self._connections[host] = client
                return self._run(client, host, command, timeout)

    @staticmethod
    def _run(client, host: str, command: str, timeout: float) -> str:
        _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        exit_status = stdout.channel.recv_exit_status()
        err = stderr.read().decode(errors="replace")
        if exit_status != 0:
            raise RuntimeError(
                f"SSH command failed (exit {exit_status}) on {host}: {command!r}: {err}"
            )
        return stdout.read().decode(errors="replace")

    def close_all(self) -> None:
        """Close and clear every cached connection. Not required by any
        current caller, but cheap cleanup for tests/shutdown - matches this
        module's general tidiness about not leaking resources."""
        with self._lock:
            for client in self._connections.values():
                try:
                    client.close()
                except Exception:
                    pass
            self._connections.clear()

    # ---- forward actions ----
    def isolate(self, host: str) -> None:
        # OS-level "quarantine bridge" equivalent: DROP all inbound traffic
        # except our own control port, so terminate_process/quarantine_file
        # etc. can still reach the host afterward. Same fix a hypervisor-
        # level controller applies at the vNIC/bridge level instead - see
        # playbooks.py's PB-01 ordering comment for why this matters.
        cmd = (
            "sudo iptables -N airdr_isolate 2>/dev/null; "
            "sudo iptables -F airdr_isolate; "
            f"sudo iptables -A airdr_isolate -p tcp --dport {self.port} -j ACCEPT; "
            "sudo iptables -A airdr_isolate -j DROP; "
            "sudo iptables -C INPUT -j airdr_isolate 2>/dev/null || "
            "sudo iptables -I INPUT -j airdr_isolate"
        )
        self._exec(host, cmd)

    def terminate_process(self, host: str, pid: int) -> None:
        self._exec(host, f"sudo kill -9 {int(pid)}")

    def block_ip_hash(self, host: str, value: str) -> None:
        if _looks_like_ip(value):
            self._exec(host, f"sudo iptables -A INPUT -s {value} -j DROP")
        else:
            self._exec(host, f"echo {value} | sudo tee -a {self.blocklist_file} >/dev/null")

    def quarantine_file(self, host: str, path: str) -> None:
        self._exec(
            host,
            f"sudo mkdir -p {self.quarantine_dir} && "
            f"sudo mv {path} {self.quarantine_dir}/ && "
            f"sudo chmod 000 {self.quarantine_dir}/$(basename {path})",
        )

    def lock_directory(self, host: str, path: str) -> None:
        self._exec(host, f"sudo chattr +i {path}")

    def snapshot(self, host: str) -> str:
        snapshot_id = f"ssh-backup-{int(time.time())}"
        dest = f"{self.backup_dir}/{snapshot_id}"
        # Best-effort file-level backup (no LVM/ZFS assumed available) - a
        # real deployment should use whatever snapshot-capable filesystem the
        # host actually has.
        self._exec(host, f"sudo mkdir -p {dest} && sudo cp -a /home/. {dest}/ 2>/dev/null || true")
        return snapshot_id

    def update_policy(self, host: str, rule: str) -> None:
        self._exec(host, f"echo {rule} | sudo tee -a {self.policy_file} >/dev/null")

    # ---- PathPredict-only additions (see host_controller.py's abstract
    # method docstrings above) ----
    def list_directory(self, host: str, path: str) -> list:
        # `-1` = one entry per line, `-a` = include dotfiles (a ransomware
        # process may well touch those too); `.`/`..` filtered out since
        # they're not real "next targets".
        output = self._exec(host, f"ls -1a {path}")
        return [line for line in output.splitlines() if line not in (".", "..")]

    def backup_file(self, host: str, path: str) -> Dict[str, str]:
        backup_id = f"ssh-file-backup-{int(time.time())}"
        dest_dir = f"{self.backup_dir}/{backup_id}"
        # Best-effort file-level copy, same "no LVM/ZFS assumed available"
        # caveat as snapshot() above.
        self._exec(host, f"sudo mkdir -p {dest_dir} && sudo cp -a {path} {dest_dir}/")
        return {
            "backup_id": backup_id,
            "source_path": path,
            "backup_path": f"{dest_dir}/{os.path.basename(path)}",
        }

    # ---- reverse actions ----
    def release_host(self, host: str) -> None:
        self._exec(
            host,
            "sudo iptables -D INPUT -j airdr_isolate 2>/dev/null; "
            "sudo iptables -F airdr_isolate 2>/dev/null; "
            "sudo iptables -X airdr_isolate 2>/dev/null || true",
        )

    def unblock_ip_hash(self, host: str, value: str) -> None:
        if _looks_like_ip(value):
            self._exec(host, f"sudo iptables -D INPUT -s {value} -j DROP")
        else:
            self._exec(host, f"sudo sed -i '/^{value}$/d' {self.blocklist_file}")

    def unquarantine_file(self, host: str, path: str) -> None:
        self._exec(
            host,
            f"sudo chmod 644 {self.quarantine_dir}/$(basename {path}) && "
            f"sudo mv {self.quarantine_dir}/$(basename {path}) {path}",
        )

    def unlock_directory(self, host: str, path: str) -> None:
        self._exec(host, f"sudo chattr -i {path}")

    def remove_snapshot(self, host: str, snapshot_id: str) -> None:
        if not snapshot_id:
            raise ValueError("no snapshot_id to remove")
        self._exec(host, f"sudo rm -rf {self.backup_dir}/{snapshot_id}")

    def remove_policy(self, host: str, rule: str) -> None:
        self._exec(host, f"sudo sed -i '/^{rule}$/d' {self.policy_file}")

    def remove_backup(self, host: str, backup_id: str) -> None:
        if not backup_id:
            raise ValueError("no backup_id to remove")
        self._exec(host, f"sudo rm -rf {self.backup_dir}/{backup_id}")
