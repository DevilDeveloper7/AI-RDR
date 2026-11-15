"""Settings for the M6 -> M5 gateway link, read from environment variables (see .env.example).

Nothing secret is ever read from an environment VALUE: the gateway signing key and the SSH private key are FILES,
and only their paths are configured. Error messages never contain key material.
"""
import os
import stat
from dataclasses import dataclass
from pathlib import Path

USER_ROLES = ("viewer", "analyst", "responder")  # roles M6 may claim for the logged-in analyst; 'connector' is service-only
_REQUIRED = ("M5_SSH_HOST", "M5_SSH_USER", "M5_SSH_IDENTITY_FILE", "M5_SSH_KNOWN_HOSTS_FILE", "M5_GATEWAY_KEY_FILE", "M5_AGENT_ID")
_DEFAULT_DATA_DIR = Path(__file__).resolve().parents[4] / "data"


class M5ConfigError(ValueError):
    """Missing or unsafe M5 gateway configuration."""


@dataclass(frozen=True)
class M5GatewayConfig:
    host: str
    user: str
    identity_file: str
    known_hosts_file: str
    key_file: str
    agent_id: str
    port: int = 22
    issuer: str = "m6-backend"
    timeout: float = 45.0
    service_id: str = "m6-backend"
    analyst_id: str = "m6-analyst"
    analyst_roles: tuple = ("analyst",)
    data_dir: str = str(_DEFAULT_DATA_DIR)

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env
        get = lambda key, default="": (env.get(key) or default).strip()
        missing = [key for key in _REQUIRED if not get(key)]
        if missing:
            raise M5ConfigError("Missing M5 settings: " + ", ".join(missing))
        try:
            port, timeout = int(get("M5_SSH_PORT", "22")), float(get("M5_TIMEOUT", "45"))
        except ValueError:
            raise M5ConfigError("M5_SSH_PORT must be an integer and M5_TIMEOUT a number of seconds.")
        if not 1 <= port <= 65535 or not 5 <= timeout <= 60:  # M5 rejects requests that live longer than 60 s
            raise M5ConfigError("M5_SSH_PORT must be 1-65535 and M5_TIMEOUT 5-60 seconds.")
        roles = tuple(r.strip() for r in get("M5_ANALYST_ROLES", "analyst").split(",") if r.strip())
        if not roles or any(r not in USER_ROLES for r in roles):
            raise M5ConfigError("M5_ANALYST_ROLES must list roles from: " + ", ".join(USER_ROLES))
        return cls(host=get("M5_SSH_HOST"), user=get("M5_SSH_USER"), identity_file=get("M5_SSH_IDENTITY_FILE"),
                   known_hosts_file=get("M5_SSH_KNOWN_HOSTS_FILE"), key_file=get("M5_GATEWAY_KEY_FILE"),
                   agent_id=get("M5_AGENT_ID"), port=port, issuer=get("M5_ISSUER", "m6-backend"), timeout=timeout,
                   service_id=get("M5_SERVICE_ID", "m6-backend"),
                   analyst_id=get("M5_ANALYST_ID") or get("ANALYST_NAME") or "m6-analyst", analyst_roles=roles,
                   data_dir=get("M6_DATA_DIR") or str(_DEFAULT_DATA_DIR))


def read_key(path):
    """Gateway signing key: a private regular file owned by this user, 32-4096 bytes. Never logged."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        raise M5ConfigError("The gateway key file cannot be opened (check M5_GATEWAY_KEY_FILE; symlinks are refused).")
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise M5ConfigError("The gateway key file must be a regular file owned by you with no group/other access (chmod 600).")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            key = stream.read(4097)
    finally:
        os.close(fd)
    if not 32 <= len(key) <= 4096:
        raise M5ConfigError("The gateway key file must contain 32 to 4096 bytes.")
    return key
