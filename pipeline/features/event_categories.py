"""Canonical event_mask vocabulary shared across all 4 Tier-1 datasets.

The raw `event_type` vocabulary across the four normalized sources is NOT one shared
set -- ELFEN has `process_config`/`process_info`, EN2025 has a dozen Windows-specific
categories (`registry_*`, `crypto_operation`, `thread_control`, `service_control`,
`process_manipulation`, `process_terminate`), the Lifecycle dataset has
`hardware_counter_sample`/`syscall`, and Linux-APT-2024 has `authentication`,
`compliance_check`, `anomaly_detection`, `package_management`, `other`, and a long tail
of `wazuh:<decoder>` values (verified via a distinct-value scan of all four normalized
parquet files before writing this). A single `event_mask` bitmask feature usable by one
model across all 4 sources needs bit N to mean the same thing regardless of which source
produced the row -- so this module folds the ~28 raw event_type values down into 13
semantically-coherent bits, rather than giving every dataset-specific string its own bit
(which would make the mask source-identifying rather than behavior-describing, and blow
up to 20+ bits for what's mostly long-tail Wazuh decoder-name noise).

Mapping (documented here, not just in code, since this is a judgment call):
  FILE_ACCESS   -- file_access
  FILE_MODIFY   -- file_modify
  FILE_DELETE   -- file_delete
  PROCESS_SPAWN -- process_spawn
  PROCESS_OTHER -- process_terminate, process_manipulation, process_config, process_info
  NETWORK       -- network_connection
  REGISTRY      -- registry_access, registry_modify, registry_delete
  CRYPTO        -- crypto_operation
  THREAD        -- thread_control
  SERVICE       -- service_control
  SYSCALL_GENERIC -- syscall, hardware_counter_sample
  AUTH          -- authentication
  ANOMALY_OTHER -- anomaly_detection, compliance_check, package_management, other, and
                   the fallback for anything unrecognized (incl. every `wazuh:*` value --
                   these are generic built-in Wazuh alert types with no behavioral
                   category of their own per data/normalized/SUMMARY.md)
"""

from __future__ import annotations

import polars as pl

FILE_ACCESS = 1 << 0
FILE_MODIFY = 1 << 1
FILE_DELETE = 1 << 2
PROCESS_SPAWN = 1 << 3
PROCESS_OTHER = 1 << 4
NETWORK = 1 << 5
REGISTRY = 1 << 6
CRYPTO = 1 << 7
THREAD = 1 << 8
SERVICE = 1 << 9
SYSCALL_GENERIC = 1 << 10
AUTH = 1 << 11
ANOMALY_OTHER = 1 << 12

_EVENT_TYPE_TO_BIT = {
    "file_access": FILE_ACCESS,
    "file_modify": FILE_MODIFY,
    "file_delete": FILE_DELETE,
    "process_spawn": PROCESS_SPAWN,
    "process_terminate": PROCESS_OTHER,
    "process_manipulation": PROCESS_OTHER,
    "process_config": PROCESS_OTHER,
    "process_info": PROCESS_OTHER,
    "network_connection": NETWORK,
    "registry_access": REGISTRY,
    "registry_modify": REGISTRY,
    "registry_delete": REGISTRY,
    "crypto_operation": CRYPTO,
    "thread_control": THREAD,
    "service_control": SERVICE,
    "syscall": SYSCALL_GENERIC,
    "hardware_counter_sample": SYSCALL_GENERIC,
    "authentication": AUTH,
    "anomaly_detection": ANOMALY_OTHER,
    "compliance_check": ANOMALY_OTHER,
    "package_management": ANOMALY_OTHER,
    "other": ANOMALY_OTHER,
}

BIT_NAMES = {
    FILE_ACCESS: "FILE_ACCESS",
    FILE_MODIFY: "FILE_MODIFY",
    FILE_DELETE: "FILE_DELETE",
    PROCESS_SPAWN: "PROCESS_SPAWN",
    PROCESS_OTHER: "PROCESS_OTHER",
    NETWORK: "NETWORK",
    REGISTRY: "REGISTRY",
    CRYPTO: "CRYPTO",
    THREAD: "THREAD",
    SERVICE: "SERVICE",
    SYSCALL_GENERIC: "SYSCALL_GENERIC",
    AUTH: "AUTH",
    ANOMALY_OTHER: "ANOMALY_OTHER",
}


def canonical_bit_expr(event_type_col: str = "event_type") -> pl.Expr:
    """Row-level Int32 canonical bit for `event_type_col`. Anything starting with
    `wazuh:` (a long tail of ~7 generic Linux-APT-2024 decoder names, none behaviorally
    distinct) or otherwise unrecognized falls back to ANOMALY_OTHER."""
    col = pl.col(event_type_col)
    return (
        pl.when(col.str.starts_with("wazuh:"))
        .then(pl.lit(ANOMALY_OTHER, dtype=pl.Int32))
        .otherwise(
            col.replace_strict(_EVENT_TYPE_TO_BIT, default=ANOMALY_OTHER, return_dtype=pl.Int32)
        )
    )
