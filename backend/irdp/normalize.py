"""
Normalization: raw Wazuh alerts + auditd/fs events -> the 3 SDD-shaped
documents (ai-rdr-raw-wazuh-logs-*, ai-rdr-fs-events-*,
ai-rdr-normalized-events-*), plus the correlation_id and severity logic that
ties them together at "the main join point" (SDD's own words for the
normalized-events index).

Read backend/irdp/__init__.py's package docstring first - it explains
Correction 1 (auditd, not inotify) and Correction 2 (two different
`event_mask` fields) in full. This module is where both corrections are
actually applied:

  - `_inotify_label_for()` implements Correction 1: an auditd syscall name
    mapped onto the SDD's inotify-flavored STRING vocabulary for
    ai-rdr-fs-events-*'s `event_mask` field. That field's SDD-given shape
    (a per-event string label) is correct for THIS index - only the source
    is auditd, not inotify, and every call site says so.

  - `compute_ml_event_mask()` implements Correction 2: it imports
    `pipeline.features.event_categories.canonical_bit_expr` - the exact
    function the trained model's own feature pipeline uses - and never
    reimplements or approximates its bit values. The result is an integer,
    written only onto `ai-rdr-normalized-events-*` documents, and never onto
    `ai-rdr-fs-events-*`'s `event_mask` string field even though both fields
    share a name.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

import polars as pl

from pipeline.features.event_categories import canonical_bit_expr

from .event_source import HONEY_FILE_RULE_IDS, RawEvent

# Correlation window: events on the same host within this many seconds are
# considered part of the same incident and get the same correlation_id.
# Matches pipeline/features/windowing.py's default 30-second ML feature
# window deliberately - the normalized-events correlation grouping and the
# ML engine's own windowing should agree on what "the same incident" means,
# even though this pipeline computes its own bitmask aggregate rather than
# calling windowing.py directly (windowing.py is built for offline
# DataFrame-shaped training data, not a live per-event stream).
CORRELATION_WINDOW_SECONDS = 30

# Correction 1: auditd syscall -> the SDD's inotify-flavored event_mask
# vocabulary for ai-rdr-fs-events-*. The SDD's §6.1 example list is
# "IN_ACCESS, IN_MODIFY, IN_DELETE, IN_CLOSE_WRITE" (explicitly "such as",
# not exhaustive) - IN_MOVED_TO is added here for renames since auditd's
# real rule 100103 (task-breakdown.md S2.2) produces exactly that operation
# and inotify's own real mask vocabulary already defines IN_MOVED_TO/
# IN_MOVED_FROM, so this is a defensible extension, not an invented value.
_AUDITD_SYSCALL_TO_INOTIFY_LABEL = {
    "read": "IN_ACCESS",
    "write": "IN_MODIFY",
    "rename": "IN_MOVED_TO",
    "delete": "IN_DELETE",
}

# Tier-1 event_type vocabulary (pipeline/features/event_categories.py's own
# input vocabulary) inferred from an auditd syscall - used only to compute
# the ML-facing bitmask (Correction 2), never written to any document
# directly.
_AUDITD_SYSCALL_TO_TIER1_EVENT_TYPE = {
    "read": "file_access",
    "write": "file_modify",
    # No rename-specific bit exists in event_categories.py's 13-bit
    # vocabulary (see that module's docstring) - a rename modifies a
    # directory entry, so file_modify is the closest real category rather
    # than inventing a 14th bit this pipeline alone would use.
    "rename": "file_modify",
    "delete": "file_delete",
}


def _parse_ts(ts: str) -> datetime:
    """Real bug found and fixed live on `airdr-detect` (2026-09-30, Python
    3.10): real Wazuh alert timestamps carry a colonless UTC offset (e.g.
    `2026-09-29T11:25:39.610+0000`), which `datetime.fromisoformat()` only
    accepts from Python 3.11 onward - 3.10 (the real deployment target;
    this repo's own dev venv runs 3.14, which never surfaced this) raises
    `ValueError`. Every real event would have crashed this function.
    Insert the missing colon before parsing, rather than relying on the
    interpreter's leniency - correct on every Python version, not just
    3.11+."""
    ts = ts.replace("Z", "+00:00")
    ts = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", ts)
    return datetime.fromisoformat(ts)


def _inotify_label_for(auditd_syscall: Optional[str]) -> Optional[str]:
    """Correction 1. Returns None (rather than guessing) for a syscall this
    pipeline doesn't recognize - an unmapped value should be visible as a
    gap, not silently mislabeled."""
    if auditd_syscall is None:
        return None
    return _AUDITD_SYSCALL_TO_INOTIFY_LABEL.get(auditd_syscall)


def _infer_tier1_event_type(raw: RawEvent) -> str:
    """Pragmatic classifier from a RawEvent into event_categories.py's input
    vocabulary - this mapping is this pipeline's own judgment call (the SDD
    doesn't define it; event_categories.py only defines the vocabulary and
    the vocabulary->bit mapping, not how to derive the vocabulary from a
    live Wazuh/auditd event). Never invents a new category outside that
    module's own vocabulary - anything not confidently classified below
    falls through to "other", which event_categories.canonical_bit_expr
    already maps to ANOMALY_OTHER (its own documented fallback for
    behaviorally-generic events, e.g. plain `wazuh:*` decoder noise).
    """
    if raw.honey_file_triggered or raw.kind == "fs_event" or raw.auditd_syscall:
        mapped = _AUDITD_SYSCALL_TO_TIER1_EVENT_TYPE.get(raw.auditd_syscall or "")
        if mapped:
            return mapped
        return "file_access"  # a flagged fs-relevant event with no more specific op known

    text = f"{raw.mitre_technique or ''} {raw.process_name or ''} {raw.raw_message or ''}".lower()
    if raw.mitre_technique and raw.mitre_technique.upper().startswith("T1059"):
        return "process_spawn"
    # Checked before the generic src_ip/dest_ip network fallback below: a
    # real auth-failure alert (e.g. sshd) very often carries a source IP
    # too, and "authentication" is the more behaviorally specific category
    # for it - network_connection is meant for alerts that are ABOUT network
    # activity itself (e.g. a firewall/IDS match), not every alert that
    # happens to mention an IP.
    if "auth" in text or "sshd" in text or "login" in text:
        return "authentication"
    if raw.src_ip or raw.dest_ip:
        return "network_connection"
    return "other"


def correlation_id_for(raw: RawEvent) -> str:
    """Deterministic correlation_id shared by every RawEvent on the same
    host within the same CORRELATION_WINDOW_SECONDS bucket - "derived from
    host_id + a time-proximity window", exactly as irdp-pipeline-spec.md
    suggests. Two RawEvents from the same real-world incident (e.g. a
    honey-file Wazuh alert and the auditd fs_event record of the same file
    touch) land in the same bucket even when they arrive as two separate
    RawEvents, since real telemetry for one touch rarely shares an identical
    timestamp.
    """
    ts = _parse_ts(raw.timestamp)
    bucket = int(ts.timestamp() // CORRELATION_WINDOW_SECONDS)
    key = f"{raw.host_id}:{bucket}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _synthesize_event_id(raw: RawEvent) -> str:
    """Fallback event_id for a RawEvent whose source didn't supply one
    (e.g. a synthetic honey-file alert fixture in a test) - deterministic
    from content, not random, so re-running the same input twice produces
    the same id (idempotency-friendly, matching arm.py's own
    compute_action_id() convention elsewhere in this backend)."""
    key = f"{raw.kind}:{raw.timestamp}:{raw.host_id}:{raw.file_path}:{raw.rule_id}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _entity_id_for(raw: RawEvent) -> str:
    if raw.process_id is not None:
        return f"{raw.host_id}:{raw.process_id}"
    return raw.host_id


def to_raw_wazuh_log_doc(raw: RawEvent) -> Dict[str, Any]:
    """ai-rdr-raw-wazuh-logs-* shape - SDD primary fields verbatim:
    @timestamp, agent_id, host_name, rule_id, mitre_technique, process_name,
    src_ip, dest_ip, raw_message."""
    assert raw.kind == "wazuh_alert", "to_raw_wazuh_log_doc() is only valid for kind='wazuh_alert'"
    return {
        "@timestamp": raw.timestamp,
        "agent_id": raw.agent_id,
        "host_name": raw.host_name,
        "rule_id": raw.rule_id,
        "mitre_technique": raw.mitre_technique,
        "process_name": raw.process_name,
        "src_ip": raw.src_ip,
        "dest_ip": raw.dest_ip,
        "raw_message": raw.raw_message,
    }


def to_fs_event_doc(raw: RawEvent) -> Dict[str, Any]:
    """ai-rdr-fs-events-* shape - SDD primary fields verbatim: @timestamp,
    event_id, host_id, event_mask, file_path, process_id, user_id,
    honey_file_triggered.

    Correction 1 applied here: `event_mask` is the SDD's per-event STRING
    label (e.g. "IN_ACCESS"), sourced from auditd via `_inotify_label_for`,
    never from an actual inotify watch. This is deliberately the ONE place
    in this pipeline where the string form of `event_mask` is written -
    everywhere else (ai-rdr-normalized-events-*) uses the integer bitmask
    instead (Correction 2, see compute_ml_event_mask()).
    """
    return {
        "@timestamp": raw.timestamp,
        "event_id": raw.event_id or _synthesize_event_id(raw),
        "host_id": raw.host_id,
        "event_mask": _inotify_label_for(raw.auditd_syscall),
        "file_path": raw.file_path,
        "process_id": raw.process_id,
        "user_id": raw.user_id,
        "honey_file_triggered": raw.honey_file_triggered,
    }


def is_fs_relevant(raw: RawEvent) -> bool:
    """Whether this RawEvent should ALSO produce an ai-rdr-fs-events-*
    document, even when its own `kind` is "wazuh_alert" - true for any
    honey-file rule match (rule_id in HONEY_FILE_RULE_IDS) or an explicit
    honey_file_triggered flag, since those alerts are fundamentally
    file-system events that happened to arrive at this pipeline already
    wrapped as a Wazuh alert (see event_source.RawEvent's docstring)."""
    if raw.kind == "fs_event":
        return True
    return bool(raw.honey_file_triggered or (raw.rule_id in HONEY_FILE_RULE_IDS))


def compute_ml_event_mask(raw_events: Iterable[RawEvent]) -> int:
    """Correction 2. The ML-facing `event_mask` for a correlated group of
    RawEvents (an "incident"), computed EXACTLY the way
    pipeline/features/windowing.py computes it for offline training
    windows: each event's Tier-1 event_type -> canonical bit via
    `event_categories.canonical_bit_expr` (imported, not reimplemented),
    then the *unique* bits summed - which is a bitwise-OR since every bit is
    a disjoint power of two, matching windowing.py's
    `pl.col("_bits").list.sum()` over `pl.col("_bit").unique()` exactly.

    Never hardcodes a parallel copy of FILE_ACCESS/PROCESS_SPAWN/etc. - if
    event_categories.py's bit values or vocabulary ever change, this
    function picks up the change automatically because it calls that
    module's own function, not a local copy.
    """
    event_types = [_infer_tier1_event_type(e) for e in raw_events]
    if not event_types:
        return 0
    df = pl.DataFrame({"event_type": event_types})
    df = df.with_columns(canonical_bit_expr("event_type").alias("_bit"))
    mask = 0
    for bit in df["_bit"].unique().to_list():
        mask |= int(bit)
    return mask


def to_normalized_event_doc(
    raw: RawEvent,
    *,
    correlation_id: str,
    ml_event_mask: int,
) -> Dict[str, Any]:
    """ai-rdr-normalized-events-* shape - SDD primary fields (event_id,
    correlation_id, event_type, host_id, entity_id, entropy_score,
    anomaly_score, confidence_level, severity, response_status), plus
    `@timestamp` (needed for any time-series index, even though the SDD's
    abbreviated primary-fields list for this one index doesn't spell it
    out - every OTHER index in the same table does list it) and the
    ML-facing `event_mask` bitmask (Correction 2 - see module docstring for
    why this pipeline adds it here despite it not being in the SDD's
    abbreviated list either).

    `entropy_score`/`anomaly_score`/`confidence_level` are left `None`
    here on purpose - populating them is live ML inference's job (task
    4.2/Risk Fusion), explicitly out of this pipeline's scope; this
    pipeline must not fabricate placeholder scores to make the index look
    used (task instructions).

    `severity` is the deliberately minimal 2-tier rule (irdp-pipeline-spec
    .md): honey_file_triggered=true -> "critical", everything else ->
    "low". No Medium/High - there is no real signal to back them yet.

    `honey_file_triggered` itself is ALSO denormalized onto this document
    (same judgment call as `event_mask`/`@timestamp` above - not in the
    SDD's abbreviated primary-fields list for THIS index, which only
    defines it for ai-rdr-fs-events-*): the SDD calls normalized-events "the
    main join point" where "every detection layer... add[s]... onto the
    same document lineage" - Risk Fusion (task 4.4) and ARM both need this
    exact signal without joining back to ai-rdr-fs-events-* by
    correlation_id every time, and severity alone loses the raw boolean
    (a future 3rd tier could change what "critical" implies; the raw flag
    should stay legible independent of that).
    """
    return {
        "@timestamp": raw.timestamp,
        "event_id": raw.event_id or _synthesize_event_id(raw),
        "correlation_id": correlation_id,
        "event_type": _infer_tier1_event_type(raw),
        "host_id": raw.host_id,
        "entity_id": _entity_id_for(raw),
        "entropy_score": None,
        "anomaly_score": None,
        "confidence_level": None,
        "severity": "critical" if raw.honey_file_triggered else "low",
        "response_status": "new",
        "event_mask": ml_event_mask,
        "honey_file_triggered": raw.honey_file_triggered,
    }
