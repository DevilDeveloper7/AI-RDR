"""
IRDP - Intelligent Ransomware Data Pipeline (SDD S4.1.1; task 4.1;
planning/irdp-pipeline-spec.md). Phase A: the real, importable, locally-
testable package - no live OpenSearch/Wazuh credentials or network access are
assumed or required to import or unit-test it (mirrors backend/host_controller
.py's own framing for ARM's Phase A).

This is a *polling consumer*, not a streaming pipeline - latency isn't
critical here since the honey-file path already bypasses this pipeline for
the time-sensitive case (irdp-pipeline-spec.md's own scoping). A real
deployment calls `run_once()` on a timer/loop; building that timer/loop is
explicitly out of this phase's scope - see pipeline.run_once's docstring.

## Layout (a small sub-package rather than one flat backend/irdp.py)

The spec left the flat-file-vs-package choice to this task's judgment. A
single file would have mixed five genuinely separate concerns (event source,
checkpoint store, normalization/correlation rules, writer, orchestration)
that each want their own ABC + fake + real implementation, same as
backend/host_controller.py does for one concern alone. Splitting them mirrors
that existing pattern instead of fighting it:

  event_source.py   RawEvent, WazuhEventSource (ABC) + RealWazuhEventSource
  checkpoint.py      CheckpointStore (ABC) + InMemoryCheckpointStore/FileCheckpointStore
  normalize.py       correlation_id / severity / event_type / ML-bitmask logic,
                     and the 3 document-shape builders
  writer.py          EventWriter (ABC) + OpenSearchEventWriter (stub)
  pipeline.py        run_once() - the single-pass orchestration

`backend.tests.fakes` (matching the existing FakeHostController convention)
holds `FakeEventSource`/`FakeEventWriter` - no live credentials needed to run
backend/tests/.

## The two corrections this module deliberately encodes (see irdp-pipeline-
## spec.md for the full reasoning - summarized here since it's easy to get
## wrong by pattern-matching on the SDD's own field names)

**Correction 1**: the SDD's `ai-rdr-fs-events-*` design says "Linux inotify
events". This project's actual, deployed, verified detection path is auditd
(task-breakdown.md S2.2: rules 100100/100103, MITRE T1486) - inotify was
never made to work. `event_source.py`/`normalize.py` build around auditd and
say so explicitly in comments; they never claim to be inotify-sourced. The
fs-events document's `event_mask` field keeps its SDD-given name and its
SDD-given STRING-label shape (e.g. "IN_ACCESS") - that shape is correct for
*this* index - it's just populated by mapping an auditd syscall
(open/read/write/rename/unlink) onto the inotify-flavored vocabulary, not by
reading a real inotify mask.

**Correction 2 (the one not to get wrong)**: `pipeline/features/
event_categories.py` defines a *completely different* `event_mask` - an
integer bitmask, one of the trained model's 8 input features, computed by
OR-ing together canonical category bits over a time window (see that
module's own docstring and pipeline/features/windowing.py's
`_bits.unique().list.sum()`, which is exactly a bitwise-OR since the bits are
disjoint powers of two). `normalize.py`'s `compute_ml_event_mask()` imports
and reuses that module's `canonical_bit_expr()` directly - it does not
reimplement or approximate the bit values - and writes the result only onto
the ML-facing `ai-rdr-normalized-events-*` document, under the same field
name but never confused with the per-event string label above. The SDD's own
"primary fields" list for `ai-rdr-normalized-events-*` doesn't spell this
field out (it lists `event_id, correlation_id, event_type, host_id,
entity_id, entropy_score, anomaly_score, confidence_level, severity,
response_status`) - this pipeline adds it anyway because that index is the
SDD's own stated "main join point... used by... the ML engine", and Correction
2 is explicitly about not silently feeding that engine the wrong shape once
live inference exists. This is a judgment call, documented here rather than
silently assumed.
"""

from __future__ import annotations

from .checkpoint import CheckpointStore, FileCheckpointStore, InMemoryCheckpointStore
from .event_source import HONEY_FILE_RULE_IDS, RawEvent, RealWazuhEventSource, WazuhEventSource
from .normalize import (
    compute_ml_event_mask,
    correlation_id_for,
    to_fs_event_doc,
    to_normalized_event_doc,
    to_raw_wazuh_log_doc,
)
from .pipeline import run_once
from .writer import EventWriter, OpenSearchEventWriter

__all__ = [
    "CheckpointStore",
    "FileCheckpointStore",
    "InMemoryCheckpointStore",
    "HONEY_FILE_RULE_IDS",
    "RawEvent",
    "RealWazuhEventSource",
    "WazuhEventSource",
    "compute_ml_event_mask",
    "correlation_id_for",
    "to_fs_event_doc",
    "to_normalized_event_doc",
    "to_raw_wazuh_log_doc",
    "run_once",
    "EventWriter",
    "OpenSearchEventWriter",
]
