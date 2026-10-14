"""
run_once() - the single-pass orchestration: poll the event source since the
last checkpoint, normalize, write via the EventWriter, advance the
checkpoint. This is what a real deployment would call on a timer/loop -
building that timer/loop is explicitly out of this phase's scope
(irdp-pipeline-spec.md: "a simple polling consumer... latency isn't
critical here since the honey-file path already bypasses this pipeline for
the time-sensitive case").
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from ..host_controller import HostController
from ..pathpredict import (
    IncidentTrackerStore,
    PathPredictWriter,
    advance_incident_and_predict,
    incident_key,
)
from ..risk_fusion import (
    ARM_NOTIFIABLE_TIERS,
    NullThreatIntelClient,
    ThreatIntelClient,
    TriggerSender,
    fuse,
    send_trigger_if_needed,
)
from .checkpoint import CheckpointStore
from .event_source import RawEvent, WazuhEventSource
from .normalize import (
    compute_ml_event_mask,
    correlation_id_for,
    is_fs_relevant,
    to_fs_event_doc,
    to_normalized_event_doc,
    to_raw_wazuh_log_doc,
)
from .writer import EventWriter

if TYPE_CHECKING:
    # Type-checking-only import - see this function's own docstring (task
    # m2-integration) for why `M2Client` is NOT imported at module level
    # here: `backend.m2_client` imports `RawEvent` from
    # `backend.irdp.event_source`, which is exactly the same import-order
    # shape that made `score_events` need a lazy, function-body import below
    # (see that import's own comment) - avoided here entirely since this
    # module only ever calls `m2_client.score(...)` duck-typed, never
    # constructs or isinstance-checks an `M2Client`, so no runtime import is
    # needed at all.
    from ..m2_client import M2Client

DEFAULT_CHECKPOINT_KEY = "irdp"


def run_once(
    source: WazuhEventSource,
    checkpoint_store: CheckpointStore,
    writer: EventWriter,
    *,
    checkpoint_key: str = DEFAULT_CHECKPOINT_KEY,
    threat_intel_client: Optional[ThreatIntelClient] = None,
    trigger_sender: Optional[TriggerSender] = None,
    pathpredict_writer: Optional[PathPredictWriter] = None,
    incident_tracker_store: Optional[IncidentTrackerStore] = None,
    host_controller: Optional[HostController] = None,
    m2_client: Optional["M2Client"] = None,
) -> Dict[str, Any]:
    """One poll-normalize-write-advance pass.

    Steps, matching irdp-pipeline-spec.md's "Implementation" list:
      1. poll() new RawEvents since the stored checkpoint.
      2. For each: write its own raw shape -
         ai-rdr-raw-wazuh-logs-* for kind="wazuh_alert", and
         ai-rdr-fs-events-* for kind="fs_event" OR any wazuh_alert that is
         fs-relevant (honey-file rule match) - see normalize.is_fs_relevant.
      3. Group events into correlation_id buckets (host_id + time window)
         and compute one ML-facing bitmask per bucket (Correction 2), then
         write one ai-rdr-normalized-events-* document per RawEvent, all
         documents in the same bucket sharing both correlation_id and the
         bucket's aggregate event_mask.
      4. Score this batch's RawEvents against the real v3 model
         (backend/ml_scoring.py, task 4.2) and write one
         ai-rdr-ml-detections-* document per (host, process, window) -
         `score_events()` does its own (sample_id, process_id, window_index)
         grouping internally (via the real `build_feature_windows()`), so
         this step is a single call over the whole batch, not something
         this function groups itself. A batch spanning fewer than
         `ml_scoring.WINDOW_SEC` (30s) of real activity for a given entity
         still gets scored - `build_feature_windows` forms one window from
         however many events actually landed in it, same as any offline
         source's last, possibly-partial window.
      5. Advance the checkpoint to the max timestamp seen in this batch -
         see checkpoint.py's docstring for the same-timestamp tiebreak
         limitation this simple watermark accepts.

    `pathpredict_writer`/`incident_tracker_store`/`host_controller` (task
    3.4b; planning/pathpredict-deployment-spec.md Part 1) are all optional
    and all-or-nothing in effect: omitted (every existing caller/test before
    this task), this is a complete no-op, identical to prior behavior. When
    all three are provided, for each entity in this same Risk Fusion loop
    whose `fused["risk_tier"]` lands in `ARM_NOTIFIABLE_TIERS`, this
    collects the group's file-path-bearing `RawEvent`s (sorted by
    timestamp), loads/advances that incident's persisted
    `backend.pathpredict.IncidentState` via `advance_incident_and_predict()`
    (the live incremental hit/miss recording - see that function's own
    docstring for the exact contract), writes the resulting prediction via
    `pathpredict_writer`, and persists the updated state via
    `incident_tracker_store`. Display-only: `backup_file()` is never called
    anywhere in this path (spec's own explicit scope boundary) - an entity
    is skipped for PathPredict this poll (but every other step above still
    runs normally) if it has no file-path events this poll, or if its
    `file_mod_rate` isn't a usable positive number yet (no ETA can be
    computed without one - the same "don't call build_prediction with an
    input it would legitimately raise on, just avoid calling it" guard the
    spec itself calls for on the empty-touched case, applied here too,
    disclosed as this task's own addition, not spec-literal).

    `m2_client` (task m2-integration; planning/m2-integration-spec.md
    Part 1) is optional and a complete no-op when omitted (every existing
    caller/test before this task), matching every other optional param's
    convention above. When provided, for each entity's ML detection this
    poll (same `by_host_process` grouping used for Risk Fusion/PathPredict
    above), calls `m2_client.score(group, run_id=incident_key(...))` and, if
    it returns a result (not `None`), attaches it under a denormalized `m2`
    field on that SAME `ai-rdr-ml-detections-*` document before it is
    written - never a new index/write path. **`fuse()` below is never
    touched by this task and never reads the `m2` field** - this is the
    load-bearing safety boundary of this whole feature (M2 is a second,
    parallel, display-only ML opinion per the spec's own integration
    decision, never a `risk_tier`/ARM-trigger input) - see the wiring site's
    own comment for the explicit statement of this, matching how
    PathPredict's own wiring comment explicitly says "never calls
    backup_file()".

    Returns a small summary dict, useful for tests and for whatever caller
    eventually wraps this in a timer/loop.
    """
    # Lazy import - breaks a real circular import (backend.ml_scoring
    # imports RawEvent from backend.irdp.event_source; backend/irdp/
    # __init__.py eagerly imports this module; a module-level import here
    # would make any import of backend.irdp fail with "partially
    # initialized module" whenever backend.ml_scoring hasn't finished
    # loading yet - hit and fixed live during Phase B packaging, 2026-09-30,
    # not caught by the test suite because pytest's own collection order
    # happened to dodge it).
    from ..ml_scoring import score_events

    since = checkpoint_store.get(checkpoint_key)
    raw_events: List[RawEvent] = source.poll(since)

    if not raw_events:
        return {
            "raw_events_processed": 0,
            "raw_wazuh_logs_written": 0,
            "fs_events_written": 0,
            "normalized_events_written": 0,
            "ml_detections_written": 0,
            "triggers_sent": 0,
            "pathpredict_predictions_written": 0,
            "m2_scores_attached": 0,
            "checkpoint": since,
        }

    groups: Dict[str, List[RawEvent]] = defaultdict(list)
    for raw in raw_events:
        groups[correlation_id_for(raw)].append(raw)
    masks = {cid: compute_ml_event_mask(events) for cid, events in groups.items()}

    raw_wazuh_logs_written = 0
    fs_events_written = 0
    normalized_events_written = 0

    for raw in raw_events:
        if raw.kind == "wazuh_alert":
            writer.write_raw_wazuh_log(to_raw_wazuh_log_doc(raw))
            raw_wazuh_logs_written += 1
        elif raw.kind != "fs_event":
            raise ValueError(f"unknown RawEvent.kind {raw.kind!r} (expected 'wazuh_alert' or 'fs_event')")

        if is_fs_relevant(raw):
            writer.write_fs_event(to_fs_event_doc(raw))
            fs_events_written += 1

        cid = correlation_id_for(raw)
        writer.write_normalized_event(
            to_normalized_event_doc(raw, correlation_id=cid, ml_event_mask=masks[cid])
        )
        normalized_events_written += 1

    # Same (host_id, process_id) grouping score_events()/windowing.py uses
    # internally (pipeline.py's own step-4 docstring above) - NOT the
    # correlation_id buckets built for the ML event_mask above, which group
    # by (host_id, time window) instead. Rebuilt here rather than threaded
    # out of score_events() because this grouping is needed only for the
    # Honey-File flag / indicator extraction below and (task m2-integration)
    # M2 scoring, not for anything score_events() itself returns. Built
    # unconditionally (moved out of the `trigger_sender is not None` gate
    # below, task m2-integration) since M2 scoring must run independently of
    # whether a trigger_sender is wired in at all.
    by_host_process: Dict[Tuple[str, Optional[int]], List[RawEvent]] = defaultdict(list)
    for raw in raw_events:
        by_host_process[(raw.host_id, raw.process_id)].append(raw)

    ml_detections_written = 0
    m2_scores_attached = 0
    detections: List[Dict[str, Any]] = []
    for detection in score_events(raw_events):
        # Task m2-integration (planning/m2-integration-spec.md Part 1): a
        # second, parallel, display-only ML opinion, attached to THIS SAME
        # ai-rdr-ml-detections-* document before it is written - denormalized
        # onto the detection record, never a new index (matches Risk Fusion's
        # own dashboard_signals convention of grouping multiple signal
        # strengths together). **fuse() below is never touched and never
        # reads this `m2` field** - this is the load-bearing safety boundary
        # of this whole task (see backend/m2_client.py's module docstring),
        # the exact equivalent of PathPredict's own wiring comment stating
        # "never calls backup_file()". Complete no-op when m2_client is
        # omitted (every existing caller/test before this task).
        if m2_client is not None:
            group = by_host_process.get((detection.get("host_id"), detection.get("process_id")), [])
            run_id = incident_key(detection.get("host_id"), detection.get("process_id"))
            m2_result = m2_client.score(group, run_id=run_id)
            if m2_result is not None:
                detection["m2"] = {
                    "prediction": m2_result.prediction,
                    "ransomware_probability": m2_result.ransomware_probability,
                    "threshold": m2_result.threshold,
                    "alert": m2_result.alert,
                    "model_name": m2_result.model_name,
                    "feature_version": m2_result.feature_version,
                    "explanation": m2_result.explanation,
                }
                m2_scores_attached += 1
            # m2_result is None -> "m2" key simply omitted from this
            # document, never written as null/empty - a dashboard or query
            # can distinguish "M2 had no opinion" from "M2 said 0%" this way.

        writer.write_ml_detection(detection)
        detections.append(detection)
        ml_detections_written += 1

    triggers_sent = 0
    pathpredict_predictions_written = 0
    if trigger_sender is not None:
        client = threat_intel_client or NullThreatIntelClient()

        for detection in detections:
            group = by_host_process.get((detection.get("host_id"), detection.get("process_id")), [])
            honey_file_triggered = any(raw.honey_file_triggered for raw in group)

            ips = {raw.src_ip for raw in group if raw.src_ip} | {raw.dest_ip for raw in group if raw.dest_ip}
            threat_intel_result = None
            for ip in ips:
                result = client.lookup({"ip": ip})
                threat_intel_result = result
                if result.matched:
                    break

            fused = fuse(detection, threat_intel_result, honey_file_triggered=honey_file_triggered)
            if send_trigger_if_needed(fused, trigger_sender) is not None:
                triggers_sent += 1

            # task 3.4b: PathPredict wiring - display-only, never calls
            # backup_file() (see this function's own docstring above). Runs
            # in this same loop/gate (fused["risk_tier"] in
            # ARM_NOTIFIABLE_TIERS), matching the spec's explicit "same loop
            # Risk Fusion's own trigger logic already runs in" instruction.
            if (
                pathpredict_writer is not None
                and incident_tracker_store is not None
                and host_controller is not None
                and fused["risk_tier"] in ARM_NOTIFIABLE_TIERS
            ):
                host_id = detection.get("host_id")
                process_id = detection.get("process_id")
                file_events = sorted(
                    (raw for raw in group if raw.file_path), key=lambda raw: raw.timestamp
                )
                file_mod_rate = detection.get("file_mod_rate")

                # Step 1's explicit guard: nothing to predict on yet this
                # poll - never call build_prediction()/advance_incident_and_
                # predict() with an empty touched sequence (see
                # build_prediction()'s own ValueError-by-design). Also skip
                # (this task's own disclosed addition, not spec-literal) when
                # file_mod_rate isn't a usable positive number yet - no ETA
                # can be computed without one, same reasoning as the
                # empty-touched guard, applied so a single malformed window
                # can never crash the rest of this poll's trigger-sending.
                if file_events and file_mod_rate is not None and file_mod_rate > 0:
                    key = incident_key(host_id, process_id)
                    state = incident_tracker_store.get(key)
                    # "new this poll" = not already in the PERSISTED
                    # touched_so_far as loaded above (fixed for this
                    # membership check - advance_incident_and_predict() is
                    # the one that grows touched_so_far incrementally while
                    # processing these new touches in arrival order).
                    persisted_touched = set(state.touched_so_far) if state is not None else set()
                    new_touches = [
                        raw.file_path for raw in file_events if raw.file_path not in persisted_touched
                    ]

                    prediction, updated_state = advance_incident_and_predict(
                        host_controller,
                        host_id,
                        new_touches,
                        state,
                        file_mod_rate=file_mod_rate,
                    )
                    pathpredict_writer.write_prediction(host_id, process_id, prediction)
                    incident_tracker_store.put(key, updated_state)
                    pathpredict_predictions_written += 1

    new_checkpoint = max(raw.timestamp for raw in raw_events)
    if since is not None:
        new_checkpoint = max(new_checkpoint, since)
    checkpoint_store.set(checkpoint_key, new_checkpoint)

    return {
        "raw_events_processed": len(raw_events),
        "raw_wazuh_logs_written": raw_wazuh_logs_written,
        "fs_events_written": fs_events_written,
        "normalized_events_written": normalized_events_written,
        "ml_detections_written": ml_detections_written,
        "triggers_sent": triggers_sent,
        "pathpredict_predictions_written": pathpredict_predictions_written,
        "m2_scores_attached": m2_scores_attached,
        "checkpoint": new_checkpoint,
    }
