"""
PathPredict tests (task 3.4; planning/pathpredict-spec.md). Uses
FakeHostController exclusively - no live SSH access, matching every
other test in this package.

Also covers task 3.4b (planning/pathpredict-deployment-spec.md Part 1):
IncidentTrackerStore/PathPredictWriter (fakes + the real OpenSearch classes'
never-raise behavior, exercised only against mocked `requests` responses -
no live OpenSearch) and advance_incident_and_predict()'s own incremental
hit/miss recording logic, hand-computed against a known directory listing
and a known touch sequence.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from backend import pathpredict as pp
from backend.tests.fakes import FakeHostController

HOST = "airdr-target"


def _opensearch_response(status_code=200, source=None):
    # Mirrors test_threat_intel.py's own `_opensearch_response` convention
    # exactly: a MagicMock doesn't raise on `.raise_for_status()` unless its
    # `side_effect` is configured, so this is what actually exercises a
    # mocked 403/500 against code that must NOT call raise_for_status() at
    # all (that's exactly the never-raise discipline being tested).
    resp = MagicMock()
    resp.status_code = status_code
    resp.raise_for_status.side_effect = requests.HTTPError() if status_code >= 400 else None
    if source is not None:
        resp.json.return_value = {"_source": source}
    return resp


@pytest.fixture
def controller() -> FakeHostController:
    return FakeHostController()


@pytest.fixture
def allow_list_path(tmp_path):
    """A critical_assets.yml with one path pattern, isolated to tmp_path so
    tests never depend on (or risk mutating expectations about) the real
    backend/critical_assets.yml."""
    p = tmp_path / "critical_assets.yml"
    p.write_text("hosts: []\npaths:\n  - \"/data/critical.db\"\n  - \"/etc/*\"\n")
    return p


# ---------------------------------------------------------------------------
# Within-directory ranking (spec S4.2)
# ---------------------------------------------------------------------------


def test_ranking_is_alphabetical_and_excludes_touched(allow_list_path):
    listing = ["/data/c.txt", "/data/a.txt", "/data/b.txt", "/data/d.txt"]
    touched = ["/data/a.txt"]  # already touched -> excluded
    ranked = pp.rank_within_directory(listing, touched, allow_list_path)
    assert ranked == ["/data/b.txt", "/data/c.txt", "/data/d.txt"]


def test_ranking_excludes_critical_assets(allow_list_path):
    listing = ["/data/a.txt", "/data/critical.db", "/data/z.txt"]
    ranked = pp.rank_within_directory(listing, touched=[], allow_list_path=allow_list_path)
    assert "/data/critical.db" not in ranked
    assert ranked == ["/data/a.txt", "/data/z.txt"]


def test_ranking_excludes_glob_matched_critical_assets(allow_list_path):
    listing = ["/etc/passwd", "/etc/shadow", "/data/a.txt"]
    ranked = pp.rank_within_directory(listing, touched=[], allow_list_path=allow_list_path)
    assert ranked == ["/data/a.txt"]


# ---------------------------------------------------------------------------
# Live per-incident confidence tracker (spec S4.2)
# ---------------------------------------------------------------------------


def test_tracker_cold_start_prior_before_any_evidence():
    tracker = pp.IncidentConfidenceTracker(cold_start_prior=0.5)
    assert tracker.running_hit_rate == 0.5
    assert tracker.topk == "0/0"


def test_tracker_hit_rate_updates_across_matched_and_missed_touches():
    tracker = pp.IncidentConfidenceTracker()
    # 3 correct predictions in a row -> topk "3/3", hit-rate 1.0
    tracker.record_touch("/data/a.txt", "/data/a.txt")
    tracker.record_touch("/data/b.txt", "/data/b.txt")
    tracker.record_touch("/data/c.txt", "/data/c.txt")
    assert tracker.topk == "3/3"
    assert tracker.running_hit_rate == 1.0

    # a miss: predicted d.txt but e.txt was touched instead
    tracker.record_touch("/data/d.txt", "/data/e.txt")
    assert tracker.topk == "3/4"
    assert tracker.running_hit_rate == pytest.approx(0.75)

    # another miss
    tracker.record_touch("/data/f.txt", "/data/g.txt")
    assert tracker.topk == "3/5"
    assert tracker.running_hit_rate == pytest.approx(0.6)


# ---------------------------------------------------------------------------
# riskPct / conf monotonicity (spec S4.3)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("running_hit_rate", [0.0, 0.2, 0.5, 0.75, 1.0])
def test_riskpct_is_monotonically_non_increasing_in_k(running_hit_rate):
    pcts = [pp.risk_pct(pp.conf_at_k(running_hit_rate, k)) for k in range(20)]
    for earlier, later in zip(pcts, pcts[1:]):
        assert later <= earlier


def test_conf_at_k_zero_equals_running_hit_rate():
    assert pp.conf_at_k(0.8, 0) == pytest.approx(0.8)


def test_conf_at_k_decays_with_distance():
    hit_rate = 0.8
    decay = 0.85
    assert pp.conf_at_k(hit_rate, 1, decay) == pytest.approx(hit_rate * decay)
    assert pp.conf_at_k(hit_rate, 2, decay) == pytest.approx(hit_rate * decay ** 2)


# ---------------------------------------------------------------------------
# ETA (spec S4.3)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "k, file_mod_rate, expected_seconds",
    [
        # file_mod_rate is files/minute (matches pipeline/features/windowing.py's
        # real convention); expected_seconds = k * 60 / file_mod_rate.
        (0, 2.0, 0.0),
        (1, 2.0, 30.0),
        (4, 2.0, 120.0),
        (3, 1.0, 180.0),
    ],
)
def test_eta_seconds_matches_k_over_file_mod_rate(k, file_mod_rate, expected_seconds):
    assert pp.eta_seconds(k, file_mod_rate) == pytest.approx(expected_seconds)


def test_eta_str_format():
    assert pp.eta_str(4, 2.0) == "T+120s"
    assert pp.eta_str(0, 2.0) == "T+0s"


def test_eta_rejects_non_positive_rate():
    with pytest.raises(ValueError):
        pp.eta_seconds(1, 0.0)


# ---------------------------------------------------------------------------
# Cross-directory frontier fallback (spec S4.4)
# ---------------------------------------------------------------------------


def test_cross_directory_confidence_never_exceeds_ceiling_regardless_of_hit_rate():
    for running_hit_rate in (0.9, 1.0):
        for k in range(0, 5):
            conf = min(pp.conf_at_k(running_hit_rate, k), pp.CROSS_DIRECTORY_CONFIDENCE_CEILING)
            assert conf <= pp.CROSS_DIRECTORY_CONFIDENCE_CEILING


def test_recent_directories_most_recent_first_deduped():
    touched = ["/data/a/x.txt", "/data/b/y.txt", "/data/a/z.txt", "/data/c/w.txt"]
    dirs = pp.recent_directories(touched, active_directory="/data/c")
    # most-recent-first, excluding active dir, deduped
    assert dirs == ["/data/a", "/data/b"]


def test_cross_directory_frontier_ranks_each_directory_alphabetically(controller, allow_list_path):
    controller.directories[(HOST, "/data/b")] = ["z.txt", "y.txt"]
    controller.directories[(HOST, "/data/a")] = ["m.txt", "n.txt"]
    touched = ["/data/a/x.txt", "/data/b/y.txt", "/data/c/w.txt"]

    frontier = pp.cross_directory_frontier(controller, HOST, touched, active_directory="/data/c", allow_list_path=allow_list_path)

    # /data/b visited more recently than /data/a -> its entries come first,
    # each directory's own entries alphabetical, "y.txt" already touched so excluded.
    assert frontier == ["/data/b/z.txt", "/data/a/m.txt", "/data/a/n.txt"]


# ---------------------------------------------------------------------------
# Output shape (spec S1)
# ---------------------------------------------------------------------------


def test_build_prediction_matches_demo_contract_shape(controller, allow_list_path):
    controller.directories[(HOST, "/data")] = ["a.txt", "b.txt", "c.txt", "critical.db"]
    touched = ["/data/a.txt"]
    tracker = pp.IncidentConfidenceTracker()
    tracker.record_touch("/data/a.txt", "/data/a.txt")  # one correct prediction so far

    result = pp.build_prediction(
        controller, HOST, touched, file_mod_rate=2.0, tracker=tracker, allow_list_path=allow_list_path
    )

    assert set(result.keys()) == {"lead", "topk", "targets"}
    assert result["topk"] == "1/1"
    assert isinstance(result["lead"], int)
    assert isinstance(result["targets"], list)
    for target in result["targets"]:
        assert set(target.keys()) == {"path", "riskPct", "conf", "eta", "state"}
        assert isinstance(target["path"], str)
        assert isinstance(target["riskPct"], int)
        assert isinstance(target["conf"], float)
        assert target["eta"].startswith("T+") and target["eta"].endswith("s")
        assert target["state"] in {"Protected", "Backed up", "At Risk"}

    # critical asset never appears
    assert not any(t["path"] == "/data/critical.db" for t in result["targets"])
    # b.txt then c.txt, alphabetical, a.txt excluded as already touched
    paths = [t["path"] for t in result["targets"]]
    assert paths == ["/data/b.txt", "/data/c.txt"]

    # riskPct monotonically non-increasing across the returned targets
    pcts = [t["riskPct"] for t in result["targets"]]
    assert pcts == sorted(pcts, reverse=True)


def test_build_prediction_state_uses_pluggable_callback(controller, allow_list_path):
    controller.directories[(HOST, "/data")] = ["a.txt", "b.txt"]
    tracker = pp.IncidentConfidenceTracker()

    def fake_action_state(path: str) -> str:
        return "Backed up" if path.endswith("b.txt") else "At Risk"

    result = pp.build_prediction(
        controller,
        HOST,
        touched=["/data/a.txt"],
        file_mod_rate=1.0,
        tracker=tracker,
        allow_list_path=allow_list_path,
        get_action_state=fake_action_state,
    )
    states = {t["path"]: t["state"] for t in result["targets"]}
    assert states["/data/b.txt"] == "Backed up"


def test_build_prediction_falls_back_to_cross_directory_once_active_dir_exhausted(controller, allow_list_path):
    # active directory (/data/c) has nothing left; /data/b has an untouched entry
    controller.directories[(HOST, "/data/c")] = ["w.txt"]
    controller.directories[(HOST, "/data/b")] = ["y.txt", "z.txt"]
    touched = ["/data/b/y.txt", "/data/c/w.txt"]
    tracker = pp.IncidentConfidenceTracker()

    result = pp.build_prediction(
        controller, HOST, touched, file_mod_rate=1.0, tracker=tracker, allow_list_path=allow_list_path
    )

    paths = [t["path"] for t in result["targets"]]
    assert paths == ["/data/b/z.txt"]
    assert result["targets"][0]["conf"] <= pp.CROSS_DIRECTORY_CONFIDENCE_CEILING


# ---------------------------------------------------------------------------
# HostController: list_directory / backup_file (spec S2/S5)
# ---------------------------------------------------------------------------


def test_fake_list_directory_records_call_and_returns_seeded_entries(controller):
    controller.directories[(HOST, "/data")] = ["a.txt", "b.txt"]
    result = controller.list_directory(HOST, "/data")
    assert result == ["a.txt", "b.txt"]
    assert ("list_directory", (HOST, "/data")) in controller.calls


def test_fake_list_directory_unseeded_returns_empty(controller):
    assert controller.list_directory(HOST, "/nowhere") == []


def test_fake_backup_file_records_call_and_returns_dict(controller):
    detail = controller.backup_file(HOST, "/data/a.txt")
    assert detail["source_path"] == "/data/a.txt"
    assert "backup_id" in detail and "backup_path" in detail
    assert ("backup_file", (HOST, "/data/a.txt")) in controller.calls


def test_fake_remove_backup_records_call(controller):
    detail = controller.backup_file(HOST, "/data/a.txt")
    controller.remove_backup(HOST, detail["backup_id"])
    assert ("remove_backup", (HOST, detail["backup_id"])) in controller.calls


def test_pathpredict_backup_file_action_wrapper_and_reversal(controller):
    result = pp.backup_file(controller, HOST, "/data/a.txt")
    assert result["status"] == "success"
    assert result["action"] == "backup_file"
    assert result["reversible"] is True
    assert "backup_id" in result["detail"]

    pp.PATHPREDICT_REVERSAL_HANDLERS["backup_file"](controller, result)
    assert ("remove_backup", (HOST, result["detail"]["backup_id"])) in controller.calls


# ---------------------------------------------------------------------------
# Task 3.4b: IncidentTrackerStore / PathPredictWriter fakes
# ---------------------------------------------------------------------------


def test_incident_key_format():
    assert pp.incident_key("airdr-target", 9001) == "airdr-target:9001"
    assert pp.incident_key("airdr-target", None) == "airdr-target:None"


def test_in_memory_incident_tracker_store_miss_returns_none():
    store = pp.InMemoryIncidentTrackerStore()
    assert store.get("airdr-target:9001") is None


def test_in_memory_incident_tracker_store_round_trips():
    store = pp.InMemoryIncidentTrackerStore()
    state = pp.IncidentState(matched=2, total_predictions_made=3, touched_so_far=["/data/a.txt"])
    store.put("airdr-target:9001", state)
    got = store.get("airdr-target:9001")
    assert got.matched == 2
    assert got.total_predictions_made == 3
    assert got.touched_so_far == ["/data/a.txt"]


def test_in_memory_pathpredict_writer_denormalizes_and_overwrites():
    writer = pp.InMemoryPathPredictWriter()
    writer.write_prediction("airdr-target", 9001, {"lead": 1, "topk": "0/1", "targets": []})
    doc = writer.written["airdr-target:9001"]
    assert doc["host_id"] == "airdr-target"
    assert doc["process_id"] == 9001
    assert "@timestamp" in doc
    assert doc["topk"] == "0/1"

    # overwritten, not appended - one doc per incident (spec's "current live
    # prediction state," not a log).
    writer.write_prediction("airdr-target", 9001, {"lead": 0, "topk": "1/2", "targets": []})
    assert len(writer.written) == 1
    assert writer.written["airdr-target:9001"]["topk"] == "1/2"


# ---------------------------------------------------------------------------
# Task 3.4b: OpenSearchIncidentTrackerStore - never-raise contract on an
# ordinary cache-backend failure (built in from the start, mirroring
# OpenSearchThreatIntelCache's now-fixed implementation, task 4.3b).
# ---------------------------------------------------------------------------


def test_opensearch_tracker_store_get_returns_none_on_connection_error():
    with patch("requests.get", side_effect=requests.exceptions.ConnectionError()):
        store = pp.OpenSearchIncidentTrackerStore(host="opensearch.example", username="u", password="p")
        assert store.get("airdr-target:9001") is None


def test_opensearch_tracker_store_get_returns_none_on_timeout():
    with patch("requests.get", side_effect=requests.exceptions.Timeout()):
        store = pp.OpenSearchIncidentTrackerStore(host="opensearch.example", username="u", password="p")
        assert store.get("airdr-target:9001") is None


def test_opensearch_tracker_store_get_returns_none_on_404():
    with patch("requests.get", return_value=_opensearch_response(status_code=404)):
        store = pp.OpenSearchIncidentTrackerStore(host="opensearch.example", username="u", password="p")
        assert store.get("airdr-target:9001") is None


def test_opensearch_tracker_store_get_returns_none_on_500_without_raising():
    with patch("requests.get", return_value=_opensearch_response(status_code=500)):
        store = pp.OpenSearchIncidentTrackerStore(host="opensearch.example", username="u", password="p")
        # Must not raise - no raise_for_status() anywhere in this path.
        assert store.get("airdr-target:9001") is None


def test_opensearch_tracker_store_get_returns_none_on_403_without_raising():
    with patch("requests.get", return_value=_opensearch_response(status_code=403)):
        store = pp.OpenSearchIncidentTrackerStore(host="opensearch.example", username="u", password="p")
        assert store.get("airdr-target:9001") is None


def test_opensearch_tracker_store_get_returns_none_on_unparseable_body():
    resp = _opensearch_response(status_code=200)
    resp.json.side_effect = ValueError("not json")
    with patch("requests.get", return_value=resp):
        store = pp.OpenSearchIncidentTrackerStore(host="opensearch.example", username="u", password="p")
        assert store.get("airdr-target:9001") is None


def test_opensearch_tracker_store_get_parses_real_200_response():
    source = {"matched": 2, "total_predictions_made": 3, "touched_so_far": ["/data/a.txt", "/data/b.txt"]}
    with patch("requests.get", return_value=_opensearch_response(status_code=200, source=source)):
        store = pp.OpenSearchIncidentTrackerStore(host="opensearch.example", username="u", password="p")
        got = store.get("airdr-target:9001")
    assert got == pp.IncidentState(matched=2, total_predictions_made=3, touched_so_far=["/data/a.txt", "/data/b.txt"])


def test_opensearch_tracker_store_put_does_not_raise_on_connection_error():
    with patch("requests.put", side_effect=requests.exceptions.ConnectionError()):
        store = pp.OpenSearchIncidentTrackerStore(host="opensearch.example", username="u", password="p")
        store.put("airdr-target:9001", pp.IncidentState())  # must not raise


def test_opensearch_tracker_store_put_does_not_raise_on_timeout():
    with patch("requests.put", side_effect=requests.exceptions.Timeout()):
        store = pp.OpenSearchIncidentTrackerStore(host="opensearch.example", username="u", password="p")
        store.put("airdr-target:9001", pp.IncidentState())


def test_opensearch_tracker_store_put_does_not_raise_on_500_without_raising():
    with patch("requests.put", return_value=_opensearch_response(status_code=500)):
        store = pp.OpenSearchIncidentTrackerStore(host="opensearch.example", username="u", password="p")
        store.put("airdr-target:9001", pp.IncidentState())


def test_opensearch_tracker_store_put_sends_expected_doc():
    with patch("requests.put", return_value=_opensearch_response(status_code=200)) as mock_put:
        store = pp.OpenSearchIncidentTrackerStore(host="opensearch.example", username="u", password="p")
        state = pp.IncidentState(matched=1, total_predictions_made=2, touched_so_far=["/data/a.txt"])
        store.put("airdr-target:9001", state)

    _, kwargs = mock_put.call_args
    assert kwargs["json"] == {
        "matched": 1,
        "total_predictions_made": 2,
        "touched_so_far": ["/data/a.txt"],
    }
    assert mock_put.call_args[0][0].endswith(
        "ai-rdr-pathpredict-incident-state/_doc/airdr-target:9001"
    )


# ---------------------------------------------------------------------------
# Task 3.4b: OpenSearchPathPredictWriter - same never-raise contract.
# ---------------------------------------------------------------------------


def test_opensearch_pathpredict_writer_does_not_raise_on_connection_error():
    with patch("requests.put", side_effect=requests.exceptions.ConnectionError()):
        writer = pp.OpenSearchPathPredictWriter(host="opensearch.example", username="u", password="p")
        writer.write_prediction("airdr-target", 9001, {"lead": 0, "topk": "0/0", "targets": []})


def test_opensearch_pathpredict_writer_does_not_raise_on_timeout():
    with patch("requests.put", side_effect=requests.exceptions.Timeout()):
        writer = pp.OpenSearchPathPredictWriter(host="opensearch.example", username="u", password="p")
        writer.write_prediction("airdr-target", 9001, {"lead": 0, "topk": "0/0", "targets": []})


def test_opensearch_pathpredict_writer_does_not_raise_on_500_without_raising():
    with patch("requests.put", return_value=_opensearch_response(status_code=500)):
        writer = pp.OpenSearchPathPredictWriter(host="opensearch.example", username="u", password="p")
        # Must not raise (no raise_for_status() in this path).
        writer.write_prediction("airdr-target", 9001, {"lead": 0, "topk": "0/0", "targets": []})


def test_opensearch_pathpredict_writer_sends_expected_doc_and_id():
    with patch("requests.put", return_value=_opensearch_response(status_code=200)) as mock_put:
        writer = pp.OpenSearchPathPredictWriter(host="opensearch.example", username="u", password="p")
        writer.write_prediction("airdr-target", 9001, {"lead": 1, "topk": "1/1", "targets": []})

    args, kwargs = mock_put.call_args
    assert args[0].endswith("ai-rdr-pathpredict-predictions/_doc/airdr-target:9001")
    assert kwargs["json"]["host_id"] == "airdr-target"
    assert kwargs["json"]["process_id"] == 9001
    assert kwargs["json"]["topk"] == "1/1"
    assert "@timestamp" in kwargs["json"]


# ---------------------------------------------------------------------------
# Task 3.4b: advance_incident_and_predict() - the "subtle part" (spec Part 1
# #4 step 3). Hand-computed, not just "some number came out": a known
# directory listing (/data: a.txt, b.txt, c.txt, d.txt) and a known touch
# sequence chosen so some touches genuinely match the live top-1 prediction
# and some don't.
#
# Touch-by-touch, by hand (active directory is always /data throughout):
#   1. a.txt - touched_so_far is empty -> no prior prediction exists yet ->
#      predicted_top=None -> can't match (not a hit, not a "wrong guess",
#      just no evidence yet) -> running total 0/1.
#   2. b.txt - remaining=[b,c,d] -> predicted top-1 is b.txt -> b.txt touched
#      -> HIT -> 1/2.
#   3. d.txt - remaining=[c,d] -> predicted top-1 is c.txt -> d.txt touched
#      -> MISS -> 1/3.
#   4. c.txt - remaining=[c] -> predicted top-1 is c.txt -> c.txt touched ->
#      HIT -> 2/4.
# Final: matched=2, total_predictions_made=4, topk="2/4".
# ---------------------------------------------------------------------------


def test_advance_incident_and_predict_hand_computed_hit_miss(controller):
    controller.directories[(HOST, "/data")] = ["a.txt", "b.txt", "c.txt", "d.txt"]
    new_touches = ["/data/a.txt", "/data/b.txt", "/data/d.txt", "/data/c.txt"]

    prediction, updated_state = pp.advance_incident_and_predict(
        controller, HOST, new_touches, state=None, file_mod_rate=2.0
    )

    assert updated_state.matched == 2
    assert updated_state.total_predictions_made == 4
    assert updated_state.touched_so_far == new_touches
    assert prediction["topk"] == "2/4"
    # directory fully exhausted (all 4 entries touched), no other directory
    # visited -> nothing left to predict.
    assert prediction["targets"] == []

    # backup_file() must never be invoked anywhere in this path - display-
    # only, per the spec's own explicit scope boundary.
    assert not any(name == "backup_file" for name, _ in controller.calls)


def test_advance_incident_and_predict_resumes_from_persisted_state(controller):
    """The incremental comparison must use the FULL persisted touched_so_far
    (not just this call's new_touches) to find the active directory and rank
    remaining entries - proven by seeding a non-None, non-trivial prior
    state and checking the very first new touch's hit/miss is judged against
    a real prior prediction, not treated as a fresh cold start."""
    controller.directories[(HOST, "/data")] = ["a.txt", "b.txt", "c.txt"]
    prior_state = pp.IncidentState(matched=1, total_predictions_made=1, touched_so_far=["/data/a.txt"])

    # Immediately before this new touch, touched_so_far=["/data/a.txt"] ->
    # remaining=[b,c] -> predicted top-1 is b.txt -> touching b.txt is a HIT.
    prediction, updated_state = pp.advance_incident_and_predict(
        controller, HOST, ["/data/b.txt"], state=prior_state, file_mod_rate=1.0
    )

    assert updated_state.matched == 2  # 1 (carried over) + 1 new hit
    assert updated_state.total_predictions_made == 2
    assert updated_state.touched_so_far == ["/data/a.txt", "/data/b.txt"]
    assert prediction["topk"] == "2/2"
    assert prediction["targets"][0]["path"] == "/data/c.txt"


def test_advance_incident_and_predict_never_calls_backup_file(controller):
    """Explicit, dedicated assertion (spec's own required test): zero calls
    to HostController.backup_file anywhere in this new code path, across a
    multi-touch, multi-call scenario - not just a side-effect of the
    hand-computed test above."""
    controller.directories[(HOST, "/data")] = ["a.txt", "b.txt", "c.txt", "d.txt", "e.txt"]
    state = None
    for touches in (["/data/a.txt"], ["/data/b.txt", "/data/c.txt"], ["/data/d.txt"]):
        _, state = pp.advance_incident_and_predict(controller, HOST, touches, state=state, file_mod_rate=3.0)

    backup_calls = [name for name, _ in controller.calls if name == "backup_file"]
    assert backup_calls == []
