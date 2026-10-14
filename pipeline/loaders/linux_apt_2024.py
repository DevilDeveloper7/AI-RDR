"""Loader for the Linux-APT Dataset 2024 (Tier 1 — raw-event).

Source: data/linux-apt-2024/ — 17 CSVs exported from a Wazuh SIEM
(Elasticsearch `_source.*` field export), plus `local_rules.xml`, a genuine
Wazuh custom-rules file whose `<group name="...">` blocks attribute specific
custom rule IDs to APT41, Apache Struts exploitation, and a "Trulus" group
(this appears to be the dataset author's label for the "Turla-style TTPs"
mentioned in analysis/dataset-plan.md — kept verbatim rather than renamed,
since that's an inference, not something the source states outright).

Most rows are standard built-in Wazuh alerts (auditd command audit, web
access-log attacks, PAM/sshd auth, syscheck FIM, SCA compliance checks,
rootcheck) that are NOT tied to any specific named APT group — only rows
whose `_source.rule.id` matches a local_rules.xml-defined ID get a `family`
value; everything else gets `family = None`, which is the honest answer for
a dataset that is APT-flavored but mostly built-in-rule alert noise.

Output: data/normalized/linux_apt_2024_raw_events.parquet
"""

from __future__ import annotations

import glob
import json
import re
from pathlib import Path

import pandas as pd

from pipeline.schema import validate_tier1

DATA_DIR = Path(__file__).resolve().parents[2] / "data" / "linux-apt-2024"
OUT_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "normalized"
    / "linux_apt_2024_raw_events.parquet"
)

SOURCE_DATASET = "linux_apt_2024"

# Groups that represent generic/built-in detections, not a specific named
# attacker/family — deliberately excluded from the rule_id -> family map.
_GENERIC_GROUPS = {"local,syslog,sshd", "malware"}


def _parse_local_rules_families(xml_path: Path) -> dict[str, str]:
    """Map custom Wazuh rule id -> family/group name from local_rules.xml.

    The file is not well-formed XML (missing a closing '>' on the final
    </group tag), so this uses a line-scanning approach: track the most
    recently seen `<group name="...">` line and attribute every `<rule id=...>`
    seen after it to that group, until the next group tag.
    """
    text = xml_path.read_text(encoding="utf-8", errors="replace")
    rule_to_family: dict[str, str] = {}
    current_group: str | None = None
    for line in text.splitlines():
        group_match = re.search(r'<group name="([^"]+)"', line)
        if group_match:
            current_group = group_match.group(1).rstrip(",").strip()
            continue
        rule_match = re.search(r'<rule id="(\d+)"', line)
        if rule_match and current_group and current_group not in _GENERIC_GROUPS:
            rule_to_family[rule_match.group(1)] = current_group
    return rule_to_family


def _event_type(row: pd.Series) -> str:
    syscheck_event = row.get("_source.syscheck.event", "")
    if isinstance(syscheck_event, str) and syscheck_event.strip():
        return {
            "added": "file_access",
            "modified": "file_modify",
            "deleted": "file_delete",
        }.get(syscheck_event.strip(), "file_access")

    decoder = str(row.get("_source.decoder.name", "") or "").strip()
    return {
        "auditd": "process_spawn",
        "web-accesslog": "network_connection",
        "pam": "authentication",
        "sshd": "authentication",
        "dpkg-decoder": "package_management",
        "sudo": "process_spawn",
        "sca": "compliance_check",
        "ossec": "anomaly_detection",
        "rootcheck": "anomaly_detection",
    }.get(decoder, "other" if not decoder else f"wazuh:{decoder}")


def _clean(value):
    if pd.isna(value):
        return None
    if isinstance(value, str) and value.strip() == "":
        return None
    return value


def _row_to_raw_fields(row: pd.Series, family_match: dict | None, source_csv: str) -> str:
    payload = {"source_csv": source_csv}
    for col, val in row.items():
        cleaned = _clean(val)
        if cleaned is not None:
            payload[col] = cleaned
    payload["local_rule_match"] = family_match
    return json.dumps(payload, default=str)


def load() -> pd.DataFrame:
    rule_to_family = _parse_local_rules_families(DATA_DIR / "local_rules.xml")

    csv_files = sorted(glob.glob(str(DATA_DIR / "*.csv")))
    frames = []
    for path in csv_files:
        df = pd.read_csv(path, dtype=str, keep_default_na=True, low_memory=False)
        df["_source_csv"] = Path(path).stem
        frames.append(df)
    raw = pd.concat(frames, ignore_index=True)
    n_rows = len(raw)

    records = []
    for _, row in raw.iterrows():
        rule_id = str(row.get("_source.rule.id", "") or "").strip()
        family = rule_to_family.get(rule_id)
        family_match = None
        if family is not None:
            family_match = {
                "rule_id": rule_id,
                "group": family,
                "rule_description": _clean(row.get("_source.rule.description")),
                "mitre_technique": _clean(row.get("_source.rule.mitre.technique")),
            }

        ts_epoch = _clean(row.get("_source.timestamp"))
        timestamp = None
        if ts_epoch is not None:
            try:
                timestamp = pd.to_datetime(float(ts_epoch), unit="s", utc=True).isoformat()
            except (ValueError, TypeError):
                timestamp = _clean(row.get("_source.@timestamp"))
        else:
            timestamp = _clean(row.get("_source.@timestamp"))

        file_path = _clean(row.get("_source.syscheck.path")) or _clean(row.get("_source.data.file"))

        records.append(
            {
                "sample_id": row["_source_csv"],
                "source_dataset": SOURCE_DATASET,
                "label": "apt",
                "label_type": "generic_intrusion",
                "label_confidence": 1.0,
                "family": family,
                "timestamp": timestamp,
                "host_id": _clean(row.get("_source.agent.name")),
                "process_id": None,
                "event_type": _event_type(row),
                "file_path": file_path,
                "raw_fields": _row_to_raw_fields(row, family_match, row["_source_csv"]),
            }
        )

    out = pd.DataFrame.from_records(records)
    return out, n_rows


def main() -> None:
    df, n_rows = load()
    validated = validate_tier1(df)
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    validated.to_parquet(OUT_PATH, index=False)

    print(f"[linux_apt_2024] source rows read: {n_rows}")
    print(f"[linux_apt_2024] rows written: {len(validated)}")
    print(f"[linux_apt_2024] event_type distribution:\n{validated['event_type'].value_counts()}")
    print(f"[linux_apt_2024] family distribution (non-null):\n{validated['family'].value_counts(dropna=True)}")
    print(f"[linux_apt_2024] wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
