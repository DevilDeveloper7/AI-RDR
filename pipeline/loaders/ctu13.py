"""Loader for CTU-13 (Tier 2 — feature passthrough).

SAFETY: data/ctu-13/CTU-13-Dataset.tar.bz2 contains live executable malware binaries
(rbot.exe, Neris.exe, QvodSetuPuls23.exe, an _unpacked.exe sample, a disguised .xls.exe)
alongside the netflow data. This loader does NOT touch the archive itself — extraction
was done once, out-of-band, with a targeted `tar xjf` naming each of the 13
`.binetflow` paths explicitly (never `tar xjf` the whole archive). Verified after
extraction that data/ctu-13/CTU-13-Dataset/ contains exactly 13 files, all `.binetflow`,
nothing else. This loader only ever reads `*.binetflow` under that directory.

Source: data/ctu-13/CTU-13-Dataset/<scenario>/capture*.binetflow — comma-delimited
(NOT semicolon/tab as normalization-progress.md guessed before inspection), 15 columns:
StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,TotBytes,
SrcBytes,Label. Sport/Dport are sometimes hex strings (e.g. "0x0303" for ICMP/ARP/IPX
flows) — kept as Utf8 rather than forced to a numeric type that would fail or truncate.

Output: data/normalized/ctu13_features.parquet
"""

from __future__ import annotations

import glob
import re
from pathlib import Path

import polars as pl

from pipeline.schema import validate_tier2_polars

DATA_DIR = Path(__file__).resolve().parents[2] / "data" / "ctu-13" / "CTU-13-Dataset"
OUT_PATH = Path(__file__).resolve().parents[2] / "data" / "normalized" / "ctu13_features.parquet"

SOURCE_DATASET = "ctu13_features"

# Sport/Dport carry hex values for some protocols (icmp/arp/ipx) — must stay Utf8.
_SCHEMA_OVERRIDES = {"Sport": pl.Utf8, "Dport": pl.Utf8}


def _verify_only_binetflow_extracted() -> None:
    """Hard safety gate: refuse to run if anything other than .binetflow ended up
    on disk under CTU-13-Dataset/ (e.g. a future re-extraction mistake)."""
    all_files = [Path(p) for p in glob.glob(str(DATA_DIR / "**" / "*"), recursive=True) if Path(p).is_file()]
    bad = [p for p in all_files if p.suffix != ".binetflow"]
    if bad:
        raise RuntimeError(
            f"SAFETY ABORT: non-.binetflow files found under {DATA_DIR}: {bad}. "
            "Refusing to proceed — CTU-13-Dataset.tar.bz2 contains live malware binaries."
        )


def load() -> tuple[pl.DataFrame, dict[str, int]]:
    _verify_only_binetflow_extracted()

    paths = sorted(
        glob.glob(str(DATA_DIR / "*" / "*.binetflow")),
        key=lambda p: int(Path(p).parent.name),
    )
    if not paths:
        raise FileNotFoundError(f"no .binetflow files found under {DATA_DIR}")

    per_scenario_counts: dict[str, int] = {}
    frames = []
    for path in paths:
        scenario = Path(path).parent.name  # "1".."13"
        df = pl.read_csv(path, schema_overrides=_SCHEMA_OVERRIDES, infer_schema_length=100_000)
        n = df.height
        per_scenario_counts[scenario] = n

        label_col = pl.col("Label")
        df = df.with_columns(
            [
                (pl.lit(f"ctu13_scenario{scenario}_") + pl.int_range(0, n).cast(pl.Utf8)).alias("sample_id"),
                pl.lit(SOURCE_DATASET).alias("source_dataset"),
                pl.when(label_col.str.contains("Normal"))
                .then(pl.lit("benign"))
                .otherwise(pl.lit("other"))
                .alias("label"),
                pl.when(label_col.str.contains("Normal"))
                .then(pl.lit("benign_baseline"))
                .otherwise(pl.lit("generic_intrusion"))
                .alias("label_type"),
                pl.lit(1.0).alias("label_confidence"),
                # scenario -> botnet family is publicly documented for CTU-13, but we
                # only extracted .binetflow files (README/exe excluded per the safety
                # note), so we have no in-archive way to verify that mapping here —
                # left null rather than asserting an unverified fact into training data.
                pl.lit(None, dtype=pl.Utf8).alias("family"),
                pl.lit(scenario).alias("ctu13_scenario"),
                pl.when(label_col.str.contains("Botnet"))
                .then(pl.lit("Botnet"))
                .when(label_col.str.contains("Normal"))
                .then(pl.lit("Normal"))
                .when(label_col.str.contains("Background"))
                .then(pl.lit("Background"))
                .otherwise(pl.lit("Other"))
                .alias("ctu13_traffic_category"),
            ]
        )
        frames.append(df)

    provenance_cols = ["sample_id", "source_dataset", "label", "label_type", "label_confidence", "family"]
    combined = pl.concat(frames, how="diagonal_relaxed")
    other_cols = [c for c in combined.columns if c not in provenance_cols]
    combined = combined.select(provenance_cols + other_cols)
    return combined, per_scenario_counts


def main() -> None:
    df, per_scenario_counts = load()
    validated = validate_tier2_polars(df)
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    validated.write_parquet(OUT_PATH)

    print("[ctu13] rows per scenario:")
    for scenario, n in sorted(per_scenario_counts.items(), key=lambda kv: int(kv[0])):
        print(f"  scenario {scenario}: {n}")
    print(f"[ctu13] total rows written: {validated.height}")
    print(f"[ctu13] label distribution:\n{validated['label'].value_counts()}")
    print(f"[ctu13] traffic category distribution:\n{validated['ctu13_traffic_category'].value_counts()}")
    print(f"[ctu13] wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
