"""Feature module for the Ransomware Lifecycle Dataset (Tier 1) — task 3.2.

Source: data/normalized/lifecycle_raw_events.parquet (18,432,297 rows across three
modalities — ftrace 10,058,416 / net 8,314,247 / perf 59,634 — see
data/normalized/SUMMARY.md for the full normalization history, including the 41GB-RSS
crash this loader hit and how it was fixed).

**Scale**: this is the largest of the four sources by a wide margin, so this module uses
Polars end-to-end (no pandas until the final, already-aggregated ~thousands-of-windows
frame goes to Pandera for validation) and vectorized regex `str.contains` checks against
`raw_fields` instead of a per-row `json.loads` Python loop for the write/read/rename/
crypto flags — a Python loop over 18.4M dict parses was measured impractically slow for
an interactive run; the regex approach only checks for a literal, unambiguous JSON key
substring (e.g. `"event":"sys_enter_write"`, `"crypto_algo":"`) which the polars
`struct.json_encode()` call in the normalization loader always renders in the same
compact form (verified by inspecting raw `raw_fields` strings directly before writing
these patterns, not assumed).

**Windowing note**: `sample_id` is namespaced per modality (`ftrace/<stage>/<run>`,
`net/<stage>/<run>`, `perf/<stage>/<run>`) from the normalization pass specifically
because the three modalities are NOT reliably joinable to the same logical run (verified
again here, not just carried over as an assumption — ftrace uses `symm_AES_128t_N` while
net/perf use `symm_AES_128b_N` for what looks like the same run, with no reliable rule to
re-pair them). Windowing by `(sample_id, process_id)` therefore naturally keeps
ftrace/net/perf windows of "the same" run separate, which is the intended, safe behavior,
not a bug to fix here.

entropy_score — RESOLVED as a documented null, no direct byte content: verified this is
still true after specifically re-checking the exec-stage crypto runs (`crypto_algo`/
`key_bits` are real fields already parsed into `raw_fields` during normalization) as the
tracker doc's own warning asked. Listed every distinct ftrace `event` name present in the
dataset (all syscall enter/exit names — `sys_enter_write`/`sys_enter_read`/etc.) and
inspected `details` on write/read/rename events and on `sys_enter_newfstatat`/
`sys_exit_newfstatat` (the only stat-family syscall traced): `details` only ever contains
pointer addresses, byte *counts* (not content), and raw return codes (e.g. `0x0`,
`0xfffffffffffffffe`) — never a resolved path string and never buffer bytes, and no
before/after file-size pair exists anywhere in the trace. There is therefore no route to
a real entropy value, direct or size-delta-derived, from this source.

`encryption_rate` (SDD: "proportion of files with entropy > 7.2") is consequently also
null throughout, per its own definition — there is no entropy to threshold. However,
since the exec-stage `crypto_algo`/`key_bits` fields ARE real signal that real AES/
Salsa20/asymmetric operations occurred in a window, this module adds an extra,
explicitly-NOT-equivalent `crypto_op_rate` column (fraction of the window's events that
are tagged with a non-null `crypto_algo`) as the tracker doc's suggested "documented
proxy" — kept as a clearly separate, additional column (the feature schema is
`strict=False` precisely to allow this) rather than overloading `encryption_rate` itself
with a fundamentally different definition under the same name.

`unique_extensions_touched` is 0 for every window in this source: `file_path` is null for
every Lifecycle row (ftrace only exposes a pointer address for path-taking syscall
arguments, never a resolved string — a property of raw ftrace, not a parsing gap; net/perf
have no file-path concept at all). This is a real, honest 0, not a null or a bug.

Output: data/features/lifecycle_features.parquet, training_eligible=true throughout.
"""

from __future__ import annotations

from pathlib import Path

import polars as pl

from pipeline.features.schema import validate_features
from pipeline.features.windowing import build_feature_windows

IN_PATH = Path(__file__).resolve().parents[2] / "data" / "normalized" / "lifecycle_raw_events.parquet"
OUT_PATH = Path(__file__).resolve().parents[2] / "data" / "features" / "lifecycle_features.parquet"

SOURCE_DATASET = "ransomware_lifecycle"
WINDOW_SEC = 30

_WRITE_EVENTS = r"sys_enter_write|sys_enter_pwrite64|sys_enter_fsync|sys_enter_fdatasync|sys_enter_ftruncate|sys_enter_truncate"
_READ_EVENTS = r"sys_enter_read|sys_enter_pread64"
_RENAME_EVENTS = r"sys_enter_rename|sys_enter_renameat|sys_enter_renameat2"

# strips tshark's trailing "<9-digit-nanoseconds> <TZ abbrev>" down to 6-digit
# microseconds so polars' %.f can parse it (nanosecond precision + a CDT/CST
# abbreviation are both things polars' strptime can't handle directly).
_NET_TS_FIX_RE = r"^([A-Za-z]{3} \d{1,2} \d{4} \d{2}:\d{2}:\d{2})\.(\d{6})\d* [A-Z]{2,4}$"


def load() -> tuple[pl.DataFrame, dict]:
    df = pl.read_parquet(IN_PATH)
    n_in = df.height

    is_rel = pl.col("timestamp").str.starts_with("REL:")
    rel_seconds = pl.col("timestamp").str.slice(4).cast(pl.Float64, strict=False)
    fixed_wallclock = pl.col("timestamp").str.replace(_NET_TS_FIX_RE, "${1}.${2}")
    wallclock_seconds = (
        fixed_wallclock.str.to_datetime(format="%b %d %Y %H:%M:%S%.f", strict=False).dt.epoch(
            time_unit="ms"
        )
        / 1000.0
    )

    df = df.with_columns(
        [
            pl.when(is_rel).then(rel_seconds).otherwise(wallclock_seconds).alias("t_seconds"),
            pl.col("raw_fields").str.contains(f'"event":"({_WRITE_EVENTS})"').alias("is_write"),
            pl.col("raw_fields").str.contains(f'"event":"({_READ_EVENTS})"').alias("is_read"),
            pl.col("raw_fields").str.contains(f'"event":"({_RENAME_EVENTS})"').alias("is_rename"),
            pl.col("raw_fields").str.contains('"crypto_algo":"').alias("is_crypto"),
            pl.lit(None, dtype=pl.Utf8).alias("extension"),  # file_path is null throughout — see docstring
            pl.lit(None, dtype=pl.Float64).alias("entropy_bits"),  # documented null — see docstring
        ]
    )
    n_null_ts = int(df.select(pl.col("t_seconds").is_null().sum()).item())
    if n_null_ts:
        df = df.filter(pl.col("t_seconds").is_not_null())

    windows = build_feature_windows(
        df,
        window_sec=WINDOW_SEC,
        source_dataset=SOURCE_DATASET,
        training_eligible=True,
        extra_aggs=[(pl.col("is_crypto").sum() / pl.len()).alias("crypto_op_rate")],
    )
    stats = {
        "rows_in": n_in,
        "rows_dropped_unparseable_timestamp": n_null_ts,
        "windows_out": windows.height,
        "write_events": int(df.select(pl.col("is_write").sum()).item()),
        "read_events": int(df.select(pl.col("is_read").sum()).item()),
        "rename_events": int(df.select(pl.col("is_rename").sum()).item()),
        "crypto_tagged_events": int(df.select(pl.col("is_crypto").sum()).item()),
    }
    return windows, stats


def main() -> None:
    windows, stats = load()
    validated = validate_features(windows.to_pandas())
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    validated.to_parquet(OUT_PATH, index=False)

    print(f"[lifecycle-features] {stats}")
    print(f"[lifecycle-features] windows written: {len(validated)}")
    print(f"[lifecycle-features] entropy_score non-null windows: {validated['entropy_score'].notna().sum()}")
    print(
        f"[lifecycle-features] crypto_op_rate > 0 windows: "
        f"{(validated['crypto_op_rate'] > 0).sum()} / {len(validated)}"
    )
    print(f"[lifecycle-features] wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
