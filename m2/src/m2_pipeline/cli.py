from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from .features import FeatureGenerationConfig, generate_feature_file
from .io import discover_trace_files, iter_normalized_runs
from .training import train_models
from .windowing import SlidingWindowConfig, iter_run_windows


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai-rdr-m2",
        description="Normalize Linux telemetry and create leakage-safe sliding windows.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser("inspect", help="Inspect labels and runs")
    inspect_parser.add_argument("input", type=Path)
    inspect_parser.add_argument("--source", default="lifecycle")
    inspect_parser.add_argument("--max-runs", type=int)

    preprocess = subparsers.add_parser(
        "preprocess", help="Normalize traces and write window JSONL"
    )
    preprocess.add_argument("input", type=Path)
    preprocess.add_argument("output", type=Path)
    preprocess.add_argument("--source", default="lifecycle")
    preprocess.add_argument("--mode", choices=("time", "events"), default="time")
    preprocess.add_argument("--size", type=float, default=5.0)
    preprocess.add_argument("--stride", type=float, default=1.0)
    preprocess.add_argument("--min-events", type=int, default=2)
    preprocess.add_argument("--max-runs", type=int)
    preprocess.add_argument(
        "--allow-unknown-labels",
        action="store_true",
        help="Keep traces whose benign/ransomware label cannot be inferred",
    )

    features = subparsers.add_parser(
        "features", help="Extract parity-safe window features"
    )
    features.add_argument("input", type=Path)
    features.add_argument("output", type=Path)
    features.add_argument("--source", default="lifecycle")
    features.add_argument("--mode", choices=("time", "events"), default="time")
    features.add_argument("--size", type=float, default=5.0)
    features.add_argument("--stride", type=float, default=5.0)
    features.add_argument("--min-events", type=int, default=2)
    features.add_argument("--max-windows-per-run", type=int, default=200)
    features.add_argument("--max-runs", type=int)
    features.add_argument("--seed", type=int, default=321)

    train = subparsers.add_parser(
        "train", help="Train and evaluate baseline, Random Forest and XGBoost"
    )
    train.add_argument("features", type=Path)
    train.add_argument("output_directory", type=Path)
    train.add_argument("--seed", type=int, default=321)
    train.add_argument(
        "--exclude-feature",
        action="append",
        default=[],
        help="Feature to omit for an ablation run; repeat for multiple features",
    )
    return parser


def inspect_dataset(
    input_path: Path,
    source: str,
    max_runs: int | None = None,
) -> dict[str, Any]:
    files = discover_trace_files(input_path)
    labels: Counter[str] = Counter()
    runs: Counter[str] = Counter()
    event_types: Counter[str] = Counter()
    parse_errors: list[dict[str, str]] = []
    event_count = 0

    for run_index, (run_id, _label, events) in enumerate(
        iter_normalized_runs(input_path, source=source)
    ):
        if max_runs is not None and run_index >= max_runs:
            break
        try:
            for event in events:
                event_count += 1
                labels[event.label] += 1
                runs[event.run_id] += 1
                event_types[event.event_type] += 1
        except (OSError, ValueError, json.JSONDecodeError) as error:
            parse_errors.append({"run_id": run_id, "error": str(error)})

    return {
        "input": str(input_path),
        "source": source,
        "files": len(files),
        "events": event_count,
        "runs": len(runs),
        "labels": dict(labels),
        "top_event_types": dict(event_types.most_common(20)),
        "parse_errors": parse_errors,
        "max_runs": max_runs,
    }


def preprocess_dataset(args: argparse.Namespace) -> dict[str, Any]:
    files = discover_trace_files(args.input)
    config = SlidingWindowConfig(
        mode=args.mode,
        size=args.size,
        stride=args.stride,
        min_events=args.min_events,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")

    labels: Counter[str] = Counter()
    splits: Counter[str] = Counter()
    seen_runs: set[str] = set()
    event_count = 0
    window_count = 0
    skipped_unknown_runs: set[str] = set()

    try:
        with temporary.open("w", encoding="utf-8") as output:
            for run_index, (run_id, label, events) in enumerate(
                iter_normalized_runs(args.input, source=args.source)
            ):
                if args.max_runs is not None and run_index >= args.max_runs:
                    break
                seen_runs.add(run_id)
                if label == "unknown" and not args.allow_unknown_labels:
                    skipped_unknown_runs.add(run_id)
                    continue

                def counted_events():
                    nonlocal event_count
                    for event in events:
                        event_count += 1
                        yield event

                for window in iter_run_windows(counted_events(), config):
                    output.write(
                        json.dumps(window.to_dict(), separators=(",", ":")) + "\n"
                    )
                    window_count += 1
                    labels[window.label] += 1
                    splits[window.split] += 1
        temporary.replace(args.output)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise

    report = {
        "input": str(args.input),
        "output": str(args.output),
        "source": args.source,
        "files": len(files),
        "events_read": event_count,
        "runs": len(seen_runs),
        "windows": window_count,
        "window_labels": dict(labels),
        "window_splits": dict(splits),
        "skipped_unknown_runs": sorted(skipped_unknown_runs),
        "window_config": {
            "mode": config.mode,
            "size": config.size,
            "stride": config.stride,
            "min_events": config.min_events,
        },
        "split_policy": "SHA-256 by run_id: 70% train / 15% validation / 15% test",
        "max_runs": args.max_runs,
    }
    report_path = args.output.with_suffix(args.output.suffix + ".report.json")
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "inspect":
            result = inspect_dataset(args.input, args.source, args.max_runs)
        elif args.command == "preprocess":
            result = preprocess_dataset(args)
        elif args.command == "features":
            result = generate_feature_file(
                args.input,
                args.output,
                FeatureGenerationConfig(
                    window=SlidingWindowConfig(
                        mode=args.mode,
                        size=args.size,
                        stride=args.stride,
                        min_events=args.min_events,
                    ),
                    max_windows_per_run=args.max_windows_per_run,
                    seed=args.seed,
                ),
                source=args.source,
                max_runs=args.max_runs,
            )
        else:
            result = train_models(
                args.features,
                args.output_directory,
                seed=args.seed,
                exclude_features=tuple(args.exclude_feature),
            )
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        parser.error(str(error))
        return 2
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
