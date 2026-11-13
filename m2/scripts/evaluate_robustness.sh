#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCAL_LIBOMP="$ROOT/vendor/libomp/libomp/23.1.2/lib"

if [[ "$(uname -s)" == "Darwin" && -d "$LOCAL_LIBOMP" ]]; then
  export DYLD_LIBRARY_PATH="$LOCAL_LIBOMP${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
fi

cd "$ROOT"
exec .venv/bin/ai-rdr-m2 robustness \
  data/processed/lifecycle-features.jsonl \
  artifacts/models/random_forest.joblib \
  artifacts/robustness \
  --seed 321 --repetitions 10 --folds 5
