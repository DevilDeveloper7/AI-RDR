#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCAL_LIBOMP="$ROOT/vendor/libomp/libomp/23.1.2/lib"

if [[ "$(uname -s)" == "Darwin" && -d "$LOCAL_LIBOMP" ]]; then
  export DYLD_LIBRARY_PATH="$LOCAL_LIBOMP${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
fi

exec "$ROOT/.venv/bin/ai-rdr-m2" train \
  "$ROOT/data/processed/lifecycle-features.jsonl" \
  "$ROOT/artifacts/models" \
  --seed 321
