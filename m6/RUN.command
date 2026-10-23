#!/usr/bin/env bash
# Double-click this file on macOS (or run ./RUN.command). It simply starts run.sh.
cd "$(dirname "$0")" || exit 1
bash ./run.sh "$@"
status=$?
# Keep the Terminal window open if something went wrong, so the message can be read.
if [ $status -ne 0 ] && [ $status -ne 130 ] && [ $status -ne 143 ]; then
  printf '\nM6 stopped with an error (code %s). Press Enter to close this window.' "$status"
  read -r _
fi
exit $status
