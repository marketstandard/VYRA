#!/usr/bin/env bash
# Host-side mutation check for the exhaustive enumeration tests
# (crates/vyra-proofs/tests/exhaustive.rs). Runs on any OS with bash + perl +
# cargo (Git Bash on Windows works); needs no model checker.
#   exhaustive-mutants.sh <scratch-dir> [report-file]
# For each mutant in mutants.tsv that names an exhaustive test: fresh copy of
# the mutated file, apply mutant, run the one targeted test. Exit non-zero if
# the unmutated baseline fails or any outcome differs from the
# "expected (exhaustive)" column.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
scratch="$1"
report="${2:-$scratch/exhaustive-mutants.txt}"
ws="$scratch/ws"
export CARGO_TARGET_DIR="$scratch/target"

bash "$here/make-workspace.sh" "$repo" "$ws" >/dev/null
: > "$report"
status=0

run_test() { # $1 = test name or empty for all
  (cd "$ws" && cargo test --offline -q -p vyra-proofs --test exhaustive -- ${1:+--exact "$1"}) \
    >"$scratch/last.log" 2>&1
}

start=$(date +%s)
if run_test ""; then
  echo "BASELINE all exhaustive tests: PASS ($(( $(date +%s) - start ))s)" | tee -a "$report"
else
  echo "BASELINE: FAIL" | tee -a "$report"; tail -30 "$scratch/last.log"; exit 1
fi

while IFS=$'\t' read -r id file from to harness test _ expected; do
  case "$id" in ''|\#*) continue ;; esac
  [ "$test" = "-" ] && continue
  cp "$repo/crates/$file" "$ws/crates/$file"
  if ! bash "$here/apply-mutant.sh" "$here/mutants.tsv" "$id" "$ws/crates" >/dev/null; then
    echo "$id NOT APPLIED -> FAIL" | tee -a "$report"; status=1; continue
  fi
  if run_test "$test"; then outcome=survives; else
    if grep -q "error\[E" "$scratch/last.log"; then outcome=compile-error; else outcome=killed; fi
  fi
  verdict=OK; [ "$outcome" = "$expected" ] || { verdict=UNEXPECTED; status=1; }
  printf '%s\t%s\t%s\toutcome=%s\texpected=%s\t%s\n' "$id" "$file" "$test" "$outcome" "$expected" "$verdict" | tee -a "$report"
  cp "$repo/crates/$file" "$ws/crates/$file"
done < "$here/mutants.tsv"
exit $status
