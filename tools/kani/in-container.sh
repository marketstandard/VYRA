#!/usr/bin/env bash
# Runs INSIDE the Kani container (see Dockerfile). Expects the repository
# mounted read-only at /repo and a writable output directory at /out.
# 1. copies vyra-core, vyra-sig and vyra-proofs into /work (the repo is never
#    written);
# 2. runs every harness entry, then every mutant against its target entry,
#    one entry at a time, each with `cargo kani -j KANI_JOBS` (an entry is a
#    harness-name filter; shape-enumerated families such as
#    `transcript_framing_shape` match many harnesses);
# 3. writes /out/kani-report.txt (raw Kani output + summary table).
# Exit status: 0 iff every entry is SUCCESSFUL and every mutant's outcome
# matches mutants.tsv ("killed" = Kani reports a failed property check, not
# merely an unwinding assertion). TIMEOUT and ERROR are never SUCCESSFUL, so
# they make the exit status non-zero.
#
# Env: HARNESS_TIMEOUT  seconds per entry run (default 1200)
#      KANI_JOBS        harnesses verified in parallel within one entry (default 8)
#
# The "===== SUMMARY =====" block format is parsed by xtask (gate V2): keep
#   harness<TAB>name<TAB>RESULT<TAB>secs[<TAB>n=<harness count>]
#   mutant<TAB>id<TAB>harness<TAB>RESULT<TAB>outcome=..<TAB>expected=..<TAB>OK|UNEXPECTED<TAB>secs
#   overall exit status: N
set -uo pipefail
repo=/repo; out=/out; tools="$repo/tools/kani"
report="$out/kani-report.txt"
timeout_s="${HARNESS_TIMEOUT:-1200}"
jobs="${KANI_JOBS:-8}"
harnesses=(
  wire_decode_exact
  wire_reader_ops
  wire_round_trip
  wire_header_rejection
  transcript_prefix_inverse
  transcript_single_frame
  transcript_framing_shape
  secret_ct_eq_correct
  rng_adapter_latches_failure
  sig_message_representative
)

# Entries that need the `sig` feature (and thus a compiling vyra-sig).
features_for() { case "$1" in sig_*) echo "--features sig" ;; *) echo "" ;; esac; }

# run_one <workspace> <entry> <logfile> <resultfile> [extra kani args...]
# resultfile gets "RESULT SECS COUNT" (SUCCESSFUL|FAILED|TIMEOUT|ERROR).
run_one() {
  local ws="$1" h="$2" log="$3" res="$4" rc start result count
  shift 4
  start=$(date +%s)
  # shellcheck disable=SC2046
  (cd "$ws" && timeout "$timeout_s" cargo kani -p vyra-proofs $(features_for "$h") \
      --harness "$h" -j "$jobs" --output-format terse "$@") >"$log" 2>&1
  rc=$?
  count="$(sed -n 's/^Complete - \([0-9]*\) successfully verified harnesses, \([0-9]*\) failures.*/\1+\2/p' "$log" | tail -1)"
  count=$(( ${count:-0} ))
  if [ $rc -eq 124 ]; then result=TIMEOUT
  elif [ $rc -eq 0 ] && grep -q "VERIFICATION:- SUCCESSFUL" "$log"; then result=SUCCESSFUL
  elif grep -q "VERIFICATION:- FAILED" "$log"; then result=FAILED
  else result=ERROR; fi
  echo "$result $(( $(date +%s) - start )) $count" > "$res"
}

mkdir -p /work/logs
bash "$tools/make-workspace.sh" "$repo" /work/ws >/dev/null
# Build once (both feature sets) so the timed runs only verify.
(cd /work/ws && cargo kani -p vyra-proofs --only-codegen) >/work/logs/build.log 2>&1 || true
(cd /work/ws && cargo kani -p vyra-proofs --features sig --only-codegen) >/work/logs/build-sig.log 2>&1 || true

cbmc_bin="$(find "$HOME/.kani" -type f -name cbmc -perm -u+x 2>/dev/null | head -1)"
{
  echo "# VYRA Kani report"
  echo "date (UTC):   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "kani:         $(cargo kani --version 2>&1 | head -1)"
  echo "cbmc:         $("$cbmc_bin" --version 2>&1 | head -1)"
  echo "solver:       CaDiCaL (Kani default; no harness overrides it)"
  echo "rustc (host): $(rustc --version)"
  echo "uname:        $(uname -srm), $(nproc) CPUs"
  echo "settings:     HARNESS_TIMEOUT=${timeout_s}s KANI_JOBS=${jobs}"
  echo
} > "$report"
t0=$(date +%s)

for h in "${harnesses[@]}"; do
  run_one /work/ws "$h" "/work/logs/$h.log" "/work/logs/$h.res" < /dev/null
  echo "harness $h: $(cat "/work/logs/$h.res")"
done

# Mutants: one reusable workspace copy (with the built target dir, so only
# the mutated crate rebuilds); the mutated file is restored after each run.
rm -rf /work/mut; cp -R /work/ws /work/mut
while IFS=$'	' read -r id file _ _ harness _; do
  case "$id" in ''|\#*) continue ;; esac
  if bash "$tools/apply-mutant.sh" "$tools/mutants.tsv" "$id" /work/mut/crates >/dev/null; then
    run_one /work/mut "$harness" "/work/logs/mut-$id.log" "/work/logs/mut-$id.res" --fail-fast < /dev/null
  else
    echo "NOT-APPLIED - 0" > "/work/logs/mut-$id.res"
  fi
  cp "/work/ws/crates/$file" "/work/mut/crates/$file"
  echo "mutant $id: $(cat "/work/logs/mut-$id.res")"
done < "$tools/mutants.tsv"

# Report, in fixed order.
status=0
summary=()
for h in "${harnesses[@]}"; do
  read -r result secs count < "/work/logs/$h.res" || { result=ERROR; secs=-; count=0; }
  { echo "===== harness $h: $result (${secs}s wall, $count harnesses) ====="; cat "/work/logs/$h.log"; echo; } >> "$report"
  summary+=("harness	$h	$result	${secs}s	n=$count")
  [ "$result" = SUCCESSFUL ] || status=1
done
while IFS=$'\t' read -r id file _ _ harness _ expected _; do
  case "$id" in ''|\#*) continue ;; esac
  read -r result secs _ < "/work/logs/mut-$id.res" || { result=ERROR; secs=-; }
  case "$result" in FAILED) outcome=killed ;; SUCCESSFUL) outcome=survives ;; *) outcome="$result" ;; esac
  # A kill counts only if some failed check is a property check, not merely
  # an unwinding assertion (which would say "bound too small", not "bug found").
  if [ "$outcome" = killed ] && ! grep -A40 "Failed Checks:" "/work/logs/mut-$id.log"        | grep -E "^Failed Checks:" | grep -qv "unwinding assertion"; then
    outcome=unwind-only
  fi
  verdict=OK; [ "$outcome" = "$expected" ] || { verdict=UNEXPECTED; status=1; }
  { echo "===== mutant $id ($file) vs $harness: $result -> $outcome (expected $expected) $verdict ====="
    grep -E "Failed Checks:|File: |VERIFICATION|Verification Time" "/work/logs/mut-$id.log" 2>/dev/null | head -20
    echo; } >> "$report"
  summary+=("mutant	$id	$harness	$result	outcome=$outcome	expected=$expected	$verdict	${secs}s")
done < "$tools/mutants.tsv"

{ echo "total wall time: $(( $(date +%s) - t0 ))s (excluding image build)"
  echo "===== SUMMARY ====="; printf '%s\n' "${summary[@]}"; echo "overall exit status: $status"; } >> "$report"
printf '%s\n' "${summary[@]}"
echo "overall exit status: $status"
exit $status
