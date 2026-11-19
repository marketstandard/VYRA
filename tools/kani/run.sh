#!/usr/bin/env bash
# Reproduce the VYRA Kani run from a clean machine with Docker (Linux/macOS).
#   tools/kani/run.sh [out-dir]
# Builds the pinned image (tools/kani/Dockerfile), runs every harness (the
# signature harness included) and every mutant in a container with the
# repository mounted READ-ONLY, then copies the raw report to
# results/kani-report.txt. Exit status is non-zero if any harness is not
# SUCCESSFUL (FAILED, TIMEOUT or ERROR) or any mutant outcome differs from
# tools/kani/mutants.tsv.
# Env: HARNESS_TIMEOUT  seconds per harness run (default 1200)
#      KANI_JOBS        parallel Kani runs inside the container (default 4)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
out="${1:-$(mktemp -d)}"
mkdir -p "$out"
image="vyra-kani:0.68.0"

docker build -t "$image" "$here"
set +e
docker run --rm \
  -e HARNESS_TIMEOUT="${HARNESS_TIMEOUT:-1200}" -e KANI_JOBS="${KANI_JOBS:-4}" \
  -v "$repo:/repo:ro" -v "$out:/out" \
  "$image" bash /repo/tools/kani/in-container.sh
rc=$?
set -e
if [ -f "$out/kani-report.txt" ]; then
  docker image inspect --format 'image {{.Id}}' "$image" >> "$out/kani-report.txt" || true
  cp "$out/kani-report.txt" "$repo/results/kani-report.txt"
  echo "report: $repo/results/kani-report.txt (exit $rc)"
else
  echo "no report produced (exit $rc)"; [ "$rc" -ne 0 ] || rc=1
fi
exit $rc
