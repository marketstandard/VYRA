#!/usr/bin/env bash
# Apply one mutant from mutants.tsv to a COPY of the crates directory.
#   apply-mutant.sh <mutants.tsv> <mutant-id> <path-to-copy-of/crates>
# Fails (exit 3) unless the original text occurs exactly once, so a mutant can
# never silently not apply. Never point this at the real repository.
set -euo pipefail
tsv="$1"; id="$2"; crates="$3"

line="$(awk -F'\t' -v id="$id" '$1 == id' "$tsv")"
[ -n "$line" ] || { echo "unknown mutant $id" >&2; exit 2; }
IFS=$'\t' read -r _ file from to _ <<<"$line"
target="$crates/$file"

FROM="$from" TO="$to" perl -0777 -i -pe '
  my $n = () = /\Q$ENV{FROM}\E/g;
  if ($n != 1) { print STDERR "mutant text occurs $n times\n"; exit 3 }
  s/\Q$ENV{FROM}\E/$ENV{TO}/;
' "$target"
grep -qF -- "$to" "$target" || { echo "mutant $id not applied" >&2; exit 3; }
echo "applied $id to $file"
