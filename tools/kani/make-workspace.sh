#!/usr/bin/env bash
# Build a minimal, self-contained copy of the workspace that contains only
# vyra-core, vyra-sig and vyra-proofs (the code under proof), so proofs and
# mutants run on a copy and never touch the repository.
#   make-workspace.sh <repo-root> <dest-dir>
set -euo pipefail
repo="$1"; dest="$2"
rm -rf "$dest"
mkdir -p "$dest/crates"
for c in vyra-core vyra-sig vyra-proofs; do
  cp -R "$repo/crates/$c" "$dest/crates/$c"
  rm -rf "$dest/crates/$c/target"
done
cp "$repo/Cargo.lock" "$dest/Cargo.lock"
# Same workspace manifest, members narrowed to the three crates.
sed 's#^members = .*#members = ["crates/vyra-core", "crates/vyra-sig", "crates/vyra-proofs"]#' \
  "$repo/Cargo.toml" > "$dest/Cargo.toml"
echo "workspace copy at $dest"
