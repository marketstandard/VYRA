#!/usr/bin/env bash
# Host-side TYPE CHECK (not verification) of the Kani harness modules, for
# machines where Kani cannot run (e.g. Windows). Builds a scratch copy in
# which `kani` is a tiny stub crate (any() returns zeros, assume() is a no-op)
# and the #[kani::proof]/#[kani::unwind] attributes are stripped, then runs
# clippy with -D warnings (dead code allowed: nothing calls the harnesses).
# A pass here proves NOTHING about the properties; it only catches compile
# errors in the harness code before a real Kani run.
#   typecheck-harnesses.sh <scratch-dir>   (includes the sig harness)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
scratch="$1"; shift || true
ws="$scratch/ws"
bash "$here/make-workspace.sh" "$repo" "$ws" >/dev/null

mkdir -p "$ws/crates/kani/src"
cat > "$ws/crates/kani/Cargo.toml" <<'EOF'
[package]
name = "kani"
version = "0.0.0"
edition = "2024"
publish = false
EOF
cat > "$ws/crates/kani/src/lib.rs" <<'EOF'
//! Type-check stub only; NOT the Kani verifier.
pub trait Arb { fn arb() -> Self; }
impl Arb for u8 { fn arb() -> Self { 0 } }
impl Arb for usize { fn arb() -> Self { 0 } }
impl Arb for bool { fn arb() -> Self { false } }
impl<T: Arb, const N: usize> Arb for [T; N] { fn arb() -> Self { core::array::from_fn(|_| T::arb()) } }
pub fn any<T: Arb>() -> T { T::arb() }
pub fn assume(_c: bool) {}
pub fn assert(c: bool, msg: &'static str) { assert!(c, "{}", msg) }
EOF
sed -i 's#^members = .*#members = ["crates/vyra-core", "crates/vyra-sig", "crates/vyra-proofs", "crates/kani"]#' "$ws/Cargo.toml"
sed -i 's#^\[features\]#kani = { path = "../kani" }\n\n[features]#' "$ws/crates/vyra-proofs/Cargo.toml"
sed -i -e 's/^#\[cfg(kani)\]$//' -e 's/^#\[cfg(all(kani, feature = "sig"))\]$//' "$ws/crates/vyra-proofs/src/lib.rs"
sed -i -E '/^[[:space:]]*#\[kani::(proof|unwind\([0-9]+\))\]$/d' "$ws/crates/vyra-proofs/src/"*.rs
(cd "$ws" && CARGO_TARGET_DIR="$scratch/target" cargo clippy --offline -q -p vyra-proofs --features sig --lib -- \
  -D warnings -A dead_code)
echo "harness modules type-check (stub kani; NOT a verification result)"
