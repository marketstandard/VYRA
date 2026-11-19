# VYRA bounded model checking: results

Status (2026-11-19): **the Kani suite has been run to completion. Every harness
is SUCCESSFUL and every mutant behaved as expected.** The raw output is in
`results/kani-report.txt`, which `tools/kani/run.ps1` wrote.

Wording rule: each result below reads "bounded model checking of `<property>`
up to `<bound>`". Nothing outside the stated bound is covered. Nothing here
says anything about SHA-3, timing, or side channels.

## Tooling

| Item | Value |
|------|-------|
| Kani | 0.68.0 (`cargo install --locked kani-verifier --version 0.68.0`) |
| CBMC | 6.11.0 (installed by `cargo kani setup`) |
| SAT solver | CaDiCaL (the Kani default; no harness overrides it) |
| Base image | `rust:1-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea` (linux/amd64 manifest `sha256:198cd28b4ba92b20fe849d5d8b119ace1bd28423d9e82e9c4de5ee1300d453a0`) |
| Built image | `vyra-kani:0.68.0`, id `sha256:2dbdef80e322f20b4c274882069e090e7f2326328ef6dbcb54d3e782650f1ec0` |
| Host | Docker Desktop on Windows 11, WSL2 kernel 6.18.58.1, 32 CPUs, 31 GB |
| Command | `powershell -File tools\kani\run.ps1 -Jobs 8` (or `tools/kani/run.sh`); inside the container, per entry: `cargo kani -p vyra-proofs [--features sig] --harness <entry> -j 8 --output-format terse` |
| Total wall time | 1079 s end to end for `run.ps1` (docker build cached; includes a fresh Kani build of the crates); 800 s of that is verification (10 entries = 413 harnesses, plus 12 mutants). A dev-container run with a warm build: 860 s |

An "entry" is a Kani harness-name filter. The families marked `*` contain one
harness per **shape**: every combination of concrete lengths up to the bound,
with fully symbolic contents. The union of the shapes is exactly the bounded
domain. `tools/kani/gen-shapes.py` generates the families (`--check` detects a
stale list). Why shapes: see "What the run revealed".

## Per-harness results

| Entry | Property | Exact bound | Harnesses | Result | Time | Mutants (outcome) |
|-------|----------|-------------|-----------|--------|------|-------------------|
| `wire_decode_exact` | P1: `wire::decode` is total. It returns Ok exactly when magic, version and type match. On Ok it returns `input[6]` and exactly the subslice `input[7..]`. On every other input it returns the exact error class. | input length 0..=24, all byte values, all 7 expected types | 1 | SUCCESSFUL | 5 s | M1 killed |
| `wire_reader_ops` | P1: every `Reader` op is total. `take(n)` (for ANY `usize` n) returns exactly the next n bytes, or the exact error with the reader unchanged. After every step, `finish` succeeds exactly when all bytes were consumed. | input length 0..=64, sequences of up to 5 ops | 1 | SUCCESSFUL | 30 s | M2, M3 killed |
| `wire_round_trip` (`wire_round_trip_p0..p16`) | P2: `encode` produces exactly the specified header and payload layout. `decode(encode(t,s,p),u)` is `Ok((s,p))` exactly when `t == u`; otherwise it is the exact error. | payload length 0..=16, all byte values, all suite bytes, all 49 (t,u) pairs | 17 | SUCCESSFUL | 14 s | M4 killed |
| `wire_header_rejection` | P2: decode succeeds exactly when magic, version and type bytes are canonical. All 2^56 header values are covered symbolically. | payload length 0..=4 | 1 | SUCCESSFUL | 2 s | M5 killed |
| `transcript_prefix_inverse` | P3.1: `prefix_len(frame_prefix_of_len(n)) == Some(n)`; also `frame_prefix(x) == frame_prefix_of_len(len x)` | **every `usize` n** (2^64 values); x length ≤ 2 | 1 | SUCCESSFUL | 2 s | M8 killed |
| `transcript_single_frame` | P3.2: `take_frame(push_frame(x) ‖ rest) == Some((x, rest))`, returned as the exact subslices | len(x) ≤ 16, len(rest) ≤ 16, all byte values | 1 | SUCCESSFUL | 45 s | M6 killed |
| `transcript_framing_shape` (`*_l{a}_f{…}`) | P3.3: `parse_framed(framed_encoding(label, fields)) == (label, fields)`, which implies injectivity | label length ≤ 3; 0..=3 fields, each of length ≤ 3; all byte values | 340 | SUCCESSFUL | 374 s (8 parallel) | M7 killed |
| `secret_ct_eq_correct` | P4: `ct_eq` equals byte equality in both orders, with no panic on unequal lengths | lengths 0..=8 each, independently; all byte values | 1 | SUCCESSFUL | 11 s | M9 killed |
| `rng_adapter_latches_failure` | P5: `RandCoreRng` never panics. Before any failure, outputs are exactly the source's bytes. From the failing call on, outputs are all zero and the source is never called again. `finish` errors exactly when some call failed. | ≤ 4 calls of u32/u64/fill (buffer ≤ 8 bytes); every success/failure pattern; the source writes arbitrary bytes on failure | 1 | SUCCESSFUL | 26 s | M10, M11 killed |
| `sig_message_representative` (`*_c{c}_m{m}`) | P6: the real `vyra_sig::message_representative_with_digest` succeeds. Its 44-byte prefix `"VYRA-SIG-v1" ‖ suite ‖ digest` sits at fixed offsets. A reference parser recovers exactly (suite, digest, context, message), which implies injectivity. | context length 0..=6, message length 0..=6, all suite bytes, all 2^256 digests, all byte values | 49 | SUCCESSFUL | 47 s (8 parallel) | M12 killed |

Mutants (`tools/kani/mutants.tsv`). Each one is applied to a scratch copy and
run against its entry with `--fail-fast`. A kill counts only when a
**property** check fails. A failure that is only an unwinding assertion would
be recorded as `unwind-only`, which counts as an unexpected outcome.

| Mutant | Change | Failed check reported by Kani |
|--------|--------|-------------------------------|
| M1 | decode skips the version check | `assertion failed: header_ok` |
| M2 | `Reader::finish` always Ok | `assertion failed: fin == ...` |
| M3 | `take(n)` splits at n−1 | `assertion failed: n <= left`, `is_subslice_at(...)` |
| M4 | encode writes version 2 | `assertion failed: enc[4] == VERSION` |
| M5 | decode skips the type check | `assertion failed: res.is_ok() == canonical` |
| M6 | `push_frame` drops the length prefix | `take_frame rejected frame(x) \|\| rest` |
| M7 | prefix keeps only bit 0 of the length | `parse_framed rejected framed_encoding output` |
| M8 | prefix keeps only the low byte of the length | `prefix_len(frame_prefix_of_len(n)) == Some(n)` (now killed; it survived every earlier bound) |
| M9 | `ct_eq` compares lengths only | `sa.ct_eq(&sb) == (a == b)` |
| M10 | no zero-fill after a failure | `"non-zero output after failure"` |
| M11 | source called again after a failure | `"source called after a failure"` |
| M12 | vyra-sig representative drops the context-length byte | `repr.len() == SIG_FIXED_LEN + 1 + ctx.len() + msg.len()` |

## What the framing theorem now states (P3)

1. **For every `usize` length n**, the 8-byte prefix decodes back to n
   (`transcript_prefix_inverse`). The prefix arithmetic is therefore injective
   for all lengths. This covers the part that M8 attacks, which no
   small-length bound could see.
2. For |x| ≤ 16 and |rest| ≤ 16, `take_frame(frame(x) ‖ rest)` returns exactly
   `(x, rest)`, where `frame` is the library's own `push_frame`.
3. For label length ≤ 3 and ≤ 3 fields of length ≤ 3, the independent
   reference parser `vyra_proofs::reference::parse_framed` is a left inverse
   of `framed_encoding`. Hence, on that domain,
   `framed_encoding(a) == framed_encoding(b)` ⇒ `a = parse(enc(a)) = parse(enc(b)) = b`:
   same label, same number of fields, same bytes.

`Transcript` hashes exactly `framed_encoding`. The vyra-core host test
`transcript_hashes_exactly_framed_encoding` checks this as a known answer
through the sha3/shake crates, and both use `frame_prefix`.

NOT machine-checked:
- SHA3-256 / SHAKE256 (assumed collision resistant).
- Steps 2–3 beyond their bounds. The extension to long inputs is the hand
  argument "the parser reads the length, which step 1 proves correct for every
  length, and splits there; `split_at_checked` is the standard library".

## What each proof does NOT cover

- **Wire:** payload checks owned by vyra-kem/sig/seal (suite ids, lengths, key validation, check values); inputs beyond the bounds.
- **ct_eq:** timing and constant-time behaviour. Zeroization is also not covered: the harness skips `Drop` (`mem::forget`) because zeroize's optimisation barrier is inline assembly, which Kani does not support.
- **RNG:** `RandCoreTryRng`; randomness quality; what upstream crates do with zero bytes.
- **P6:** the public-key digest (SHA3-256); contexts longer than 6 bytes, although the function accepts up to 255; messages longer than 6 bytes; the component signature schemes.

## What the run revealed (no defect in vyra-core or vyra-sig)

- **`wire_reader_ops` FAILED in the first run.** This was a bound problem in the harness, not a defect: `1 of 323 failed: unwinding assertion loop 0, File "<builtin-library-memcmp>"`. The harness compares `Error::InvalidLength { what: "trailing bytes", .. }`, and comparing the 14-byte `&'static str` needs 15 unwindings, but the harness had `unwind(7)`. Raising it to 16 made the harness SUCCESSFUL. No library change.
- **`wire_round_trip` FAILED in the first run** with `1 of 700 failed: unwinding assertion loop 0`. This was the same harness bound problem: the 22-byte `"unexpected object type"` compare against `unwind(18)`. With `unwind(24)` the symbolic-length version then **exhausted memory** (CBMC "out of memory", ~30 GB). It is now one harness per payload length (17 harnesses, all lengths 0..=16), which takes seconds. The property is unchanged.
- **Framing (P3) and P6:** symbolic slice lengths combined with reading the encoder's output back made CBMC exhaust 28–31 GB. This happened during propositional post-processing, after symex: about 100k steps in ~3 s, then OOM.
  - Tried and failed:
    - smaller bounds, down to (1,2,1);
    - a no-allocation parser;
    - a stack copy of the encoding;
    - `--solver kissat` (OOM);
    - `--cbmc-args --arrays-uf-always` (still in post-processing at 240 s);
    - `--solver z3` (CBMC 6.11 crashes: `map::at`, status 6).
  - What worked: concrete lengths with symbolic contents, about 2 s per shape.
  - A second trigger: a `kani::any::<[u8; 0]>()` zero-sized buffer also blew up (OOM at shape (0,[3])). Every slice is therefore cut from a non-empty symbolic buffer; an empty slice is a value with no content, so no input is lost.
- **`secret_ct_eq_correct`** reported `TerminatorKind::InlineAsm is not currently supported` at `zeroize-1.9.2/src/barrier.rs:68`, reached through `Drop`. This is a Kani limitation, not a defect; the harness now skips `Drop` (see "not covered").
- **Earlier host finding (unchanged):** `Reader::rest()` leaves a dangling empty slice. This is harmless; harnesses compare empty slices by length.

## Exhaustive enumeration tests (host, no Kani)

`cargo test -p vyra-proofs` (tests/exhaustive.rs) still runs on any host. It checks P1–P5 over exactly stated finite domains, and now also checks the reference parser as a left inverse on the framing domain, plus a sanity test for the signature parser. The host mutation check `tools/kani/exhaustive-mutants.sh` exits 0. For these tests, M8 is still expected to survive: they only reach lengths below 256. The Kani prefix lemma is what kills it.

Mutant run times (s): M1 14, M2 11, M3 17, M4 8, M5 2, M6 15, M7 89, M8 2, M9 2, M10 28, M11 26, M12 26.
Times are wall-clock per entry (Kani build excluded), from `results/kani-report.txt`.
