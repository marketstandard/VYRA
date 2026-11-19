# VYRA specification, wire version 1

## 1. Status and scope

This document specifies VYRA wire version 1: a hybrid key-encapsulation
mechanism (VYRA-KEM), a composite signature scheme (VYRA-SIG) and a sealed box
(VYRA-SEAL), as implemented in the crates `vyra-core`, `vyra-kem`, `vyra-sig`
and `vyra-seal` at version 0.1.0.

- **Status: research prototype.** VYRA has had no independent cryptanalysis and
  no third-party audit. No security proof exists for VYRA's concrete
  instantiation. See `docs/SECURITY.md` and `docs/THREAT_MODEL.md`.
- **Source of truth.** Every byte layout, label and size below was read from the
  code. Where this document and the code disagree, the code defines version 1
  and this document has a bug.
- **HQC version.** The HQC component implements the **HQC specification
  version 5.1 (2026/11/09)**, reference implementation tag `v5.1.0` (commit
  `06567ccb`), through VYRA's in-tree port `crates/vyra-hqc` (D-14). HQC is
  not yet a published standard (FIPS 207 is pending).
- **Wire version.** The version byte is 1. Per D-14, "v1" is the format at
  first publication of the repository; earlier development snapshots that
  used the same byte with pre-v5.1 HQC parameters are not VYRA v1.
- **Interoperability.** HQC keys, ciphertexts and shared secrets match the
  official HQC v5.1 known-answer vectors (component level only; there is no
  independent second v5.1 implementation to interoperate with, and nothing is
  claimed about FIPS 207). The VYRA hybrid formats themselves interoperate with
  nothing else: not with the IETF composite ML-DSA format (RFC 10073, formerly
  draft-ietf-lamps-pq-composite-sigs), not with X-Wing or the CFRG hybrid-KEM
  drafts.
- **Name.** VYRA stands for "Verified Yielding Resistance Architecture"; what
  each word means and does not mean is defined by its evidence in D-15 and
  `docs/SECURITY.md` §"What the name means".
- **Scope.** VYRA specifies primitives. It does not specify a protocol, key
  distribution, identity binding, replay protection or algorithm negotiation.

The key words MUST, MUST NOT, SHOULD are used in their RFC 2119 sense.

## 2. Notation

| Notation | Meaning |
|----------|---------|
| `a ‖ b` | byte-string concatenation |
| `len(x)` | length of `x` in bytes |
| `u64_be(n)` | `n` as an 8-byte big-endian unsigned integer |
| `[b]` | the one-byte string containing byte `b` |
| `"..."` | the ASCII bytes of the string, no terminator |
| `x[i..j]` | bytes `i` (inclusive) to `j` (exclusive) of `x` |
| `frame(x)` | `u64_be(len(x)) ‖ x` |
| `SHA3-256`, `SHAKE256` | FIPS 202 |
| `ss`, `K` | shared secrets (32 bytes) |
| component 1 / 2 | KEM: 1 = ML-KEM, 2 = HQC. Signature: 1 = ML-DSA, 2 = Ed25519 (transition suites) or SLH-DSA (dual post-quantum suites) |

All lengths are in bytes. All objects have fixed lengths per suite except the
sealed box, whose length is `len(plaintext) + overhead(suite)`.

## 3. Components

Every building block is labelled **ESTABLISHED** (specified and analysed
outside VYRA; VYRA uses it unmodified) or **VYRA-ORIGINAL** (designed in this
project; reviewed only within this project; no external specification or
analysis).

| Component | Label | Source / where specified | Used for |
|-----------|-------|--------------------------|----------|
| ML-KEM-512/768/1024 | ESTABLISHED | FIPS 203; Rust crate `ml-kem` 0.3.4 | KEM component 1 |
| HQC-128/192/256 (the specification's HQC-1/3/5), HQC v5.1 — the **algorithm** | ESTABLISHED (published design, pre-standard: FIPS 207 unpublished) | HQC specification version 5.1 (2026/11/09); reference implementation tag `v5.1.0`, commit `06567ccb`, gitlab.com/pqc-hqc/hqc | KEM component 2 |
| HQC v5.1 **implementation** `crates/vyra-hqc` | VYRA-ORIGINAL (in-tree port: a fork of `hqc-kem` 0.1.0-rc.0 modified by the VYRA authors to v5.1; checked against all official v5.1 KATs only; see its `NOTICE.md`) | D-14 | KEM component 2 |
| ML-DSA-44/65/87 (pure, hedged) | ESTABLISHED | FIPS 204; Rust crate `ml-dsa` 0.1.2 | signature component 1 |
| Ed25519ph (RFC 8032, SHA-512 prehash, with context) | ESTABLISHED | RFC 8032 §5.1; Rust crate `ed25519-dalek` 3.0.0, `sign_prehashed` / `verify_prehashed_strict` | signature component 2, transition suites (§7.4) |
| Ed25519 (PureEd25519) | ESTABLISHED | RFC 8032; Rust crate `ed25519-dalek` 3.0.0, `verify_strict` | standalone `Ed25519` adapter only (not inside the composite) |
| SLH-DSA-SHAKE-128s/192s/256s (pure, hedged) | ESTABLISHED | FIPS 205; Rust crate `fips205` 0.5.0 | signature component 2, dual post-quantum suites |
| SHA3-256, SHAKE256 | ESTABLISHED | FIPS 202; Rust crates `sha3` 0.12.0, `shake` 0.1.0 | transcript, combiner, KDF |
| ChaCha20-Poly1305 | ESTABLISHED | RFC 8439; Rust crate `chacha20poly1305` 0.11.0 | sealed-box DEM |
| KEM combiner technique (hash both shared secrets and the ciphertexts) | ESTABLISHED | Giacon, Heuer, Poettering, PKC 2018 | hybrid KEM key derivation |
| KEM-DEM (hybrid encryption) paradigm | ESTABLISHED | Cramer–Shoup; HPKE (RFC 9180) base mode | sealed box |
| Composite "sign the same representative with both, require both" technique | ESTABLISHED as a technique (e.g. RFC 10073) | — | composite signature |
| Transcript framing (`frame`, SHA3/SHAKE domain byte) | VYRA-ORIGINAL | §4 | all VYRA hashing |
| Wire format (header, object types, suite ids) | VYRA-ORIGINAL | §5 | all serialized objects |
| Suite identifiers and component pairings | VYRA-ORIGINAL | §6.1, §7.1 | KEM, signature |
| Combiner encoding (label, field order, inclusion of suite id and public keys) | VYRA-ORIGINAL | §6.4 | hybrid KEM |
| Hybrid KEM key and ciphertext layouts `pk1 ‖ pk2`, `sk1 ‖ sk2`, `ct1 ‖ ct2` | VYRA-ORIGINAL | §6.2 | hybrid KEM |
| Seed-form component secret keys (ML-KEM `d ‖ z`, HQC `seed_kem`, ML-DSA ξ) | ESTABLISHED (seed forms are defined by FIPS 203, FIPS 204, and the HQC v5.1 specification, whose default decapsulation key is the 32-byte seed); their use as VYRA's only stored form is a VYRA choice (D-12, D-13) | §6.2, §7.2 | key storage |
| SLH-DSA secret key stored as `SK.seed ‖ SK.prf ‖ PK.seed` with `PK.root` recomputed | VYRA-ORIGINAL storage form (the three fields are FIPS 205 key-generation inputs; FIPS 205's secret key is 4n bytes) | §7.2 | key storage |
| ML-KEM encapsulation-key check (type + modulus check) | ESTABLISHED (FIPS 203 §7.2 input check, performed by `ml-kem`) | §6.3 | public-key validation |
| HQC public-key padding-bit check | VYRA-ORIGINAL (strictness addition; the HQC v5.1 specification defines no encapsulation-key validation) | §6.3 | public-key validation |
| Ed25519 public-key validation (decodes, canonical re-encoding, not small order, in the prime-order subgroup) | VYRA-ORIGINAL rule set built from ESTABLISHED checks (RFC 8032 canonical encoding; small-order rejection as in `verify_strict`; prime-order-subgroup membership) | §7.6 | public-key validation |
| ML-DSA public-key validation (length only) | ESTABLISHED encoding fact (FIPS 204 `pkEncode`: every string of the right length is canonical) | §7.6 | public-key validation |
| SLH-DSA public-key validation (length only) | ESTABLISHED encoding fact (FIPS 205: `PK.seed ‖ PK.root`, every 2n-byte string is valid and canonical) | §7.6 | public-key validation |
| Secret-key check value (`VYRA-KEM-SK-v1`, `VYRA-SIG-SK-v1`, 16 bytes) | VYRA-ORIGINAL | §5.2 | wire secret keys |
| Signature message representative `M'`, public-key digest, composite context string | VYRA-ORIGINAL | §7.3 | composite signature |
| Context-binding contract (`CompositeComponent::context_bound`; every half signs under the composite context through a context-bearing mode) | VYRA-ORIGINAL | §7.4 | composite signature |
| Custom-assembly entry points (`CustomComposite::from_components`, `CustomHybridKem::from_components`) | VYRA-ORIGINAL | §7.8 | experiments, crypto-agility |
| Composite key and signature concatenation format | VYRA-ORIGINAL | §7.2 | composite signature |
| Sealed-box KDF encoding, AAD framing, derived nonce, wire layout | VYRA-ORIGINAL | §8 | sealed box |
| `DeterministicEntropy` (test-only SHAKE256 stream) | VYRA-ORIGINAL (test tooling, not a security component) | §9 | tests and vectors only |

## 4. Transcript function

Source: `crates/vyra-core/src/transcript.rs`.

A transcript is started with a label and accepts an ordered list of fields.
Each input, the label included, is framed:

```text
frame(x) = u64_be(len(x)) ‖ x
```

Two outputs are defined:

```text
Transcript(label; f1, ..., fn).finalize()
    = SHA3-256( frame(label) ‖ frame(f1) ‖ ... ‖ frame(fn) )                  32 bytes

Transcript(label; f1, ..., fn).finalize_xof(L)
    = SHAKE256( 0x01 ‖ frame(label) ‖ frame(f1) ‖ ... ‖ frame(fn) )[0..L]
```

- `vyra-core` exposes the encoding as pure functions: `frame_prefix_of_len(n)`
  (the 8-byte `u64_be(n)`), `frame_prefix(x)`, `push_frame(out, x)` and
  `framed_encoding(label, fields)`, the exact byte string the SHA3-256 form
  hashes (checked by a known-answer test). Implementers can compare against
  `framed_encoding` before hashing.
- The fixed-output form has **no** prefix byte. The XOF form prepends the domain
  byte `XOF_DOMAIN = 0x01`. (SHA3-256 and SHAKE256 also use different FIPS 202
  padding suffixes.)
- Because every field is length-prefixed with a fixed-width length, the map from
  `(label, f1, ..., fn)` to the framed byte string is injective.
- Labels used in v1 (each appears verbatim in the code):

| Label | Output form | Used by |
|-------|-------------|---------|
| `"VYRA-KEM-v1"` | SHA3-256 | KEM combiner (§6.4) |
| `"VYRA-SIG-PK-v1"` | SHA3-256 | signature public-key digest (§7.3) |
| `"VYRA-KEM-SK-v1"` | SHA3-256, first 16 bytes | KEM wire secret-key check value (§5.2) |
| `"VYRA-SIG-SK-v1"` | SHA3-256, first 16 bytes | signature wire secret-key check value (§5.2) |
| `"VYRA-SEAL-v1"` | SHAKE256 | sealed-box KDF (§8.2) |
| `"VYRA-DeterministicEntropy-v1"` | SHAKE256 | test-only entropy stream (§9) |

`"VYRA-SIG-v1"` and `"VYRA-SEAL-v1"` additionally appear unframed as fixed
prefixes (§7.3, §8.3).

## 5. Wire format

Source: `crates/vyra-core/src/wire.rs`.

Every serialized object is a 7-byte header followed by a payload:

```text
offset 0..4   magic        "VYRA"  (0x56 0x59 0x52 0x41)
offset 4      version      0x01
offset 5      object type  one byte, table below
offset 6      suite id     one byte, interpreted by the object's owner
offset 7..    payload
```

| Object type | Value | Payload | Suite ids |
|-------------|-------|---------|-----------|
| KemPublicKey | 1 | raw hybrid public key `pk1 ‖ pk2` | KEM: 1, 3, 5 |
| KemSecretKey | 2 | raw hybrid secret key `sk1 ‖ sk2` (96) ‖ check (16) | KEM: 1, 3, 5 |
| KemCiphertext | 3 | raw hybrid ciphertext `ct1 ‖ ct2` | KEM: 1, 3, 5 |
| SigPublicKey | 4 | `pk_first ‖ pk_second` | SIG: 0x02, 0x03, 0x05, 0x11, 0x13, 0x15 |
| SigSecretKey | 5 | `sk_first ‖ sk_second` (64 / 80 / 104 / 128) ‖ check (16) | SIG: 0x02, 0x03, 0x05, 0x11, 0x13, 0x15 |
| Signature | 6 | `sig_first ‖ sig_second` | SIG: 0x02, 0x03, 0x05, 0x11, 0x13, 0x15 |
| SealedBox | 7 | `kem_ct_raw ‖ aead_ciphertext ‖ tag` | KEM: 1, 3, 5 |

Object type values 0 and 8–255 are unassigned and MUST be rejected.

### 5.1 Strictness rules

A decoder MUST reject, with an error and without panicking:

1. input shorter than 7 bytes (`InvalidLength`);
2. magic other than `"VYRA"` (`InvalidEncoding`);
3. version other than `0x01` (`InvalidEncoding`);
4. object type other than the one expected by the caller (`InvalidEncoding`);
5. a suite id not assigned for that object family (`UnknownSuite`);
6. for fixed-length objects, a payload whose length differs from the suite's
   payload length, both shorter and longer (`InvalidLength`; no trailing bytes
   allowed);
7. for KEM public keys, a key failing component validation (§6.3);
8. for composite signature public keys, a key failing validation (§7.6);
9. for KEM and signature secret keys, a check value that does not match
   (`InvalidEncoding("secret key check value mismatch")`, §5.2);
10. for sealed boxes, a payload shorter than `len(kem_ct_raw) + 16`.

Additional rules at use time:

- The typed operations compare the object's suite with the operating
  instance's suite and reject a mismatch (`InvalidEncoding`).
- **Raw secret keys carry no suite.** Secret keys are suite-length-uniform (96
  bytes for every KEM suite, 64 bytes for every signature suite) and every byte
  string of that length is a valid pair of seeds. The raw trait-level
  operations (`Kem::decapsulate`, `CompositeSignature::sign_raw`) therefore
  accept a raw key of another suite and derive unrelated component keys from
  it. Only the typed objects and the wire form (with its check value) bind the
  suite.

### 5.2 Secret-key check value

Because secret keys have the same length in every suite, length cannot detect a
relabelled suite id. The wire payload of a secret key is therefore

```text
KEM:  payload = sk_raw (96) ‖ check,  check = SHA3-256( frame("VYRA-KEM-SK-v1") ‖ frame([suite_id]) ‖ frame(sk_raw) )[0..16]
SIG:  payload = sk_raw (64) ‖ check,  check = SHA3-256( frame("VYRA-SIG-SK-v1") ‖ frame([suite_id]) ‖ frame(sk_raw) )[0..16]
```

i.e. the first 16 bytes of `Transcript(label; [suite_id], sk_raw).finalize()`.
The parser recomputes it and compares in constant time. It detects a
relabelled suite id and accidental corruption. It is **not a MAC**: it has no
key, so anyone who can rewrite the file can recompute it; it reveals nothing
that the file does not already contain.

## 6. Hybrid KEM (VYRA-KEM)

Sources: `crates/vyra-kem/src/{suite,hybrid,combiner,mlkem,hqc,keys}.rs`.

### 6.1 Suites

| Suite name | Suite id | Component 1 | Component 2 | Claimed NIST category |
|------------|----------|-------------|-------------|-----------------------|
| VYRA-KEM-1 | 1 | ML-KEM-512 | HQC-128 | 1 |
| VYRA-KEM-3 | 3 | ML-KEM-768 | HQC-192 | 3 |
| VYRA-KEM-5 | 5 | ML-KEM-1024 | HQC-256 | 5 |

The suite's category is the minimum of the categories claimed by its components
(both claim the same category). These are the components' claims, not VYRA
results. The HQC categories are the HQC designers' claims for the v5.1
parameter sets (`docs/SECURITY.md` §Parameter analysis).

### 6.2 Component encodings and sizes

| Component | pk | sk (as stored by VYRA) | ct | ss |
|-----------|----|------------------------|----|----|
| ML-KEM-512 | 800 | 64 (seed `d ‖ z`) | 768 | 32 |
| ML-KEM-768 | 1184 | 64 (seed `d ‖ z`) | 1088 | 32 |
| ML-KEM-1024 | 1568 | 64 (seed `d ‖ z`) | 1568 | 32 |
| HQC-128 | 2241 | 32 (seed `seed_kem`) | 4433 | 32 |
| HQC-192 | 4514 | 32 (seed `seed_kem`) | 8978 | 32 |
| HQC-256 | 7237 | 32 (seed `seed_kem`) | 14421 | 32 |

- **ML-KEM public key:** the FIPS 203 encapsulation key `ek`.
- **ML-KEM secret key:** the 64-byte seed `d ‖ z` (32 + 32 bytes) from which
  FIPS 203 `ML-KEM.KeyGen_internal(d, z)` derives the key pair. VYRA stores the
  seed, never the expanded decapsulation key, and re-derives the key pair on
  every decapsulation (D-12). Every 64-byte string is a valid seed.
- **ML-KEM ciphertext / shared secret:** FIPS 203 `c` and `K`.
- **HQC public key:** `seed_ek (32) ‖ s`, where `s` is an `n`-bit vector packed
  little-endian into `ceil(n/8)` bytes; `n = 17669 / 35851 / 57637`.
- **HQC secret key:** the 32-byte key-generation seed `seed_kem` (D-13). In
  HQC v5.1 this is exactly the specification's default (compressed)
  decapsulation key, `dk_KEM = seed_KEM`, and equals the KAT `sk` byte for
  byte. On every use the key pair is re-derived: `seed_PKE` (and, for
  decapsulation, `sigma`) is squeezed from `SHAKE256(seed_kem ‖ [k/8])`
  (`k/8` = 16 / 24 / 32), then the PKE key pair is generated from `seed_PKE`.
  Decapsulation derives the key pair once and uses it for both the shared
  secret and the public key fed to the combiner. Every 32-byte string is a
  valid seed.
- **HQC parameters (v5.1):** `n = 17669 / 35851 / 57637`; weights
  ω = 67 / 101 / 132, ω_r = ω_e = 76 / 114 / 150; `F_2^8` arithmetic with
  polynomial `0x11B` (`x^8 + x^4 + x^3 + x + 1`).
- **HQC ciphertext:** `c_pke ‖ salt` (salt 16 bytes).

Hybrid raw encodings:

```text
pk = pk1 ‖ pk2          (ML-KEM ek ‖ HQC ek)
sk = sk1 ‖ sk2          (ML-KEM seed d‖z (64) ‖ HQC seed_kem (32)) = 96 bytes, every suite
ct = ct1 ‖ ct2          (ML-KEM c ‖ HQC c_kem)
K  = 32 bytes
```

The hybrid secret key consists only of seeds and stores no public key. During
decapsulation both `pk1` and `pk2` are re-derived from the seeds, so a secret
key cannot carry public keys that contradict it.

### 6.3 Public-key validation

A hybrid public key MUST pass both checks, at parse time
(`HybridPublicKey::from_raw` / `from_bytes`) and again inside every
encapsulation:

1. **ML-KEM (FIPS 203 encapsulation-key check):** length check, and the modulus
   check (decoding and re-encoding the 12-bit coefficients reproduces the
   input, i.e. no coefficient is `≥ q = 3329`). Performed by `ml-kem`
   `EncapsulationKey::new`. Failure: `InvalidEncoding("ML-KEM public key failed
   the FIPS 203 modulus check")`.
2. **HQC padding check (VYRA strictness addition):** the bits of the last
   public-key byte above bit `n − 1` MUST be zero. The mask is
   `0xFF << (n mod 8)`: `0xE0` for HQC-128 (`n mod 8 = 5`), `0xF8` for HQC-192
   (`n mod 8 = 3`), `0xE0` for HQC-256 (`n mod 8 = 5`). The HQC v5.1
   specification defines no encapsulation-key validation and `vyra-hqc` does
   not perform this check; VYRA does, in its adapter. It makes every
   accepted HQC public key have exactly one encoding and does not affect
   honestly generated keys.

Public keys derived from seeds are honest by construction and are not
re-validated.

### 6.4 Combiner

```text
K = SHA3-256( frame("VYRA-KEM-v1") ‖ frame([suite_id]) ‖ frame(ss1) ‖ frame(ss2)
              ‖ frame(ct1) ‖ frame(ct2) ‖ frame(pk1) ‖ frame(pk2) )
```

i.e. `Transcript("VYRA-KEM-v1"; [suite_id], ss1, ss2, ct1, ct2, pk1, pk2).finalize()`.
Concretely, for VYRA-KEM-3 the hashed string begins

```text
00 00 00 00 00 00 00 0b  "VYRA-KEM-v1"
00 00 00 00 00 00 00 01  03
00 00 00 00 00 00 00 20  ss1 (32 bytes)
00 00 00 00 00 00 00 20  ss2 (32 bytes)
00 00 00 00 00 00 04 40  ct1 (1088 bytes)
...
```

### 6.5 Algorithms

Entropy is drawn from the caller's `EntropySource` in exactly the order and
amounts shown (asserted by `crates/vyra-kem/tests/entropy.rs`).

```text
KeyGen(suite):
    d‖z  ← 64 bytes of entropy                    # ML-KEM seed
    (pk1, _) ← ML-KEM.KeyGen_internal(d, z)
    seed_kem ← 32 bytes of entropy                 # HQC seed
    (pk2, _) ← HQC.KeyGen_deterministic(seed_kem)
    return pk = pk1 ‖ pk2,  sk = (d‖z) ‖ seed_kem

Encaps(suite, pk):
    require len(pk) = pk_len(suite);  split pk = pk1 ‖ pk2
    validate pk1 (FIPS 203 modulus check) and pk2 (padding check)    else error
    (ct1, ss1) ← ML-KEM.Encaps(pk1)                # draws 32 bytes (m)
    (ct2, ss2) ← HQC.Encaps(pk2)                   # draws k + 16 bytes (m, salt)
    K ← Combine(suite_id, ss1, ss2, ct1, ct2, pk1, pk2)
    return ct = ct1 ‖ ct2, K

Decaps(suite, sk, ct):
    require len(sk) = sk_len(suite), len(ct) = ct_len(suite)          else error
    split sk = sk1 ‖ sk2, ct = ct1 ‖ ct2
    r1 ← (ML-KEM.Decaps(KeyGen_internal(sk1).dk, ct1), KeyGen_internal(sk1).ek)
    (ek2, dk2) ← HQC.KeyGen_deterministic(sk2)
    r2 ← (HQC.Decaps(dk2, ct2), ek2)
    # both r1 and r2 are computed before either result is inspected
    if r1 or r2 is an error: return that error (lengths are checked first, so
                                                 no error is expected here)
    return Combine(suite_id, ss1, ss2, ct1, ct2, pk1 = ek1, pk2 = ek2)
```

The raw `Decaps` takes a raw 96-byte key without a suite; a raw key of another
suite is accepted and yields an unrelated key (§5.1). The typed
`decapsulate_with` checks the suite of both key and ciphertext.

Entropy per operation (bytes):

| Suite | KeyGen | Encaps |
|-------|--------|--------|
| VYRA-KEM-1 | 64 + 32 = 96 | 32 + 32 = 64 |
| VYRA-KEM-3 | 64 + 32 = 96 | 32 + 40 = 72 |
| VYRA-KEM-5 | 64 + 32 = 96 | 32 + 48 = 80 |

Decapsulation draws no entropy.

### 6.6 Implicit rejection and errors

- Both components use implicit rejection (D-02): a well-formed ciphertext that
  fails the component's re-encryption check yields a pseudorandom component
  secret, not an error. The hybrid inherits this: decapsulation of a tampered
  ciphertext returns a 32-byte `K` that differs from the sender's.
- `Err` is returned only for conditions that depend on public data or on the
  caller's own key object: wrong lengths (`InvalidLength`), bad header, wrong
  object type or suite (`InvalidEncoding`, `UnknownSuite`), a non-canonical
  public key (`InvalidEncoding`), a wire secret key whose check value does not
  match (`InvalidEncoding`), and entropy failure
  (`EntropyFailure`) during KeyGen/Encaps. On `EntropyFailure` no partial
  output is returned.
- An entropy source that fails part-way through an upstream call is handled by
  `vyra_core::RandCoreRng`: it latches the failure, zero-fills that request and
  all later ones, and the adapter's `finish()` makes the VYRA call return
  `EntropyFailure`; the upstream result is discarded.

## 7. Composite signature (VYRA-SIG)

Sources: `crates/vyra-sig/src/{suite,message,composite,component,custom,mldsa,slhdsa,ed25519,keys}.rs`.

### 7.1 Suites

Two families share one composition engine and one message representative.
The suite-to-component mapping is defined in one place (`SigSuite`'s private
`components`).

| Suite name | Suite id | Family | Component 1 | Component 2 | Category label |
|------------|----------|--------|-------------|-------------|----------------|
| VYRA-SIG-2 | 0x02 | transition | ML-DSA-44 | Ed25519 | 2 (ML-DSA-44 only) |
| VYRA-SIG-3 | 0x03 | transition | ML-DSA-65 | Ed25519 | 3 (ML-DSA-65 only) |
| VYRA-SIG-5 | 0x05 | transition | ML-DSA-87 | Ed25519 | 5 (ML-DSA-87 only) |
| VYRA-SIG-PQ1 | 0x11 | dual post-quantum | ML-DSA-44 | SLH-DSA-SHAKE-128s | 1 = min(2, 1) |
| VYRA-SIG-PQ3 | 0x13 | dual post-quantum | ML-DSA-65 | SLH-DSA-SHAKE-192s | 3 = min(3, 3) |
| VYRA-SIG-PQ5 | 0x15 | dual post-quantum | ML-DSA-87 | SLH-DSA-SHAKE-256s | 5 = min(5, 5) |

- **Transition suites:** the label describes the ML-DSA component only.
  Ed25519 offers roughly 128-bit classical security in every suite and none
  against an adversary with a large quantum computer; VYRA-SIG-3 and
  VYRA-SIG-5 are deliberate category mismatches (D-08).
- **Dual post-quantum suites:** the label is the minimum of the two
  components' claimed NIST categories (D-17). All categories are the
  designers' claims (FIPS 204, FIPS 205).

### 7.2 Component encodings

| Component | pk | sk (as stored by VYRA) | sig |
|-----------|----|------------------------|-----|
| ML-DSA-44 | 1312 | 32 (seed ξ) | 2420 |
| ML-DSA-65 | 1952 | 32 (seed ξ) | 3309 |
| ML-DSA-87 | 2592 | 32 (seed ξ) | 4627 |
| Ed25519 | 32 | 32 (RFC 8032 private key) | 64 |
| SLH-DSA-SHAKE-128s (n = 16) | 32 | 48 (`SK.seed ‖ SK.prf ‖ PK.seed`) | 7856 |
| SLH-DSA-SHAKE-192s (n = 24) | 48 | 72 (`SK.seed ‖ SK.prf ‖ PK.seed`) | 16224 |
| SLH-DSA-SHAKE-256s (n = 32) | 64 | 96 (`SK.seed ‖ SK.prf ‖ PK.seed`) | 29792 |

- **ML-DSA:** FIPS 204 `pkEncode` / `sigEncode`; secret key = the 32-byte seed
  ξ of `ML-DSA.KeyGen_internal`, re-expanded on every signing (D-12).
- **Ed25519:** RFC 8032 encodings; secret key = the 32-byte private key.
- **SLH-DSA:** FIPS 205 public key `PK.seed ‖ PK.root` (2n bytes); signature
  `R ‖ SIG_FORS ‖ SIG_HT`. VYRA stores the secret key as
  `SK.seed ‖ SK.prf ‖ PK.seed` (3n bytes), exactly the key-generation
  randomness of FIPS 205 `slh_keygen`; the standard 4n-byte secret key also
  holds `PK.root`, which these three fields determine. VYRA does not store
  `PK.root` and recomputes it with `slh_keygen_internal` (FIPS 205 Algorithm
  18) on every signing call, so no stored copy can disagree with the seeds.
  Every 3n-byte string is a valid secret key. Implementation: the `fips205`
  0.5.0 crate, pure SLH-DSA (Algorithms 22/24, not HashSLH-DSA).

Composite raw encodings:

```text
pk  = pk_first ‖ pk_second          (ML-DSA ‖ Ed25519, or ML-DSA ‖ SLH-DSA)
sk  = sk_first ‖ sk_second          (ξ ‖ Ed25519 seed: 64 bytes; ξ ‖ SLH-DSA 3n: 80 / 104 / 128)
sig = sig_first ‖ sig_second
```

### 7.3 Message representative, public-key digest, composite context

```text
pk_digest = SHA3-256( frame("VYRA-SIG-PK-v1") ‖ frame([suite_id])
                      ‖ frame(pk_first) ‖ frame(pk_second) )               32 bytes

M' = "VYRA-SIG-v1" ‖ [suite_id] ‖ pk_digest ‖ [len(ctx)] ‖ ctx ‖ M

ctx_composite = "VYRA-SIG-v1" ‖ [suite_id]                                12 bytes
```

- `"VYRA-SIG-v1"` is 11 bytes, unframed. `len(ctx)` is one byte; the caller's
  `ctx` MUST be at most 255 bytes (`MAX_CONTEXT_LEN = 255`), otherwise
  `InvalidLength`. `len(M') = 45 + len(ctx) + len(M)`.
- `M` is not pre-hashed in `M'`.
- `(suite_id, pk_digest, ctx, M) → M'` is injective (fixed-length prefix
  fields, length-prefixed `ctx`, `M` last). The layout function
  `message_representative_with_digest` calls no hash function, so it can be
  checked on its own (see `docs/SECURITY.md` §Machine-checked properties).
- `ctx_composite` (`composite_context(suite_id)`; `mldsa_context(suite)` is the
  same value) is the context string **every** component signs under. It is
  12 bytes, well inside every component's 255-byte context limit (FIPS 204,
  FIPS 205, RFC 8032 Ed25519ph).
- The raw `SignatureScheme` interface of the composite uses the empty `ctx`.

### 7.4 Component halves (the context-binding contract)

Every component of a named suite is **context-bound**: it signs `M'` under
`ctx_composite` through a context-bearing mode, so no half is a valid
standalone default-mode signature (empty-context ML-DSA / SLH-DSA,
PureEd25519).

| Component | `sign_half(sk, M', ctx_composite)` | `verify_half(pk, M', ctx_composite, σ)` |
|-----------|------------------------------------|-----------------------------------------|
| ML-DSA | FIPS 204 `ML-DSA.Sign(sk, M', ctx_composite)`, pure, **hedged** (32-byte `rnd` drawn from the caller's entropy source) | FIPS 204 `ML-DSA.Verify(pk, M', σ, ctx_composite)` |
| SLH-DSA | FIPS 205 `slh_sign(M', ctx_composite, sk)`, pure, **hedged** (n-byte `addrnd` drawn from the caller's entropy source); `PK.root` recomputed from the stored seeds first | FIPS 205 `slh_verify(M', σ, ctx_composite, pk)` |
| Ed25519 | RFC 8032 **Ed25519ph** (`PH = SHA-512`, `phflag = 1`) with context `ctx_composite`: `sign_prehashed(SHA-512(M'), ctx_composite)`; deterministic | `verify_prehashed_strict(SHA-512(M'), ctx_composite, σ)` (rejects small-order `R` and keys, non-canonical `S`) |

- Ed25519ph's `dom2(1, ctx)` prefix makes an Ed25519ph signature never a valid
  PureEd25519 signature (RFC 8032 §5.1 domain separation). Ed25519ph contexts
  are limited to 255 bytes (`MAX_ED25519PH_CONTEXT_LEN`); the composite uses 12.
- **Why Ed25519ph, not Ed25519ctx:** `ed25519-dalek` 3.0 exposes no Ed25519ctx
  API (D-17). **Assumption delta:** the Ed25519 half signs `SHA-512(M')`, so a
  SHA-512 collision on two representatives forges *that half*; the ML-DSA half
  signs `M'` unhashed.
- The standalone `Ed25519` adapter (`SignatureScheme`) remains PureEd25519 with
  `verify_strict`; it is not used inside the composite.
- The trait `CompositeComponent` states the contract: `context_bound()` is true
  iff both halves pass the context unchanged to a context input; a component
  without a context input returns false, ignores the context, and its half
  then **is** a valid standalone signature. All adapters of the named suites
  return true (asserted in `conformance_sizes.rs`). The engine does not
  enforce the flag; it is a declared and tested contract (D-17; RULES 30).

### 7.5 Algorithms

```text
KeyGen(suite):
    sk_first  ← entropy (32 bytes: ξ);            pk_first  ← ML-DSA.KeyGen_internal(ξ).pk
    sk_second ← entropy (Ed25519: 32 bytes; SLH-DSA: 3n bytes, one request)
    pk_second ← Ed25519 public key of sk_second, or SLH-DSA slh_keygen_internal(sk_second).pk
    return pk = pk_first ‖ pk_second,  sk = sk_first ‖ sk_second

Sign(suite, sk, M, ctx):
    require exact len(sk) and len(ctx) ≤ 255
    pk_first, pk_second ← re-derived from sk_first, sk_second
    d   ← pk_digest(suite_id, pk_first, pk_second)
    M'  ← "VYRA-SIG-v1" ‖ [suite_id] ‖ d ‖ [len(ctx)] ‖ ctx ‖ M
    σ1  ← first.sign_half(sk_first, M', ctx_composite)     # draws 32 bytes (rnd)
    σ2  ← second.sign_half(sk_second, M', ctx_composite)   # Ed25519ph: 0 bytes; SLH-DSA: n bytes
    return σ1 ‖ σ2

Verify(suite, pk, M, ctx, σ):
    require exact lengths of pk and σ, len(ctx) ≤ 255          else InvalidLength
    M'  ← as above, from the given pk
    ok0 ← ValidatePublicKey(suite, pk)                       # §7.6
    ok1 ← first.verify_half(pk_first, M', ctx_composite, σ1)
    ok2 ← second.verify_half(pk_second, M', ctx_composite, σ2)
    # all three always evaluated; non-short-circuiting AND
    return ok0 ∧ ok1 ∧ ok2 ? Ok : VerificationFailed
```

Entropy per operation (asserted by `crates/vyra-sig/tests/entropy_sweep.rs`):

| Suite | KeyGen | Sign | Verify |
|-------|--------|------|--------|
| VYRA-SIG-2 / 3 / 5 | 64 (32 + 32) | 32 (ML-DSA `rnd`; Ed25519ph deterministic) | 0 |
| VYRA-SIG-PQ1 | 80 (32 + 48) | 48 (32 + 16) | 0 |
| VYRA-SIG-PQ3 | 104 (32 + 72) | 56 (32 + 24) | 0 |
| VYRA-SIG-PQ5 | 128 (32 + 96) | 64 (32 + 32) | 0 |

- A failure of any check is reported as `VerificationFailed` without saying
  which part failed.
- The raw `sign_raw` takes raw key bytes without a suite. Within the transition
  family secret keys are 64 bytes in every suite, so a raw key used under
  another transition suite derives an unrelated ML-DSA key and the **same**
  Ed25519 key (§5.1); the typed `sign` checks the key's suite, and wire keys
  carry the suite-bound check value (§5.2).
- Each SLH-DSA "s" signature takes on the order of seconds (measured in
  `results/benchmarks.md`); verification takes milliseconds.

### 7.6 Public-key validation

`ValidatePublicKey(suite, pk)` (`vyra_sig::validate_public_key`) runs at parse
time (`CompositePublicKey::from_raw` / `from_bytes`) and again inside every
verification (failure there is reported as `VerificationFailed`). It checks:

1. `len(pk)` equals the suite's public-key length;
2. **ML-DSA part: length only.** FIPS 204 `pkEncode` is `ρ (32 bytes) ‖ t1`
   with 10 bits per `t1` coefficient; every byte string of the right length is
   a valid, canonical public key;
3. **SLH-DSA part: length only.** A FIPS 205 public key is two n-byte strings
   `PK.seed ‖ PK.root` with no further structure, so every 2n-byte string is
   a valid public key and its own unique encoding. Evidence: decode/encode
   identity tested in both `fips205` and `slh-dsa` on random strings and the
   all-0 / all-1 patterns (`slhdsa.rs` module docs and tests);
4. **Ed25519 part:** (a) decompresses to a curve point; (b) is the canonical
   encoding of that point (re-compressing gives exactly the input bytes; RFC
   8032 §5.1.3 requires `y < p` and no sign bit when `x = 0`); (c) is not of
   small order (rejects the identity and the other 8-torsion points); (d) is
   torsion-free, i.e. in the prime-order subgroup (`[ℓ]A = O`), checked with
   curve25519-dalek's `is_torsion_free`. Failures:
   `InvalidEncoding("Ed25519 public key")`,
   `InvalidEncoding("Ed25519 public key (non-canonical)")`,
   `InvalidEncoding("Ed25519 public key (small order)")`,
   `InvalidEncoding("Ed25519 public key (not in prime-order subgroup)")`.
   The standalone `Ed25519` adapter applies the same validation in `verify`.

Check (b) is needed because `ed25519-dalek` 3.0 `VerifyingKey::from_bytes`
reduces `y` modulo `p` and accepts the sign-bit-set encoding of `x = 0` points;
check (d) because `verify_strict` and `is_weak` reject only small-order points.

### 7.7 Cross-suite length coincidence

Every pair of signature suites was checked for equal object lengths (RULES 31).
One coincidence exists: **VYRA-SIG-2 and VYRA-SIG-PQ1 public keys are both 1344
bytes raw** (1312 + 32 in both). A VYRA-SIG-2 public key whose header is
relabelled to 0x11 therefore parses (an ML-DSA-44 key followed by 32 bytes,
which are a valid SLH-DSA-SHAKE-128s public key). This **fails closed**: the
suite id is in `M'`, in the composite context and in the public-key digest,
and the signature lengths differ (2484 versus 10276 bytes), so no signature
verifies under the relabelled key (D-17). Signatures have six distinct
lengths, and no other public-key lengths coincide. Raw secret keys are 64
bytes in all three transition suites (within one family, by construction);
there the wire form's suite-bound check value (§5.2) separates them.

### 7.8 Custom assemblies (crypto-agility entry points)

`CustomComposite::from_components` (signatures) and
`CustomHybridKem::from_components` (KEM) run the **same** composition code as
the named suites over caller-supplied components and a caller-chosen
descriptor. They have no wire format, no typed key objects and no check value,
and VYRA makes no security statement about them.

- Signatures: a descriptor id assigned to a named suite is rejected
  (`InvalidEncoding("custom suite id is assigned to a named suite")`), so a
  custom assembly never produces a representative claiming a named suite.
- KEM: `CustomSuite::combiner_id` is hashed where a named suite's id is; a named
  suite's id is **not** rejected (reusing it with that suite's own components
  reproduces the suite byte for byte, which is tested).
- The failure-injection experiment (`docs/SECURITY.md` §Failure-injection
  evidence) runs through these entry points.

### 7.9 Non-interoperability with the IETF composite format

VYRA-SIG is **not** the IETF LAMPS composite ML-DSA format (RFC 10073,
formerly draft-ietf-lamps-pq-composite-sigs) and does not interoperate with it.
Differences include: a different prefix and label scheme; VYRA binds a digest of
the composite public key into `M'`; VYRA does not pre-hash `M` (its Ed25519
half prehashes `M'` with SHA-512 as Ed25519ph); different context strings;
different key and signature encodings (no ASN.1/X.509 structures); different
identifiers; and VYRA has ML-DSA + SLH-DSA suites.

## 8. Sealed box (VYRA-SEAL)

Sources: `crates/vyra-seal/src/{sealed_box,kdf,aead}.rs`.

A sealed box encrypts one message to one recipient public key, KEM-DEM style.
It uses the KEM suites and suite ids of §6.1.

### 8.1 Sealing and opening

```text
Seal(suite, pk, aad, pt):
    require pk.suite = suite and len(pt) ≤ MAX_PLAINTEXT_LEN
    (kem_ct_raw, K) ← VYRA-KEM.Encaps(suite, pk)               # fresh, §6.5
    key ‖ nonce ← KDF(suite_id, K, kem_ct_raw)                 # §8.2
    aad' ← "VYRA-SEAL-v1" ‖ [suite_id] ‖ aad                   # §8.3
    (c, tag) ← ChaCha20-Poly1305.Encrypt(key, nonce, aad', pt) # RFC 8439
    return header(SealedBox=7, suite_id) ‖ kem_ct_raw ‖ c ‖ tag

Open(suite, sk, aad, sealed):
    parse header (type 7); suite id known; equal to the instance's suite and sk.suite
    kem_ct_raw ← next ct_len(suite) bytes                       else InvalidLength
    body ← rest; require len(body) ≥ 16                         else InvalidLength
    c ‖ tag ← body  (tag = last 16 bytes)
    K ← VYRA-KEM.Decaps(suite, sk, kem_ct_raw)                  # implicit rejection
    key ‖ nonce ← KDF(suite_id, K, kem_ct_raw)
    pt ← ChaCha20-Poly1305.Decrypt(key, nonce, aad', c, tag)    else DecryptionFailed
    return pt
```

- The tag is verified before any plaintext is released; any authentication
  failure (modified KEM ciphertext, body, tag or `aad`, wrong recipient key)
  returns `DecryptionFailed` with no further detail.
- `aad` is not transmitted; the recipient supplies it.
- Entropy: Seal draws exactly what the KEM encapsulation draws (64 / 72 / 80
  bytes for suites 1 / 3 / 5). Open draws none.

### 8.2 Key and nonce derivation

```text
key (32) ‖ nonce (12) = SHAKE256( 0x01 ‖ frame("VYRA-SEAL-v1") ‖ frame([suite_id])
                                  ‖ frame(K) ‖ frame(kem_ct_raw) )[0..44]
```

i.e. `Transcript("VYRA-SEAL-v1"; [suite_id], K, kem_ct_raw).finalize_xof(44)`,
where `kem_ct_raw = ct1 ‖ ct2` without wire header. The nonce is derived, never
transmitted, and never random. Each seal performs a fresh encapsulation, so
each derived (key, nonce) pair is intended to encrypt exactly one message.

### 8.3 Associated data

```text
aad' = "VYRA-SEAL-v1" (12 bytes) ‖ [suite_id] (1 byte) ‖ aad
```

No length framing is needed: the prefix has fixed length 13, and the AEAD
authenticates `len(aad')`.

### 8.4 Format and limits

```text
sealed = "VYRA" ‖ 0x01 ‖ 0x07 ‖ suite_id ‖ kem_ct_raw ‖ c ‖ tag(16)
len(sealed) = len(pt) + overhead(suite),   overhead = 7 + ct_len(suite) + 16
```

- `MAX_PLAINTEXT_LEN = (2^32 − 1) · 64 − 1 = 274877906879` bytes: the RFC 8439
  limit `2^38 − 64` minus one byte, as enforced by the upstream crate. Longer
  plaintexts are rejected with `InvalidLength`.
- Single-shot; whole message in memory; no streaming.
- Plaintext length is revealed exactly.
- No sender authentication, no forward secrecy with a static recipient key, no
  replay protection (see `docs/THREAT_MODEL.md`).

## 9. Entropy interface

All randomness enters through `vyra_core::EntropySource`. `OsEntropy` reads the
operating-system CSPRNG through the `getrandom` crate. `DeterministicEntropy` is
**test-only**: its stream is
`Transcript("VYRA-DeterministicEntropy-v1"; seed).finalize_xof(·)` read
incrementally, so anyone who knows the seed knows every derived key. It MUST NOT
be used for real keys.

## 10. Size tables

All values in bytes. Wire = 7-byte header + raw, plus a 16-byte check value
for secret keys. Every value is a code constant asserted equal to the length of
a generated object; the same numbers are in `results/sizes.json` /
`results/sizes.md` (written by `cargo xtask sizes`).

### 10.1 VYRA-KEM

| Suite | id | raw pk | raw sk | raw ct | shared secret | wire pk | wire sk | wire ct |
|-------|----|--------|--------|--------|---------------|---------|---------|---------|
| VYRA-KEM-1 | 1 | 3041 | 96 | 5201 | 32 | 3048 | 119 | 5208 |
| VYRA-KEM-3 | 3 | 5698 | 96 | 10066 | 32 | 5705 | 119 | 10073 |
| VYRA-KEM-5 | 5 | 8805 | 96 | 15989 | 32 | 8812 | 119 | 15996 |

Derivation: raw pk = 800 + 2241, 1184 + 4514, 1568 + 7237; raw sk = 64 + 32
in every suite; wire sk = 7 + 96 + 16; raw ct = 768 + 4433, 1088 + 8978,
1568 + 14421.
Sources: `crates/vyra-kem/src/mlkem.rs` and `crates/vyra-kem/src/hqc.rs`
(component constants), `crates/vyra-kem/src/suite.rs` (`public_key_len` …
`encoded_ciphertext_len`); asserted in `crates/vyra-kem/tests/wire.rs`
(`SIZES`, `f6_sizes_match_spec_table`).

### 10.2 VYRA-SIG

| Suite | id | raw pk | raw sk | raw sig | wire pk | wire sk | wire sig |
|-------|----|--------|--------|---------|---------|---------|----------|
| VYRA-SIG-2 | 0x02 | 1344 | 64 | 2484 | 1351 | 87 | 2491 |
| VYRA-SIG-3 | 0x03 | 1984 | 64 | 3373 | 1991 | 87 | 3380 |
| VYRA-SIG-5 | 0x05 | 2624 | 64 | 4691 | 2631 | 87 | 4698 |
| VYRA-SIG-PQ1 | 0x11 | 1344 | 80 | 10276 | 1351 | 103 | 10283 |
| VYRA-SIG-PQ3 | 0x13 | 2000 | 104 | 19533 | 2007 | 127 | 19540 |
| VYRA-SIG-PQ5 | 0x15 | 2656 | 128 | 34419 | 2663 | 151 | 34426 |

Derivation: transition raw pk = 1312 + 32, 1952 + 32, 2592 + 32; raw sk =
32 + 32; raw sig = 2420 + 64, 3309 + 64, 4627 + 64. Dual post-quantum raw pk =
1312 + 32, 1952 + 48, 2592 + 64; raw sk = 32 + 48, 32 + 72, 32 + 96; raw sig =
2420 + 7856, 3309 + 16224, 4627 + 29792. Wire = 7 + raw (+ 16 for secret keys).
Sources: `crates/vyra-sig/src/mldsa.rs`, `crates/vyra-sig/src/ed25519.rs`,
`crates/vyra-sig/src/slhdsa.rs`, `crates/vyra-sig/src/suite.rs`; asserted in
`crates/vyra-sig/tests/conformance_sizes.rs` and written to
`results/sizes.json`.

### 10.3 VYRA-SEAL

| KEM suite | id | overhead = 7 + raw ct + 16 | sealed box length |
|-----------|----|----------------------------|-------------------|
| VYRA-KEM-1 | 1 | 5224 | len(pt) + 5224 |
| VYRA-KEM-3 | 3 | 10089 | len(pt) + 10089 |
| VYRA-KEM-5 | 5 | 16012 | len(pt) + 16012 |

Source: `crates/vyra-seal/src/sealed_box.rs` (`overhead`); asserted in
`crates/vyra-seal/tests/round_trip.rs` (`overhead_per_suite`).

### 10.4 Fixed constants

| Constant | Value |
|----------|-------|
| header length | 7 |
| combined KEM secret `K` | 32 |
| public-key digest | 32 |
| secret-key check value (KEM and SIG) | 16 |
| ML-DSA context string | 12 |
| max signature context | 255 |
| ChaCha20-Poly1305 key / nonce / tag | 32 / 12 / 16 |
| sealed-box KDF output | 44 |
| max sealed-box plaintext | 274877906879 |

## 11. Test vectors

Known-answer vectors for every suite are generated from fixed seeds with
`DeterministicEntropy` by `cargo xtask vectors` into `vectors/` and checked with
`cargo xtask vectors --check` (gate F5 in `docs/CHECKS.md`); files and format
are described in `vectors/README.md` (`kem.json`, `sig.json`, `seal.json`,
`combiner.json`). They are VYRA's own
vectors, produced by this implementation: they detect changes, not errors that
were present when they were generated. Component conformance is checked
separately against official or independent known-answer data (gate F4; see the
`conformance_*` tests).

## 12. Versioning and agility

Any change to the following is a **wire-format change** and MUST bump the wire
version byte (and the affected `-v1` labels):

- any component algorithm, parameter set or upstream version that changes keys,
  ciphertexts, signatures or shared secrets byte-for-byte; in particular
  replacing HQC v5.1 with FIPS 207 HQC if they differ in any byte (D-14);
- the combiner input list, order, encoding or label;
- `M'`, the public-key digest, the ML-DSA context string, or their labels;
- the sealed-box KDF, AAD framing, nonce derivation, AEAD or layout;
- the transcript framing or the XOF domain byte;
- key encodings (e.g. moving from seed-form to expanded secret keys, or
  storing SLH-DSA's `PK.root`) or the secret-key check value (label, length,
  input);
- the component mode of any half (e.g. replacing Ed25519ph by Ed25519ctx, or
  changing the composite context string), since signatures change byte for
  byte;
- header layout, object-type values or the meaning of existing suite ids.

Adding a **new suite id** for a new component pairing, without changing the
meaning of existing ids, does not require a version bump (this is how the dual
post-quantum suites 0x11/0x13/0x15 were added; the U12-R1 change of the
Ed25519 half from PureEd25519 to Ed25519ph changed transition-suite signatures
byte for byte without a version bump; under D-14's definition of v1 as the
format at first publication, that change predates v1). A new suite
MUST be checked against every existing suite for equal object lengths (§7.7); old decoders reject
the new id with `UnknownSuite`. Suite ids are never reused for a different
pairing.

The `Kem`, `ComponentKem` and `SignatureScheme` traits make component
replacement a local code change; agility in VYRA is a code-level property, not a
negotiation mechanism.

## 13. References

See `docs/SECURITY.md` §References for bibliographic entries and their
verification status.
