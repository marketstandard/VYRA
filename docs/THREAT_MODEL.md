# VYRA threat model

This document states what VYRA is meant to protect, against whom, under which
trust assumptions, and what is out of scope. It states **goals**. Whether VYRA
meets them is discussed in `docs/SECURITY.md`; for VYRA's concrete
instantiation no security proof exists and no independent analysis has been
done. The byte-level construction is in `docs/SPEC.md`.

VYRA provides **primitives** (a hybrid KEM, a composite signature, a sealed
box). It is not a protocol. Properties that only a protocol can provide are
listed as out of scope in §6.

## 1. Assets

| Asset | Where it lives | Why it matters |
|-------|----------------|----------------|
| KEM secret keys `sk1 ‖ sk2` (ML-KEM seed `d ‖ z`, HQC seed `seed_kem`) | caller memory, caller storage | decapsulates every ciphertext ever sent to the key pair |
| Signature secret keys (ML-DSA seed ξ; Ed25519 seed or SLH-DSA `SK.seed ‖ SK.prf ‖ PK.seed`) | caller memory, caller storage | forges any signature |
| Hybrid shared secrets `K` | returned to caller | session / DEM key material |
| Sealed-box DEM key and nonce | transient, inside `seal`/`open` | decrypts / forges one sealed box |
| Plaintexts of sealed boxes | caller memory; returned by `open` as zeroizing `SecretBytes` | confidentiality of user data |
| Integrity of signed messages and of sealed-box ciphertexts + AAD | wire | authenticity / integrity |
| Entropy drawn for keygen, encapsulation, ML-DSA hedging | transient | predictable entropy breaks keys and sealed boxes |

Public keys, ciphertexts, signatures, lengths, suite ids, and the success or
failure of public-input parsing are **not** secret.

## 2. Adversary classes

| Class | Capabilities | In scope? |
|-------|--------------|-----------|
| Classical passive | observes all wire objects | yes |
| Classical active, KEM | chooses ciphertexts and obtains decapsulations (IND-CCA2 game) | yes |
| Classical active, signature | obtains composite signatures on chosen messages and contexts (CMA) | yes |
| Standalone signing oracles on component keys (key reuse) | the same component keys are also used outside the composite: the adversary obtains standalone signatures from both component keys in default mode (PureEd25519; empty-context ML-DSA / SLH-DSA), in the context variant with the empty context (Ed25519ph `""`), with a foreign application context, and with another VYRA suite's composite context | **yes** for these four modes: tested by the failure-injection game STRIP-STANDALONE (`docs/SECURITY.md` §Failure-injection evidence). **Not covered:** an oracle that signs under the composite's own context (`"VYRA-SIG-v1" ‖ suite_id`), whose output is by definition a composite half; deployments must not expose that |
| Quantum, offline | large fault-tolerant quantum computer used on recorded traffic and public keys; classical interaction with VYRA users | yes (as a goal; see §5) |
| Harvest-now-decrypt-later | records KEM/sealed-box traffic today, decrypts after a cryptographically relevant quantum computer exists | yes; this is the primary motivation for the hybrid KEM |
| Multi-user / multi-target | attacks many key pairs or many ciphertexts at once, succeeds on any one | yes as a goal; no multi-user tightness analysis exists |
| Quantum-access oracles (superposition queries to VYRA's decapsulation/signing) | — | no; not a meaningful model for this deployment and not analysed |
| Remote / local timing | measures execution time of VYRA operations, possibly co-located (cache timing) | partly: VYRA's own glue code avoids secret-dependent branching and indexing; upstream crates' timing is inherited and **unmeasured** |
| Physical side channels | power, EM, acoustic measurement | **no** |
| Fault injection | glitches, lasers, Rowhammer on the executing device | **no** |
| Compromised endpoint | malware on signer/recipient, memory disclosure, stolen key files | **no** (VYRA cannot defend the machine it runs on) |
| Malicious key owner | crafts its own keys to break binding properties (e.g. two key pairs that agree on a key) | partly: binding is a goal for the KEM combiner via hashing public keys and ciphertexts; not proven |
| Supply-chain adversary | compromises upstream crates or the build | no (trust assumption, §3) |

## 3. Trust assumptions

1. **Randomness.** `OsEntropy` (the operating system CSPRNG via `getrandom`)
   produces unpredictable, non-repeating output. If it fails it reports an
   error; VYRA then fails closed (`EntropyFailure`). A CSPRNG that returns
   predictable or repeated bytes **without** reporting failure cannot be
   detected by VYRA and breaks key generation, encapsulation and sealing (see
   `docs/SECURITY.md` §Randomness). `DeterministicEntropy` is test-only.
2. **Platform.** The CPU, OS, Rust compiler and LLVM execute the code as
   written, do not leak memory across processes, and do not introduce
   secret-dependent timing into code that is written branch-free. Rust/LLVM give
   no constant-time guarantee; this is an assumption, not a property.
   **CPU multiplier:** the default HQC carry-less multiply in `vyra-hqc` is
   constant time only if the CPU's 64×64→128-bit integer multiplication is
   constant time (stated for current x86-64 and AArch64 cores in the crate's
   notes; not guaranteed on all targets). That kernel is compiled only for x86-64
   and AArch64; every other target architecture gets the multiplier-free
   kernel automatically. An x86-64 or AArch64 core with a variable-time
   multiplier would need the `bitserial-mul` feature set by hand; VYRA cannot
   detect that. The workspace is
   tested on Rust 1.88 (the declared `rust-version`), 1.98 and 1.100.
3. **Upstream crates.** `ml-kem` 0.3.4, `ml-dsa` 0.1.2,
   `ed25519-dalek` 3.0.0, `chacha20poly1305` 0.11.0, `sha3` 0.12.0, `shake`
   0.1.0, `subtle`, `zeroize`, `getrandom` implement their specifications
   correctly. VYRA checks component conformance against known-answer data and
   second implementations (gate F4) but has not reviewed their source for
   side channels. The `ml-kem` and `ml-dsa` READMEs state that they have never
   been independently audited. SLH-DSA comes from `fips205` 0.5.0 (all 114
   selected NIST ACVP vectors pass through VYRA's adapter; its README claims
   constant-time key generation and signing, which VYRA has not verified). On 2026-11-18 `cargo audit` reported no known
   advisories for the dependency tree (122 crates checked against a database
   of 1533 advisories); that is a
   point-in-time observation, not a property, and `results/verification-report.md`
   records the latest status.
4. **Hash functions.** SHA3-256 and SHAKE256 behave as required by the
   arguments in `docs/SECURITY.md` (random-oracle-like where the combiner and
   KDF arguments need it; collision resistant where binding needs it).
5. **Key custody.** The caller stores secret keys securely. VYRA provides no
   protection at rest. The 16-byte check value in wire secret keys detects
   relabelling and accidental corruption only; it is not a MAC and gives no
   protection against anyone who can rewrite the key file.
6. **The in-tree HQC port.** HQC v5.1 is implemented by `crates/vyra-hqc`,
   VYRA-maintained code forked from `hqc-kem` 0.1.0-rc.0 (D-14). It is trusted
   to implement the HQC v5.1 specification correctly and without secret-dependent
   timing on the strength of the official v5.1 known-answer vectors, code
   structure and one coarse timing smoke test only: there is no independent
   second v5.1 implementation and no external review. HQC itself is not yet a
   published standard (FIPS 207 pending).
7. **Parameter claims.** The NIST categories quoted for the components are the
   designers' claims (FIPS 203/204/205; the HQC v5.1 specification). VYRA ran
   no estimator.
8. **Tooling is not trusted computing base.** The failure-injection crate
   (`vyra-yield`, intentionally insecure, `publish = false`), the proof crate
   (`vyra-proofs`), the pinned Docker image and Kani/CBMC toolchain
   (`tools/kani/`) and `xtask` produce evidence; they are not part of the
   library a user links, and their failure would weaken the evidence, not the
   library. Their correctness is assumed when reading the evidence (for
   example, that a SUCCESSFUL Kani result is sound within its bound).

## 4. In scope vs. out of scope

**In scope**

- Mathematical attacks on the hybrid KEM, composite signature and sealed box by
  classical and quantum adversaries interacting classically.
- Chosen-ciphertext and chosen-message attacks against the APIs as specified.
- Malformed-input handling: every decoder must reject malformed input with an
  error and must not panic (gates S1, S2, S10).
- Secret-dependent control flow and memory access **in VYRA's own code**.
- Secret hygiene in VYRA's own types: zeroize on drop, redacted `Debug`,
  constant-time equality (gate S9).
- Entropy-failure handling (fail closed, no partial outputs).

**Explicitly out of scope**

- Physical side channels (power, EM, acoustic), fault injection, and any
  leakage-resilience claim (D-04, D-05). VYRA does not implement masking, the
  POLKA countermeasures, or fault redundancy.
- Timing behaviour of the upstream component crates (inherited, unmeasured).
  The in-tree HQC port is VYRA's own code and therefore in scope for timing,
  but has only had a coarse smoke test.
- Compromised endpoints, memory-disclosure bugs outside VYRA, swap/core dumps,
  key theft.
- **Protocol-level properties**: authentication of the peer's identity, binding
  of public keys to identities (PKI), replay protection, ordering, downgrade
  and algorithm-negotiation security, forward secrecy (only achievable by a
  protocol that uses ephemeral keys and erases them; D-03), post-compromise
  security, deniability, key confirmation, cross-protocol separation beyond
  VYRA's own labels.
- Traffic analysis and length hiding (sealed boxes reveal plaintext length).
- Denial of service (large keys and ciphertexts; expensive HQC and key-expansion
  operations).
- Interoperability or compliance (not FIPS-validated; not interoperable with any
  standardised hybrid).

## 5. Security goals per primitive

These are **goals**. "Goal" means: this is what VYRA is designed to achieve
and what an analysis should establish. Evidence for each is in
`docs/SECURITY.md`, which also lists which goals have only a sketch or no
argument at all.

### 5.1 Hybrid KEM (VYRA-KEM-1/3/5)

- **G-KEM-1 (robust IND-CCA2).** VYRA-KEM is IND-CCA2 secure if **at least
  one** of ML-KEM and HQC is IND-CCA2 secure, with SHA3-256 in the combiner
  modelled as a random oracle. Intended to hold against classical adversaries;
  against quantum adversaries it is intended to hold as long as at least one
  component is IND-CCA2 secure against quantum adversaries (the components'
  own claims) and the combiner argument transfers to the QROM (not established
  for VYRA's encoding; see `docs/SECURITY.md`). In the "ML-KEM broken" case
  this goal is meant to cover, everything rests on VYRA's own HQC v5.1 port
  (trust assumption 6).
- **G-KEM-2 (harvest-now-decrypt-later).** Recorded ciphertexts stay
  confidential against a future quantum adversary as long as G-KEM-1 holds
  against quantum adversaries. Requires that the recipient secret key never
  leaks: there is **no** forward secrecy with static keys (D-03).
- **G-KEM-3 (binding).** The derived key `K` is bound to the suite, both
  component ciphertexts and both component public keys (by hashing them).
  Formal binding notions (Cremers–Dax–Medinger style) are **not** proven.
- **G-KEM-4 (no oracle beyond the components').** Decapsulation errors depend
  only on public data; invalid ciphertexts are rejected implicitly.

### 5.2 Composite signatures

**Dual post-quantum suites (VYRA-SIG-PQ1/PQ3/PQ5, ML-DSA + SLH-DSA).**

- **G-SIGPQ-1 (EUF-CMA if either component is).** The composite is intended
  to be EUF-CMA, against classical and quantum adversaries, if ML-DSA **or**
  SLH-DSA is EUF-CMA (module-lattice assumptions or hash-function properties).

**Transition suites (VYRA-SIG-2/3/5, ML-DSA + Ed25519ph).**

- **G-SIGT-1 (EUF-CMA).** Intended EUF-CMA against classical adversaries if
  ML-DSA or Ed25519ph is EUF-CMA (the latter also needs SHA-512 collision
  resistance on representatives, D-17), and against quantum adversaries if
  ML-DSA is. The category label describes ML-DSA only.
- **G-SIGT-2 (quantum).** Against an adversary able to compute Ed25519
  discrete logarithms, unforgeability rests on ML-DSA alone.

**Both families.**

- **G-SIG-SUF (SUF-CMA, weaker intent).** SUF-CMA only if both components are
  SUF-CMA; one malleable component breaks it (documented gap, observed by
  failure injection).
- **G-SIG-SEP (separation and binding).** A composite signature binds the
  suite, a digest of the whole composite public key and the caller's context;
  halves from different key pairs, suites or contexts do not recombine; in
  every named suite **neither half is a valid standalone default-mode
  signature**; standalone signing oracles in the four modes listed in §2 do
  not help to forge a composite.
- **G-SIG-KEY (key validation).** Every accepted composite public key has a
  single canonical encoding; the Ed25519 part is a non-identity element of the
  prime-order subgroup.

### 5.3 Sealed box (VYRA-SEAL)

- **G-SEAL-1 (confidentiality and ciphertext integrity, anonymous sender).**
  IND-CCA2 security of the public-key encryption (equivalently, confidentiality
  plus integrity of ciphertext and AAD with respect to whoever sealed it), if
  VYRA-KEM is IND-CCA2 and ChaCha20-Poly1305 with a single-use key is a secure
  one-time AEAD.
- **Not a goal: sender authentication.** Anyone with the recipient's public key
  can produce a valid sealed box.
- **Not a goal: forward secrecy** with a static recipient key; **not a goal:**
  replay protection or length hiding.

### 5.4 Implementation goals (all primitives)

- Malformed input never panics and never reaches upstream code with a wrong
  length.
- VYRA glue code has no secret-dependent branches or indexing; secrets are
  zeroized on drop on a best-effort basis; secret types have redacted `Debug`
  and no non-constant-time equality.
- Both components always run (KEM decapsulation, signature verification);
  failures are reported uniformly.

## 6. Non-goals

- Leakage resilience, masking, fault resistance (D-04, D-05).
- Security against an adversary who controls the entropy source.
- Protection of keys at rest, key escrow, backup, HSM integration.
- Threshold signing, multi-party decryption, hash-based fallback signatures
  (D-08).
- Any security level stronger than the minimum of the components' claimed
  categories (D-06). For signatures, any post-quantum property of Ed25519;
  any property of custom assemblies (`CustomComposite`, `CustomHybridKem`);
  security when a component key also signs under the composite's own context
  outside the composite.
- High-rate signing with the dual post-quantum suites (SLH-DSA "s" signing
  takes seconds).
- Interpretation of failure-injection or bounded-model-checking results as
  proofs (D-16, D-18).
- Standards compliance, certification, or interoperability.
- Fitness for protecting real data: VYRA is a research prototype (see
  `SECURITY.md` at the repository root).
