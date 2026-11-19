# Executive Summary  
We propose a **hybrid lattice+code** post‑quantum cryptosystem designed for strong security and performance in the quantum era.  Building on established primitives (CRYSTALS‑Kyber and HQC) and novel leakage‑resilient techniques, our scheme integrates multiple independent hardness assumptions (MLWE and quasi‑cyclic syndrome decoding) to achieve **defense‑in‑depth**.  For key exchange, the hybrid KEM encapsulates a shared key with *two* independent KEMs (e.g. Kyber + HQC); the final key is derived by hashing the two outputs (e.g. `K = H(k_Kyber || k_HQC)`).  We adopt Fujisaki–Okamoto transforms on each component for IND‑CCA security and incorporate **randomized decryption and dummy ciphertexts** (as in POLKA) to mitigate side‑channel leakage.  For signatures, we recommend a **composite** or hybrid approach (e.g. lattice-based Dilithium + classical Ed25519) to hedge against algorithmic breakthroughs.  

Our threat model assumes a quantum-capable adversary with full adaptive powers (chosen‑ciphertext, multi‑user, and side‑channel attacks), and requires forward secrecy for session keys.  Security relies on standard hardness (Module‑LWE for Kyber, QCSD for HQC) with reductionist proofs similar to hybrid KEM analyses (e.g. proving IND‑CCA security if at least one component is secure).  We explicitly state assumptions and avoid unproven claims: cryptanalysis is planned as future work.  

The design integrates into common protocols: e.g. using the hybrid KEM inside HPKE/TLS/SSH, and hybrid or composite signatures for certificates. Pseudocode outlines `KeyGen/Encaps/Decaps` for the hybrid KEM and corresponding DEM.  We compare key/cipher sizes and performance against NIST standards – e.g. Kyber-768 vs HQC-192 vs the combined hybrid – and discuss trade-offs (large keys vs computation).  Implementation must use constant-time arithmetic (NTT for Kyber, masking for HQC) and include side‑channel countermeasures (dummy operations, masking).  Attack surfaces include known quantum algorithms (Grover, sieving BKZ), classical cryptanalysis (ISD for codes, lattice reductions), and physical attacks (fault injection, as NIST schemes have shown vulnerabilities).  

We propose three parameter sets for ~128/192/256-bit quantum security: (Kyber512 + HQC128), (Kyber768 + HQC192), (Kyber1024 + HQC256).  For each we tabulate public-key, ciphertext, and signature sizes (see **Table 1**).  The roadmap includes prototype implementation, test vectors, benchmarks, and security evaluation over the next 12–18 months (illustrated in the Gantt timeline).  Comparative tables show our hybrid’s security assumptions, sizes, and expected performance versus standardized PQC algorithms (e.g. NIST Kyber, HQC, Dilithium, Falcon).  

By combining **diverse hard problems** (lattices & codes), adding **leakage resilience**, and embracing **crypto‑agility** (hybrid/composite design), our approach aims to withstand both known and future attacks.  This report details the design, provides formal sketches, and outlines an implementation and validation plan, citing primary sources at each step.  

## Threat Model and Security Goals  
- **Adversaries:** We assume both classical and fully quantum-capable attackers.  They can mount **adaptive chosen-ciphertext attacks (IND-CCA)** on encryptions and **chosen-message attacks** on signatures.  Side-channel adversaries are allowed physical leakage (power/timing) and fault injections.  Multi-user settings (multiple keypairs) and concurrency are considered.  

- **Goals:** For key exchange/KEM, achieve **IND-CCA security** and *forward secrecy* (fresh ephemeral keys per session).  For signatures, achieve **EU-CMA** security.  Protect keys against leakage and ensure robustness to implementation flaws.  We **do not claim unconditional security**; rather we reduce to hard assumptions.  

- **Assumptions:** The security of the hybrid KEM rests on:  (i) the hardness of Module-LWE (used by Kyber) and (ii) the hardness of QCSD (used by HQC).  If *either* assumption holds, the key remains secret.  This mirrors GhostLock’s analysis: confidentiality holds “as long as at least one KEM remains secure”.  Similarly, the hybrid signature scheme relies on the assumption that at least one underlying signing algorithm is unbroken (e.g. Dilithium’s lattice SIS/LWE vs. hash-based security).  

- **Countermeasures:** To counter FO‑related leakage, we use the **rigidity** and **dummy ciphertext** techniques of POLKA: encryption and decryption are randomized and verified explicitly, preventing side-channel exploitation of re-encryption tests.  We also plan masking of key operations (NTTs, polynomial multiplications) with linear overhead.  For fault attacks (e.g. seed-pointer corruption), we ensure redundant RNG and consistency checks.  

## Primitive Components  
Our design uses established post-quantum primitives as **building blocks**, clearly separating them from novel composition:  

- **Lattice KEM (Kyber):** We use the NIST‐standard ML-KEM (Kyber) parameterized at Levels 1/3/5.  Kyber is based on the Module‐LWE assumption and is IND-CCA via its FO transform.  Example sizes: Kyber-512 (L1) has 800 B PK, 768 B CT; Kyber-768 (L3) has 1184 B PK, 1088 B CT.  

- **Code KEM (HQC):** We incorporate the NIST-selected HQC backup KEM (based on quasi-cyclic code syndrome decoding).  HQC-128 (L1) has PK≈2241 B, CT≈4433 B; HQC-192 (L3): PK≈4514 B, CT≈8978 B; HQC-256 (L5): PK≈7237 B, CT≈14421 B.  (NIST noted HQC is much larger than ML-KEM, trading size for mathematical diversity).  

- **Hash KDF/Commitment:** We use a wide-output KDF (e.g. SHA-3/Shake512) to merge keys: **K** = H(“Domain||k_Kyber||k_HQC”).  This provides domain separation and resilience to Grover’s algorithm (appropriate output length for targeted security).  We also use hash-based **commitments** where needed (e.g. committing to random coins), following standard techniques to eliminate dependencies across operations.  

- **Signature Schemes:** For authentication, we recommend lattice signatures (Dilithium) and optional hash-based fallback (SPHINCS+) or composite with Ed25519.  For example, an SSH or certificate scheme could use **Dilithium + Ed25519** (as in SSH drafts): signing messages with both a PQ signature and a classical signature gives “security against both quantum and classical adversaries”.  This is a known *built-in hybrid* approach, and we adopt it as a building block (the novelty is in how we select and compose such primitives, not in inventing a new signature algorithm).  

- **Known vs Novel:** Our novelty lies not in the basic primitives (we use Kyber, HQC, Dilithium, etc., all well-studied) but in their **composition and enhancements**: a dual-KEM hybrid, integrated side-channel defenses (dummy ciphertexts), and a protocol design that explicitly supports crypto-agility and multi-party variants (see below).  

## Hybrid KEM Construction and Parameters  
We define a **hybrid KEM** `HybridKEM` with operations:

```text
KeyGen():
    (pk1, sk1) ← Kyber.KeyGen()
    (pk2, sk2) ← HQC.KeyGen()
    pk = (pk1, pk2)
    sk = (sk1, sk2)
    return (pk, sk)

Encaps(pk):
    parse pk as (pk1, pk2)
    (c1, k1) ← Kyber.Encap(pk1)
    (c2, k2) ← HQC.Encap(pk2)
    K ← KDF(concat(k1, k2))
    c = (c1, c2)
    return (c, K)

Decaps(sk, c):
    parse sk as (sk1, sk2) and c as (c1, c2)
    k1' ← Kyber.Decap(sk1, c1)    // returns ⊥ on invalid
    k2' ← HQC.Decap(sk2, c2)
    if either k1' or k2' is ⊥, return error
    K ← KDF(concat(k1', k2'))
    return K
```

- **Parameters:** We propose *three* security levels: (Kyber-512 + HQC-128) targeting ~AES128-classical (~2^128 quantum), (Kyber-768 + HQC-192) (~2^192), and (Kyber-1024 + HQC-256) (~2^256).  Key/ciphertext sizes are roughly additive: e.g. Level1 PK ≈800+2241=3041 B, CT≈768+4433=5201 B.  Table 1 (below) summarizes these and comparisons.  

- **IND-CCA Security:** By applying FO to each component, each KEM is IND-CCA on its own (as in Kyber and HQC proposals).  A folklore hybrid argument shows the combined KEM is IND-CCA if *at least one* sub‑KEM is IND-CCA.  In particular, an adversary that distinguishes the hybrid KEM can be reduced to distinguishing either the Kyber KEM or the HQC KEM, depending on which branch yields a difference.  (This reduction can be formalized in the Random Oracle Model with standard techniques.)  Since Kyber and HQC FO‑transformed KEMs are assumed secure, so is the hybrid.  

- **Forward Secrecy:** Because each session uses fresh ephemeral encapsulations (`Encap`), the shared key `K` is one-time and never reused.  Compromise of long-term secret keys `(sk1,sk2)` does not reveal past session keys.  The FO transform ensures that invalid ciphertexts are rejected, so an adversary who learns the hybrid secret key cannot “backdate” messages without detection (contrast classical ECDSA vulnerabilities).  

- **Side-Channel Countermeasures:** We adopt the **POLKA** design principles.  During Decaps, we first **add a dummy ciphertext** (randomly chosen) so that the decryption of the real ciphertext is not directly controlled by the adversary.  Then we perform **key-homomorphic** and masking-friendly operations (e.g. NTTs can be masked linear operations).  We also use *rigidity*: internal encryption/decryption maps (given deterministic coins) are injective, eliminating the need for an explicit re-encryption check during FO.  (Rigid KEMs like Kyber’s inner LWE function can support this with parameter tweaks.)  These tweaks avoid the well-known FO side-channel leak, where an attacker submits many chosen ciphertexts to learn bits of the secret.  In summary, **all private-key operations can be masked** with moderate overhead.  

## Formal Security and Proof Sketch  
We articulate security goals and underlying assumptions:  

- **Assumptions:**  
  - *MLWE Assumption:* Kyber’s security relies on hardness of Module-LWE.  
  - *QCSD Assumption:* HQC relies on the quasi-cyclic syndrome decoding problem.  
  - *Random Oracle:* We model the hash/KDF as a random oracle for IND-CCA proofs.  

- **Proof Strategy:** A typical reductionist proof proceeds as follows: Assume an attacker $\mathcal{A}$ breaks HybridKEM with non-negligible advantage.  We construct a simulator that, given access to either a Kyber-challenge or an HQC-challenge, uses $\mathcal{A}$ to distinguish or invert one of the underlying KEMs.  Concretely:  
  1. Flip a coin. If heads, embed a challenge ciphertext for Kyber in place of $\mathcal{A}$’s first encapsulation; else use challenge for HQC.  
  2. Run $\mathcal{A}$ on the hybrid public key (with real public key for the other component).  During $\mathcal{A}$’s queries, properly answer encapsulations and decapsulations using the real scheme or simulated outputs.  
  3. When $\mathcal{A}$ outputs a guess bit for the hybrid IND-CCA game, translate it to a guess on the underlying KEM challenge.  
  A detailed game-based proof can follow the template of hybrid encryption proofs (Shoup/RO model), showing that if $\mathcal{A}$ distinguishes the hybrid key, then it must succeed against at least one KEM sub-component.  Because both Kyber-FO and HQC-FO are IND-CCA secure by construction, the hybrid is too.  

- **Proof Goals:** Show that (i) the hybrid KEM yields indistinguishable (to $\mathcal{A}$) keys under IND-CPA, and (ii) post-FO and KDF, the scheme is IND-CCA.  The explicit rejection in FO (decaps returns ⊥ on invalid c) simplifies simulation.  In the QROM, one must handle hash queries for re-encryptions, but standard techniques (lazy sampling, explicit rejection) apply.  An information-theoretic argument also shows any *explicit attack* must break at least one component’s assumption.  

- **Forward Secrecy and Multi‑User:** If used in a protocol, each session’s keys are ephemeral (derived as above), so long-term compromise only endangers future sessions unless combined with key reuse.  In a multi-user setting, keys $(sk1,sk2)$ are independent per user.  Colliding sessions or interleaving does not weaken security as each session KEM is separate.  (Of course, care is needed to avoid cross-protocol attacks or key reuse, as in any hybrid scheme.)  

**Table 1** (below) summarizes security parameters and sizes for the hybrid schemes compared to individual components and classical baselines.  Our proofs aim at standard notions: IND-CCA2 for KEM, EU-CMA for signatures.  We intentionally *do not claim* security beyond reductions – active cryptanalysis and public review are needed.  

## Protocol Integration and Pseudocode  
Our hybrid KEM slots into common protocols with minimal changes.  We describe TLS/SSH key exchange and hybrid certificate usage:  

```mermaid
sequenceDiagram
    participant Server
    participant Client
    Server->>Client: send (Kyber_pk, HQC_pk)       %% Server’s long-term PQ public keys
    Note over Server,Client: Each key set at agreed parameter level
    Client->>Client: (k1,k2) = (r1,r2) from random
    Client->>Client: (c1, _) = Kyber.Encap(pk1; r1)  %% Encapsulate with random coins
    Client->>Client: (c2, _) = HQC.Encap(pk2; r2)
    Client->>Server: send (c1, c2)               %% Encrypted handshake
    Server->>Server: k1' = Kyber.Decap(sk1, c1)
    Server->>Server: k2' = HQC.Decap(sk2, c2)
    Note right of Server: K = KDF(k1' || k2')
    Client->>Client: K = KDF(k1 || k2)
    Note right of Client,Server: Shared secret K used for AEAD
```

After the handshake, `K` is used as a symmetric key (via an AEAD DEM) for data encryption.  For signatures and authentication: either party signs transcripts with **composite signatures** (e.g. Dilithium+Ed25519) to ensure integrity and quantum resistance.  

In **API form**, core algorithms would be:  
- `HybridKEM.KeyGen() → (pk, sk)`  
- `HybridKEM.Encaps(pk) → (c, K)`  
- `HybridKEM.Decaps(sk, c) → K ∥ error`  

Similarly, a hybrid signature scheme could be defined as:  
- `HybridSIG.KeyGen()`: generates `(sk1, sk2)` (e.g. Dilithium and Ed25519 keys).  
- `HybridSIG.Sign(sk, m)`: returns `(sig1, sig2)`.  
- `HybridSIG.Verify(pk, m, sig)`: checks both components.  

For **TLS or SSH integration**, the hybrid KEM corresponds to combining two groups.  For example, in HPKE one could register the hybrid KEM with code similar to [16], or in SSH add a new Key Exchange method (like GhostLock’s “.glock” container) that always uses two encapsulations.  Our design maintains the usual protocol flow, just doubling the public-key and ciphertext fields.  In TLS 1.3, one might use two KeyShare entries or define a new KEM group combining both (some draft proposals already allow hybrid groups).  

## Performance and Trade-offs  
We compare key sizes and computation costs: combining two KEMs increases wire size and CPU usage, but gains security diversity.  **Key/Ciphertext sizes:** We cite official specs and compute hybrids:  

| Scheme                     | NIST Level | Public Key (bytes) | Ciphertext (bytes) | Security Assumptions         |
|----------------------------|------------|--------------------|--------------------|------------------------------|
| X25519 (classical)         | –          | 32                 | 32                 | Elliptic-Curve Discrete Log  |
| **ML-KEM-512 (Kyber)**     | 1 (AES-128)   | 800                | 768                | Module-LWE       |
| **HQC-128**                | 1          | 2241               | 4433               | Quasi-Cyclic Syndrome Decoding |
| **Hybrid (Kyber512+HQC128)** | 1          | ~3041 (800+2241)   | ~5201 (768+4433)   | M-LWE + QCSD                |
| ML-KEM-768 (Kyber)         | 3 (AES-192)   | 1184               | 1088               | MLWE                          |
| HQC-192                    | 3          | 4514               | 8978               | QCSD                          |
| Hybrid (Kyber768+HQC192)     | 3          | ~5698              | ~10066             | M-LWE + QCSD                |
| ML-KEM-1024 (Kyber)        | 5 (AES-256)   | 1568               | 1568               | MLWE                          |
| HQC-256                    | 5          | 7237               | 14421              | QCSD                          |
| Hybrid (Kyber1024+HQC256)    | 5          | ~8805              | ~15989             | M-LWE + QCSD                |

_**Table 1:** Key/ciphertext sizes for classical and PQC schemes.  Hybrid values are sums of components (Kyber + HQC).  The “wire cost” (pk+ct) dominates bandwidth.  The hybrid roughly adds both sizes, e.g. 5201 B vs 800 B for level-1, reflecting a ~7× size inflation over Kyber alone._

**Computation:** On a modern CPU (e.g. 3.0 GHz x86), Kyber operations complete in a few hundred microseconds, while HQC (with large codes) is slower (tens to hundreds of microseconds).  Thus hybrid encapsulation/decapsulation may be ~2× slower than one component alone.  However, hybridization is parallelizable (run Kyber and HQC in parallel threads).  Both use fast arithmetic: Kyber relies on NTT and small polynomial multiplication (constant-time NTT implementations exist), HQC uses syndrome decoding (bit operations on vectors) which we implement in constant-time as well.  Memory use is increased (e.g. storing both key materials), but remains in the order of tens of kilobytes for our parameters.  

**Latency:** For real-time protocols (TLS/SSH), the extra time is modest.  Table 2 (below) sketches expected CPU cycles (from implementations) and relative speed.  Precise benchmarking is planned; preliminary data from the literature suggests combined KEM keygen/encaps ≈1–3 ms at L3 (Kyber768 + HQC192) on typical CPUs.  

**Comparison to NIST Standards:** Our hybrid sacrifices some efficiency for security margin.  For example, Kyber768 alone has 1184 B PK and 1088 B CT (224472 cycles total), while Hybrid(Kyber768+HQC192) is ≈5698 B + 10066 B (total ~15764 B) – about 7× larger.  We highlight these trade-offs in **Table 3** (simplified comparison) and charts.  Crucially, the hybrid remains competitive with other PQC: e.g. compared to SPHINCS+ (7–30 KB signatures) or Classic McEliece (1–2 KB keys), the hybrid’s keys are moderate.  

## Implementation Considerations  
- **Constant-time:** All arithmetic (e.g. Kyber NTT, HQC syndrome checks) must be implemented in constant-time (no secret-dependent branches).  Existing PQC libraries (liboqs, PQClean) provide constant-time building blocks we can reuse.  
- **Side-channel mitigations:** In addition to dummy ciphertexts, we mask inner loops.  For Kyber’s NTT-based ops, vector Boolean masking is straightforward.  HQC’s operations (bit shifts/XORs) can be masked by bitwise secret-sharing.  We will integrate state-of-art countermeasures (masking layers, WOPR randomness) similar to POLKA’s suggestions.  
- **Fault resistance:** Recent work shows PQC implementations can be broken by fault injection.  To mitigate, we will implement simple redundancy checks (e.g. verify final KDF output consistency, dual RNG reseeding, signature of ephemeral coins) and consider “self-healing” graphs for encryption state.  For example, deferring use of randomness until after key operations and checking invariants can thwart single-fault attacks.  
- **Cryptographic agility:** The scheme is designed to easily swap components.  A deployment can disable one KEM or switch in a new one (e.g. replace HQC with another code scheme) without altering the overall protocol.  This supports future migration.  

## Attack Surfaces and Cryptanalysis  
We must explicitly address known attacks:  

- **Quantum Attacks:** No known polynomial-time quantum algorithm breaks lattice or code problems.  The best known attacks are exponential (e.g. sieving BKZ for LWE, information-set decoding for codes).  Quantum computers accelerate Grover search on hashes (effectively halving security bits) and can speed up sieving by a constant.  We counter by choosing parameter sizes with a security margin (e.g. Kyber768 for “192-bit” security).  Hybrid’s security is essentially the minimum of its components: if one is broken, the other still stands.  The combination also complicates a quantum attacker who must invest effort in two realms simultaneously.  

- **Classical Cryptanalysis:** For lattices, BKZ-based lattice reduction with discrete Gaussian sampling remains the state-of-art; our Kyber parameters are set to be safe against foreseeable improvements (see NIST IR 8413 analysis).  For codes, Information-Set Decoding (ISD) attacks are the main threat; HQC’s QCSD assumption adds structure but is believed hard (NP-hard syndrome decoding).  Notably, HQC’s parameter sets were chosen to resist known ISD variants.  We stay conservative: for example, HQC-256 targets AES-256 level.  

- **Side-Channel and Fault:** As discussed, we adopt countermeasures (masking, dummy operations).  Still, we acknowledge that many PQC schemes have only recently been shown vulnerable in hardware.  Our threat model includes a physically present adversary.  We will rigorously test against Differential Power Analysis (DPA) and laser fault injection, drawing on methods from recent literature (e.g. [40], [39]).

- **Other Vectors:** Implementation bugs (e.g. RNG failures, memory issues) can undermine security.  We plan audited library use (e.g. PQClean implementations) and fuzz testing.  Transition attacks (downgrade, backdating) are mitigated by design (hybrid up-front, consistent algorithm negotiation).  

We explicitly note that **we do not rely on unverified heuristics**.  All security claims are backed by either proofs or citation of analyses.  Future cryptanalysis (by us or the community) will be needed to validate or adjust parameters.  

## Prototype and Validation Roadmap  
We outline a tentative timeline (months in 2026):  

```mermaid
gantt
    title Development Roadmap
    dateFormat YYYY-MM-DD
    section Design
    Hybrid Scheme Specification      :done,    des1, 2026-01-01, 4w
    Security Proof Sketches         :active,  des2, 2026-02-01, 6w
    section Implementation
    Software Prototype (C/Python)   :         impl1, after des2, 8w
    Side-Channel Countermeasures    :         impl2, after impl1, 6w
    Testing & Test Vectors          :         impl3, after impl2, 4w
    section Evaluation
    Benchmarking (Timing/Size)      :         eval1, after impl3, 6w
    Cryptanalysis (Prelim. Review)  :         eval2, overlaps eval1, 8w
    section Deployment
    Documentation & Release         :crit,    rel,   after eval2, 4w
```

**Milestones:** Specification (design, proofs) by ~Mar ’26; Prototype library by Aug ’26; Benchmarks and analysis by year-end 2026; Refined parameters & release by mid-2027.  We will produce test vectors for each parameter set, integrate with liboqs for community testing, and submit to PQC forums.  

**Comparative Evaluation:** We will benchmark on representative hardware (e.g. x86, ARM).  For example, preliminary data suggests Kyber-768 keygen/encaps/decaps in ~0.3ms/~0.1ms/~0.15ms; HQC-192 in ~0.2ms/~0.4ms/~0.8ms.  Combined, an L3 hybrid decapsulation may be ~1ms.  We will produce charts of throughput and latency vs. NIST KEMs.  Similarly, hybrid signatures (e.g. Dilithium-3 + Ed25519) have signature sizes ~ML-DSA-65 (3KB) + 64B, and signing ~2–3ms; Falcon-512 is ~600B/~1ms.  A detailed performance table (like Table 3) will compare these.  

## Comparison with NIST PQC Standards  
We summarize key attributes in **Table 2**.  For brevity, we compare core metrics at Level3 (AES-192), noting that analogous comparisons hold at L1/L5.  

| Scheme                | Public Key | Ciphertext | Signature | Security Level | Assumptions              | Notes                    |
|-----------------------|-----------:|-----------:|----------:|----------------|--------------------------|--------------------------|
| **CRYSTALS-Kyber-768** | 1184 B     | 1088 B     | –         | L3 (AES-192)   | Module-LWE  | NIST standard KEM       |
| **Classic McEliece**  | ~130 KB    | ~128 KB    | –         | L1 (~AES-128)  | Binary Goppa codes       | Extremely large keys    |
| **HQC-192**           | 4514 B     | 8978 B     | –         | L3             | QCSD        | NIST backup KEM        |
| **Kyber-768+HQC-192** | ~5698 B    | ~10066 B   | –         | L3             | M-LWE + QCSD             | **Hybrid (our)**       |
| **Dilithium-65**      | 1952 B     | –          | 3309 B    | L3             | Module-LWE               | NIST PQC signature     |
| **SPHINCS+-192s**     |  856 B     | –          | 10816 B   | L3             | Hash-based (Merkle)      | Stateless hash sig (large) |
| **Falcon-512**        | 897 B      | –          | 666 B     | L3             | NTRU lattices (floating) | Smaller sig, complex   |
| **Dilithium65+Ed25519** | ~1984 B  | –          | ~3373 B    | L3             | (LWE + ECC)              | Composite signature    |
| **Proposed Hybrid SIG** | ~1984 B  | –          | (Dilithium+SPHINCS) | L3    | MLWE + hash security     | (for extreme cases)    |

*Table 2: Comparison at NIST Level 3 (AES-192 equiv).  “Ciphertext” refers to KEM ciphertext; “Signature” to message signature size.  Our hybrid KEM (Kyber+HQC) has larger PK/CT than any single scheme but combines assumptions.  Composite signatures (Dilithium+Ed25519) double as hybrid mechanisms.*  

From these comparisons:  
- **Sizes:** Hybrid keys are larger but still much smaller than McEliece.  They are on par with largest lattice-based KEM (ML-KEM-1024 at 3.1 KB PK, 1.6 KB CT) and far smaller than SIKE or Classic McEliece.  Signature sizes are similar to Dilithium or Falcon.  
- **Performance:** Hybrid KEM incurs ~2× the workload of Kyber alone, but is competitive with other proposals.  The main downside is bandwidth overhead.  These trade-offs must be weighed in contexts where ciphertext size matters (e.g. IoT vs. archival storage).  
- **Assumptions:** Only our hybrid uses *both* lattice and code assumptions, giving “two lines of defense”.  This is an advantage over single-assumption schemes.  Composite signatures similarly hedge assumption risk.  

Overall, the hybrid scheme offers *crypto‑agility*: one can switch to trusting either assumption without changing interface.  Compared to NIST’s recommended (Kyber/Dilithium/others), our approach is more conservative (bigger but more diverse).  We view it as an **option for high-security deployments** or as a migration strategy.

## Novel Contributions vs Established Techniques  
- **Established:** We build on NIST-finalist algorithms (Kyber, HQC, Dilithium) and known frameworks (Fujisaki–Okamoto, KEM/DEM, hybrid signatures).  The use of dual KEMs, random oracle hashing, and composition with symmetric AEAD follows published practice.  

- **Novel:** Our key innovation is the *design of the hybrid architecture with integrated leakage resilience and explicit threat modeling*.  Specifically:  
  - **Dual-domain KEM:** While hybrid KEMs (classical+PQ) exist (GhostLock), using **two PQ KEMs** together for double coverage is less explored. We systematically analyze such a composite scheme.  
  - **Side-channel design:** We incorporate POLKA-inspired ideas (rigidity, dummy ciphertext) into the architecture, explicitly designing KDF and FO steps to be leak-resistant.  This level of side-channel awareness is a novel design criterion in PQC scheme creation.  
  - **Crypto-agility and threshold:** We outline how our scheme can be easily extended (e.g. drop-in code for multi-party decryption or threshold signing using lattice secret-sharing).  The emphasis on agility (supporting multiple schemes and levels concurrently) is part of our design philosophy.  
  - **Leakage-resilient commitments:** (Tentative) We suggest using small hash commitments to randomness within the encryption/decryption process to decorrelate internal states (inspired by vector commitment research).  A fully-fledged construction is left for follow-up work.  

Our **claims** are conservative: we show how to **reduce** breakage to underlying problems, but we do not **prove** impossibility of attacks (an impossibility proof is out of reach).  Instead, we plan thorough cryptanalysis of the composite (e.g. does combining two KEMs open novel attacks? – likely not beyond attacking each individually).  No security statement (like “unbreakable”) is made without mathematical backing.  

## Conclusions  
We have outlined a rigorous framework for designing a post-quantum cryptosystem that goes beyond standard single-algorithm approaches.  By **combining lattice and code-based KEMs**, applying **hash-based KDFs**, and enforcing **leakage-resistant implementation**, we aim for robust security under a strong threat model.  The report details each component, cites authoritative sources for all known performance and security data, and clearly labels which ideas are new versus which follow from standards.  

Our roadmap includes building reference implementations, generating test vectors, measuring performance, and subjecting the scheme to cryptanalysis (both classical and quantum, as well as side-channel testing).  We will periodically update parameter choices based on emerging attacks (e.g. adjusting NTT modulus if BKZ advances, or key sizes if ISD algorithms improve).  

In summary, this hybrid design offers **security diversity** and **resilience against side-channel and implementation attacks**.  It should be viewed as a research candidate: a starting point for deeper analysis by the cryptographic community, rather than a finished, drop-in standard.  We look forward to collaboration on refining and testing this approach.  

**Sources:** NIST PQC publications, PQC algorithm reference, recent research (POLKA, GhostLock, SSH hybrid signatures, fault analysis), and related PQCrypto literature.  These are cited throughout the text.  

