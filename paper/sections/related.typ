#import "common.typ": *

= Background and related work <sec-related>

We restrict this section to statements recorded with sources in `docs/SECURITY.md`; entries whose
bibliographic data were not checked online keep their "from memory — verify" marker in the
reference list.

*KEM combiners.* GHP18 #cite-n("GHP18") define the parallel combiner (ciphertext
$c_1 || ... || c_n$, key $W(k_1, ..., k_n, c_1 || ... || c_n)$) and show that it is IND-CCA
secure if $W$ is a split-key PRF and one ingredient is IND-CCA; their hash-based core functions are
proven in the ROM, and Don, Fehr and Huang prove a hash-based split-key PRF secure in the QROM
#cite-n("DFH22"). Millerjord, Stebila and Steckel #cite-n("MSS26") note that GHP18 assumes the
combined KEM's keys are not reused outside the combiner and give an extended model that captures
reuse. Bindel et al. #cite-n("BBFGS19") study hybrid KEMs in authenticated key exchange. X-Wing
#cite-n("XWING") omits the ML-KEM ciphertext from its key derivation and relies on a property of
ML-KEM to do so; the CFRG draft #cite-n("CFRG-HKEM") describes a UniversalCombiner that hashes both
shared secrets, both ciphertexts, both encapsulation keys and a label. That a combiner hashing only
the shared secrets is not CCA-robust once one component's ciphertexts can be mauled is shown by
GHP18 (as recorded in our decision log, D-01; we could not re-check the theorem numbers). That XOR
of the shared secrets is not IND-CCA even over two IND-CCA components is, to our knowledge,
folklore; we did not locate a verified source to attribute it to, and our harness merely
reproduces it.

*Binding.* Cremers, Dax and Medinger #cite-n("CDM23") define whether a KEM key binds the
ciphertext (X-BIND-K-CT) or the public key (X-BIND-K-PK) against HON, LEAK and MAL adversaries;
Krämer, Struck and Weishäupl #cite-n("KSW25") restate the games and analyse implicitly rejecting
KEMs including HQC (the HQC version they analysed has not been compared with v5.1), and Schmieg
#cite-n("Sch24") shows that ML-KEM is neither MAL-BIND-K-CT nor MAL-BIND-K-PK in a setting with
expanded keys.

*Composite signatures.* RFC 10073 #cite-n("RFC10073") specifies composite ML-DSA for X.509: both
components sign one representative and both must verify. Bindel et al. #cite-n("BHMS17") formalise
non-separability for such combinations. The BUFF notions of Cremers et al. #cite-n("CDFFJ21"),
restated by Düzlü, Fiedler and Fischlin #cite-n("DFF24"), include conservative exclusive ownership
(S-CEO) and message-bound signatures (MBS), which we use as games.

*Standards used.* ML-KEM (FIPS 203 #cite-n("FIPS203")) and HQC (specification v5.1
#cite-n("HQC-SPEC")\; NIST selected HQC in March 2025 and FIPS 207 is unpublished
#cite-n("NIST-HQC")) for key establishment; ML-DSA (FIPS 204 #cite-n("FIPS204")), SLH-DSA (FIPS 205
#cite-n("FIPS205")) and Ed25519/Ed25519ph (RFC 8032 #cite-n("RFC8032")) for signatures; SHA3-256 and
SHAKE256 (FIPS 202 #cite-n("FIPS202")) for VYRA's own hashing; ChaCha20-Poly1305 (RFC 8439
#cite-n("RFC8439")) as the DEM of a KEM-DEM sealed box #cite-n("CS03", "RFC9180"). HQC v5.1 raised
the secret weights of all three parameter sets relative to v5.0 in response to Carrier et al.
#cite-n("CHLT26").

*Where failure injection sits.* Relative to proofs, it is _complementary and strictly weaker_. A
proof quantifies over all adversaries against a precisely defined scheme; failure injection runs a
finite set of adversaries against a finite set of failure models and can only refute. Its use is to
catch the composition errors a proof assumes away (the implementation hashes something other than
what the proof hashes; a half is accepted by a standalone verifier; a key is not canonical), and to
make known separations executable and repeatable. Relative to conformance testing, it _covers the
composition_, which KATs do not: KATs exercise honest components on honest inputs and say nothing
about the behaviour of the combination when one component misbehaves. We did not survey the
literature systematically for comparable experiments; we know of no published matrix of this form
for hybrid KEMs and composite signatures, which is a statement about our search, not about the
literature.
