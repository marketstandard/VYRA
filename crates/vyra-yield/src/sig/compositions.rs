//! Signature compositions under test, all over the same component interface
//! ([`CompositeComponent`]).
//!
//! | design | both components sign | verification | source |
//! |--------|----------------------|--------------|--------|
//! | [`Vyra`](CompositionKind::Vyra) | `M' = "VYRA-SIG-v1" ‖ id ‖ pk_digest ‖ len(ctx) ‖ ctx ‖ M`, each half via `sign_half` under component context `"VYRA-SIG-v1" ‖ id` (ML-DSA/SLH-DSA: that FIPS context; Ed25519 since vyra-sig U12-R1: Ed25519ph with that context) | both | the real `vyra_sig::CustomComposite` (same engine as the named suites) |
//! | [`VyraPureEd`](CompositionKind::VyraPureEd) | as `Vyra`, but the Ed25519 half is the pre-U12-R1 PureEd25519 over `M'` ([`crate::sig::legacy`]) | both | historical regression control (transition pair only) |
//! | [`Concat`](CompositionKind::Concat) | the raw message `M`, each component's *default standalone* signature | both | naive "sign twice" |
//! | [`ConcatCtx`](CompositionKind::ConcatCtx) | `"VYRA-SIG-v0" ‖ id ‖ len(ctx) ‖ ctx ‖ M`, default standalone signatures | both | roughly VYRA before review findings S-1/S-2 (docs/ATTEMPTS.md): label, suite and context, but no public-key binding and no component context |
//! | [`Either`](CompositionKind::Either) | as `Vyra` | **either** half suffices | the wrong "OR" composition |
//!
//! "Default standalone signature" is the component's own
//! `SignatureScheme::sign` / `verify`: ML-DSA and SLH-DSA with the empty
//! context, Ed25519 as PureEd25519.
//!
//! Only `Vyra` is VYRA's current design. A nested/sequential composition
//! (second component signs the first's signature) is not included.

use core::fmt;

use vyra_core::{EntropySource, Error, Result, SecretBytes, SecurityLevel, Transcript};
use vyra_sig::{
    CompositeComponent, CustomComposite, CustomSuite, PK_DIGEST_LABEL, composite_context,
    message_representative_with_digest,
};

use super::models::derive_public_key;

/// Descriptor id of the `Vyra` assembly in every game (not a named suite id).
pub const VYRA_ID: u8 = 0x7A;

/// The second descriptor id, used by the cross-suite game and as the
/// "another VYRA suite" context in the standalone oracle.
pub const VYRA_ALT_ID: u8 = 0x7B;

/// Label of the [`ConcatCtx`](CompositionKind::ConcatCtx) message encoding.
pub const CONCAT_CTX_LABEL: &[u8] = b"VYRA-SIG-v0";

/// A composition design.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CompositionKind {
    /// The real VYRA composite engine via `CustomComposite::from_components`.
    Vyra,
    /// The VYRA engine with the pre-U12-R1 PureEd25519 half.
    VyraPureEd,
    /// Both sign `M` (default standalone mode); both must verify.
    Concat,
    /// Both sign a labelled, suite- and context-bound `M` (default
    /// standalone mode) without public-key binding; both must verify.
    ConcatCtx,
    /// VYRA's encoding, but verification accepts if either half verifies.
    Either,
}

impl CompositionKind {
    /// Every design, in report order.
    pub const ALL: [CompositionKind; 5] = [
        CompositionKind::Vyra,
        CompositionKind::VyraPureEd,
        CompositionKind::Concat,
        CompositionKind::ConcatCtx,
        CompositionKind::Either,
    ];

    /// Short name.
    pub const fn name(self) -> &'static str {
        match self {
            CompositionKind::Vyra => "Vyra",
            CompositionKind::VyraPureEd => "VyraPureEd",
            CompositionKind::Concat => "Concat",
            CompositionKind::ConcatCtx => "ConcatCtx",
            CompositionKind::Either => "Either",
        }
    }

    /// One-line description.
    pub const fn formula(self) -> &'static str {
        match self {
            CompositionKind::Vyra => {
                "both sign M' = label||id||H(pk1,pk2)||len(ctx)||ctx||M under component ctx label||id (Ed25519: Ed25519ph); AND"
            }
            CompositionKind::VyraPureEd => {
                "as Vyra, but the Ed25519 half is PureEd25519 over M' (pre-U12-R1 behaviour); AND"
            }
            CompositionKind::Concat => "both sign M with their default standalone mode; AND",
            CompositionKind::ConcatCtx => {
                "both sign label0||id||len(ctx)||ctx||M, default standalone mode (no pk binding); AND"
            }
            CompositionKind::Either => "VYRA's M' and component ctx; OR (either half suffices)",
        }
    }

    /// Whether halves are made with `sign_half` under the composite context
    /// (`true`) or with the default standalone `sign` (`false`).
    pub const fn uses_component_context(self) -> bool {
        matches!(
            self,
            CompositionKind::Vyra | CompositionKind::VyraPureEd | CompositionKind::Either
        )
    }

    /// The input both components sign, and the component context they sign
    /// it under (empty for the default-mode designs), for message `m` and
    /// context `ctx` under the public key `pk1 ‖ pk2` and suite byte `id`.
    /// A public function (Kerckhoffs).
    ///
    /// # Errors
    ///
    /// `InvalidLength` for a context longer than 255 bytes (encodings that
    /// carry the context).
    pub fn signed_input(
        self,
        id: u8,
        pk1: &[u8],
        pk2: &[u8],
        m: &[u8],
        ctx: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        match self {
            CompositionKind::Vyra | CompositionKind::VyraPureEd | CompositionKind::Either => {
                let mut t = Transcript::new(PK_DIGEST_LABEL);
                t.append(&[id]).append(pk1).append(pk2);
                let digest = t.finalize();
                let mp = message_representative_with_digest(id, &digest, ctx, m)?;
                Ok((mp, composite_context(id).to_vec()))
            }
            CompositionKind::Concat => Ok((m.to_vec(), Vec::new())),
            CompositionKind::ConcatCtx => {
                let len = u8::try_from(ctx.len()).map_err(|_| Error::InvalidLength {
                    what: "signature context",
                    expected: 255,
                    actual: ctx.len(),
                })?;
                let mut out = Vec::with_capacity(
                    CONCAT_CTX_LABEL
                        .len()
                        .saturating_add(2)
                        .saturating_add(ctx.len())
                        .saturating_add(m.len()),
                );
                out.extend_from_slice(CONCAT_CTX_LABEL);
                out.push(id);
                out.push(len);
                out.extend_from_slice(ctx);
                out.extend_from_slice(m);
                Ok((out, Vec::new()))
            }
        }
    }

    /// Assemble this design over `first` and `second` with suite byte `id`.
    /// (For `VyraPureEd` the caller supplies the PureEd25519 half as
    /// `second`; see [`crate::sig::SigContext::new`].)
    ///
    /// # Errors
    ///
    /// For `Vyra`/`VyraPureEd`, `CustomComposite::from_components`' error if
    /// `id` is a named suite id.
    pub fn assemble(
        self,
        id: u8,
        first: Box<dyn CompositeComponent>,
        second: Box<dyn CompositeComponent>,
        lens: SideLens,
    ) -> Result<Box<dyn SigComposite>> {
        match self {
            CompositionKind::Vyra | CompositionKind::VyraPureEd => Ok(Box::new(VyraComposite {
                kind: self,
                id,
                lens,
                inner: CustomComposite::from_components(
                    CustomSuite {
                        id,
                        name: "VYRA composite (custom assembly, experiment)",
                        level: SecurityLevel::L1,
                    },
                    first,
                    second,
                )?,
            })),
            kind => Ok(Box::new(ParallelComposite {
                kind,
                id,
                lens,
                first,
                second,
            })),
        }
    }
}

/// Component lengths of slot 1 and slot 2: `(pk, sk, sig)` each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SideLens {
    /// Slot 1 `(pk, sk, sig)` lengths.
    pub first: (usize, usize, usize),
    /// Slot 2 `(pk, sk, sig)` lengths.
    pub second: (usize, usize, usize),
}

impl SideLens {
    /// Lengths of two components.
    pub fn of(first: &dyn CompositeComponent, second: &dyn CompositeComponent) -> Self {
        SideLens {
            first: (
                first.public_key_len(),
                first.secret_key_len(),
                first.signature_len(),
            ),
            second: (
                second.public_key_len(),
                second.secret_key_len(),
                second.signature_len(),
            ),
        }
    }
}

/// The interface the games use for any composition.
pub trait SigComposite: Send + Sync {
    /// The design.
    fn kind(&self) -> CompositionKind;
    /// The suite byte.
    fn id(&self) -> u8;
    /// Component lengths.
    fn lens(&self) -> SideLens;
    /// The component context the halves are made under (empty for the
    /// default-mode designs).
    fn component_context(&self) -> Vec<u8> {
        if self.kind().uses_component_context() {
            composite_context(self.id()).to_vec()
        } else {
            Vec::new()
        }
    }
    /// Generate `(pk1 ‖ pk2, sk1 ‖ sk2)`.
    ///
    /// # Errors
    ///
    /// Component key-generation errors.
    fn generate(&self, rng: &mut dyn EntropySource) -> Result<(Vec<u8>, SecretBytes)>;
    /// Sign `m` under `ctx`.
    ///
    /// # Errors
    ///
    /// Malformed keys, overlong context, component errors.
    fn sign(&self, sk: &[u8], m: &[u8], ctx: &[u8], rng: &mut dyn EntropySource)
    -> Result<Vec<u8>>;
    /// Whether `sig` is accepted on `(m, ctx)` under `pk` (any error = no).
    fn verify(&self, pk: &[u8], m: &[u8], ctx: &[u8], sig: &[u8]) -> bool;
}

/// `Vyra` and `VyraPureEd`: the real `vyra_sig::CustomComposite`.
pub struct VyraComposite {
    kind: CompositionKind,
    id: u8,
    lens: SideLens,
    inner: CustomComposite,
}

impl fmt::Debug for VyraComposite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VyraComposite")
            .field("kind", &self.kind)
            .field("inner", &self.inner)
            .finish()
    }
}

impl SigComposite for VyraComposite {
    fn kind(&self) -> CompositionKind {
        self.kind
    }
    fn id(&self) -> u8 {
        self.id
    }
    fn lens(&self) -> SideLens {
        self.lens
    }
    fn generate(&self, rng: &mut dyn EntropySource) -> Result<(Vec<u8>, SecretBytes)> {
        self.inner.generate_raw(rng)
    }
    fn sign(
        &self,
        sk: &[u8],
        m: &[u8],
        ctx: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<Vec<u8>> {
        self.inner.sign_raw(sk, m, ctx, rng)
    }
    fn verify(&self, pk: &[u8], m: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
        self.inner.verify_raw(pk, m, ctx, sig).is_ok()
    }
}

/// `Concat`, `ConcatCtx` and `Either`.
pub struct ParallelComposite {
    kind: CompositionKind,
    id: u8,
    lens: SideLens,
    first: Box<dyn CompositeComponent>,
    second: Box<dyn CompositeComponent>,
}

impl fmt::Debug for ParallelComposite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParallelComposite")
            .field("kind", &self.kind)
            .field("first", &self.first.name())
            .field("second", &self.second.name())
            .finish()
    }
}

/// Split into exactly `a` and the rest, which must be exactly `b` bytes.
pub(crate) fn split2(bytes: &[u8], a: usize, b: usize) -> Result<(&[u8], &[u8])> {
    if bytes.len() != a.saturating_add(b) {
        return Err(Error::InvalidLength {
            what: "composite split",
            expected: a.saturating_add(b),
            actual: bytes.len(),
        });
    }
    bytes
        .split_at_checked(a)
        .ok_or(Error::Internal("composite split"))
}

impl ParallelComposite {
    fn sign_one(
        &self,
        c: &dyn CompositeComponent,
        sk: &[u8],
        input: &[u8],
        cctx: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<Vec<u8>> {
        if self.kind.uses_component_context() {
            c.sign_half(sk, input, cctx, rng)
        } else {
            c.sign(sk, input, rng)
        }
    }

    fn verify_one(
        &self,
        c: &dyn CompositeComponent,
        pk: &[u8],
        input: &[u8],
        cctx: &[u8],
        sig: &[u8],
    ) -> bool {
        let ok = if self.kind.uses_component_context() {
            c.verify_half(pk, input, cctx, sig).is_ok()
        } else {
            c.verify(pk, input, sig).is_ok()
        };
        c.validate_public_key(pk).is_ok() & ok
    }
}

impl SigComposite for ParallelComposite {
    fn kind(&self) -> CompositionKind {
        self.kind
    }
    fn id(&self) -> u8 {
        self.id
    }
    fn lens(&self) -> SideLens {
        self.lens
    }
    fn generate(&self, rng: &mut dyn EntropySource) -> Result<(Vec<u8>, SecretBytes)> {
        let (pk1, sk1) = self.first.generate_keypair(rng)?;
        let (pk2, sk2) = self.second.generate_keypair(rng)?;
        let mut pk = pk1;
        pk.extend_from_slice(&pk2);
        let mut sk = Vec::with_capacity(sk1.len().saturating_add(sk2.len()));
        sk.extend_from_slice(sk1.expose());
        sk.extend_from_slice(sk2.expose());
        Ok((pk, SecretBytes::new(sk)))
    }
    fn sign(
        &self,
        sk: &[u8],
        m: &[u8],
        ctx: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<Vec<u8>> {
        let (sk1, sk2) = split2(sk, self.lens.first.1, self.lens.second.1)?;
        let pk1 = derive_public_key(self.first.as_ref(), sk1)?;
        let pk2 = derive_public_key(self.second.as_ref(), sk2)?;
        let (input, cctx) = self.kind.signed_input(self.id, &pk1, &pk2, m, ctx)?;
        let mut sig = self.sign_one(self.first.as_ref(), sk1, &input, &cctx, rng)?;
        sig.extend_from_slice(&self.sign_one(self.second.as_ref(), sk2, &input, &cctx, rng)?);
        Ok(sig)
    }
    fn verify(&self, pk: &[u8], m: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
        let (Ok((pk1, pk2)), Ok((s1, s2))) = (
            split2(pk, self.lens.first.0, self.lens.second.0),
            split2(sig, self.lens.first.2, self.lens.second.2),
        ) else {
            return false;
        };
        let Ok((input, cctx)) = self.kind.signed_input(self.id, pk1, pk2, m, ctx) else {
            return false;
        };
        let ok1 = self.verify_one(self.first.as_ref(), pk1, &input, &cctx, s1);
        let ok2 = self.verify_one(self.second.as_ref(), pk2, &input, &cctx, s2);
        match self.kind {
            CompositionKind::Either => ok1 | ok2,
            _ => ok1 & ok2,
        }
    }
}
