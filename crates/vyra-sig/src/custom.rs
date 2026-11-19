//! Custom composite assemblies (crypto-agility entry point).
//!
//! [`CustomComposite::from_components`] runs the VYRA composite algorithms
//! (same message representative, same composite context, same public-key
//! binding, same verification rule as [`CompositeSignature`]) over two
//! caller-supplied [`CompositeComponent`]s and a caller-chosen
//! [`CustomSuite`] descriptor. It exists for experiments (for example
//! failure injection: a component that is deliberately broken) and for
//! trying other component pairs.
//!
//! **Custom assemblies are outside the named suites and the wire format.**
//! They have no [`SigSuite`], no wire encodings, no typed key objects and no
//! key check value; only raw byte interfaces are offered. A descriptor id
//! that is assigned to a named suite is rejected, so a custom assembly never
//! produces a message representative that claims a named suite. VYRA makes
//! no security statement about a custom assembly: it is only as good as the
//! components and the validation rules (`validate_public_key`,
//! `context_bound`) the caller supplies.
//!
//! [`CompositeSignature`]: crate::CompositeSignature

use core::fmt;

use vyra_core::{EntropySource, Error, Result, SecretBytes, SecurityLevel, SignatureScheme};

use crate::component::CompositeComponent;
use crate::composite::{Engine, Handle};
use crate::suite::SigSuite;

/// Descriptor of a custom composite: the suite byte bound into `M'` and the
/// composite context, plus a name and a category label for reporting. VYRA
/// does not check that `level` is justified by the components.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CustomSuite {
    /// Suite byte used in `M'` and in the composite context. Must not be the
    /// id of a named [`SigSuite`].
    pub id: u8,
    /// Name reported by [`SignatureScheme::name`].
    pub name: &'static str,
    /// Category label reported by [`SignatureScheme::level`].
    pub level: SecurityLevel,
}

/// A composite assembled from two caller-supplied components (see the
/// [module docs](self)).
pub struct CustomComposite {
    descriptor: CustomSuite,
    engine: Engine,
}

impl fmt::Debug for CustomComposite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomComposite")
            .field("descriptor", &self.descriptor)
            .field("first", &self.engine.first().name())
            .field("second", &self.engine.second().name())
            .finish()
    }
}

impl CustomComposite {
    /// Assemble a composite from `first` and `second` under `descriptor`.
    ///
    /// Raw encodings are `pk_first ‖ pk_second`, `sk_first ‖ sk_second` and
    /// `sig_first ‖ sig_second`; key generation draws `first`'s randomness
    /// and then `second`'s.
    ///
    /// # Errors
    ///
    /// `InvalidEncoding("custom suite id is assigned to a named suite")` if
    /// `descriptor.id` is the id of a named [`SigSuite`].
    pub fn from_components(
        descriptor: CustomSuite,
        first: Box<dyn CompositeComponent>,
        second: Box<dyn CompositeComponent>,
    ) -> Result<Self> {
        if SigSuite::from_id(descriptor.id).is_ok() {
            return Err(Error::InvalidEncoding(
                "custom suite id is assigned to a named suite",
            ));
        }
        Ok(CustomComposite {
            descriptor,
            engine: Engine::new(descriptor.id, Handle::Owned(first), Handle::Owned(second)),
        })
    }

    /// The descriptor this composite was assembled with.
    pub fn descriptor(&self) -> CustomSuite {
        self.descriptor
    }

    /// Exact length, then each component's
    /// [`validate_public_key`](CompositeComponent::validate_public_key).
    ///
    /// # Errors
    ///
    /// `InvalidLength` for a wrong length; the component's error otherwise.
    pub fn validate_public_key(&self, public_key: &[u8]) -> Result<()> {
        self.engine.validate_public_key(public_key)
    }

    /// Generate a raw key pair.
    ///
    /// # Errors
    ///
    /// [`Error::EntropyFailure`] if `rng` fails.
    pub fn generate_raw(&self, rng: &mut dyn EntropySource) -> Result<(Vec<u8>, SecretBytes)> {
        self.engine.generate_raw(rng)
    }

    /// Sign `message` under `context` (at most 255 bytes).
    ///
    /// # Errors
    ///
    /// `InvalidLength` for a wrong-length key or a context longer than 255
    /// bytes; `EntropyFailure` if `rng` fails; component errors.
    pub fn sign_raw(
        &self,
        secret_key: &[u8],
        message: &[u8],
        context: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<Vec<u8>> {
        self.engine.sign_raw(secret_key, message, context, rng)
    }

    /// Verify `signature` on `message` under `context`; both components and
    /// the public-key validation are always evaluated.
    ///
    /// # Errors
    ///
    /// `InvalidLength` for wrong-length inputs or a context longer than 255
    /// bytes; otherwise [`Error::VerificationFailed`] unless everything
    /// accepts.
    pub fn verify_raw(
        &self,
        public_key: &[u8],
        message: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        self.engine
            .verify_raw(public_key, message, context, signature)
    }
}

/// Raw-bytes interface with an **empty** context string.
impl SignatureScheme for CustomComposite {
    fn name(&self) -> &'static str {
        self.descriptor.name
    }

    fn level(&self) -> SecurityLevel {
        self.descriptor.level
    }

    fn public_key_len(&self) -> usize {
        self.engine.public_key_len()
    }

    fn secret_key_len(&self) -> usize {
        self.engine.secret_key_len()
    }

    fn signature_len(&self) -> usize {
        self.engine.signature_len()
    }

    fn generate_keypair(&self, rng: &mut dyn EntropySource) -> Result<(Vec<u8>, SecretBytes)> {
        self.generate_raw(rng)
    }

    fn sign(
        &self,
        secret_key: &[u8],
        message: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<Vec<u8>> {
        self.sign_raw(secret_key, message, &[], rng)
    }

    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        self.verify_raw(public_key, message, &[], signature)
    }
}
