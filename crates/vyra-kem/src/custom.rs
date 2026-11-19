//! Hybrids assembled from caller-supplied components: the crypto-agility
//! entry point. VYRA-ORIGINAL.
//!
//! [`CustomHybridKem::from_components`] runs the same composition code and the
//! same [`combine`](crate::combine) as [`HybridKem`](crate::HybridKem), over
//! any two [`ComponentKem`] implementations. A [`CustomSuite`] descriptor
//! supplies the name and the byte that the combiner hashes in place of the
//! suite id.
//!
//! # What a custom assembly is not
//!
//! - It is **not** one of the named suites (VYRA-KEM-1/3/5) and has **no wire
//!   identifier**: there is no typed key or ciphertext type and no wire
//!   encoding for it. Only the raw [`Kem`] interface is offered.
//! - Nothing about its security follows from VYRA's documentation. The
//!   combiner argument in docs/SECURITY.md assumes at least one component is
//!   IND-CCA2 secure; a caller who supplies components takes responsibility
//!   for that assumption.
//! - [`CustomSuite::combiner_id`] is hashed exactly where a named suite's id
//!   is. Reusing a named suite's id together with that suite's own components
//!   reproduces that suite's raw KEM byte for byte (this is tested); with any
//!   other components it produces keys in the same hash domain as that suite.
//!   Outside experiments that compare against a named suite, pick an id that
//!   no named suite uses.

use core::fmt;

use vyra_core::{EntropySource, Kem, Result, SecretBytes, SecurityLevel};

use crate::combiner::COMBINED_SECRET_LEN;
use crate::component::ComponentKem;
use crate::hybrid::Composition;

/// Descriptor of a custom hybrid assembly: a display name and the byte the
/// combiner hashes in the suite position. Not a wire suite identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CustomSuite {
    name: &'static str,
    combiner_id: u8,
}

impl CustomSuite {
    /// A descriptor named `name` whose combiner input is `combiner_id`
    /// (see the [module docs](self) on reusing a named suite's id).
    pub const fn new(name: &'static str, combiner_id: u8) -> Self {
        CustomSuite { name, combiner_id }
    }

    /// Display name, returned by [`Kem::name`].
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// The byte hashed by the combiner in place of a suite id.
    pub const fn combiner_id(self) -> u8 {
        self.combiner_id
    }
}

/// A hybrid KEM over two caller-supplied components, outside the named
/// suites. See the [module docs](self) for what this does and does not give.
///
/// Raw layouts are those of [`HybridKem`](crate::HybridKem): public key
/// `pk1 ‖ pk2`, secret key `sk1 ‖ sk2`, ciphertext `ct1 ‖ ct2`, shared key
/// `combine(combiner_id, ss1, ss2, ct1, ct2, pk1, pk2)` with `pk1`, `pk2`
/// derived from the secret key on decapsulation. The shared key is always
/// [`COMBINED_SECRET_LEN`] bytes.
pub struct CustomHybridKem {
    suite: CustomSuite,
    parts: Composition,
}

impl CustomHybridKem {
    /// Assemble a hybrid from `first` and `second` under the descriptor `suite`.
    pub fn from_components(
        suite: CustomSuite,
        first: Box<dyn ComponentKem>,
        second: Box<dyn ComponentKem>,
    ) -> Self {
        CustomHybridKem {
            suite,
            parts: Composition::new(first, second),
        }
    }

    /// The descriptor of this assembly.
    pub const fn suite(&self) -> CustomSuite {
        self.suite
    }

    /// The first component.
    pub fn first(&self) -> &dyn ComponentKem {
        self.parts.first.as_ref()
    }

    /// The second component.
    pub fn second(&self) -> &dyn ComponentKem {
        self.parts.second.as_ref()
    }
}

impl fmt::Debug for CustomHybridKem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomHybridKem")
            .field("suite", &self.suite)
            .field("first", &self.parts.first.name())
            .field("second", &self.parts.second.name())
            .finish()
    }
}

impl Kem for CustomHybridKem {
    fn name(&self) -> &'static str {
        self.suite.name
    }

    /// The minimum of the components' claimed levels. For components that
    /// are not what they claim (for example deliberately broken ones) this is
    /// meaningless.
    fn level(&self) -> SecurityLevel {
        self.parts.level()
    }

    fn public_key_len(&self) -> usize {
        self.parts.public_key_len()
    }

    fn secret_key_len(&self) -> usize {
        self.parts.secret_key_len()
    }

    fn ciphertext_len(&self) -> usize {
        self.parts.ciphertext_len()
    }

    fn shared_secret_len(&self) -> usize {
        COMBINED_SECRET_LEN
    }

    fn generate_keypair(&self, rng: &mut dyn EntropySource) -> Result<(Vec<u8>, SecretBytes)> {
        self.parts.generate_keypair(rng)
    }

    fn encapsulate(
        &self,
        public_key: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<(Vec<u8>, SecretBytes)> {
        self.parts
            .encapsulate(self.suite.combiner_id, public_key, rng)
    }

    fn decapsulate(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<SecretBytes> {
        self.parts
            .decapsulate(self.suite.combiner_id, secret_key, ciphertext)
    }
}

impl ComponentKem for CustomHybridKem {
    /// Validates both component public keys.
    fn validate_public_key(&self, public_key: &[u8]) -> Result<()> {
        self.parts.validate_public_key(public_key)
    }

    /// `pk1 ‖ pk2`, each derived from its component secret key.
    fn public_key_from_secret(&self, secret_key: &[u8]) -> Result<Vec<u8>> {
        self.parts.public_key_from_secret(secret_key)
    }
}
