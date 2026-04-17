//! FFLONK prover — native Rust FFLONK prover for Circom R1CS circuits.
//!
//! Byte-compatible with snarkjs 0.7.6 FFLONK Solidity verifiers on BN254.

pub mod kzg;
pub mod transcript;
pub mod wtns;
pub mod zkey;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_matches_cargo_package() {
        assert_eq!(VERSION, "0.1.0");
    }
}
