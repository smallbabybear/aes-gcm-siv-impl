//! AES-GCM-SIV implementation based on RFC 8452
//!
//! This crate provides a simple API for encrypting and decrypting data using
//! AES-GCM-SIV with both 128-bit and 256-bit key sizes.
//!
//! # Security Notes
//! - Nonces MUST NOT be reused with the same key
//! - Nonces are 12 bytes (96 bits)
//! - Maximum data size: 2^36 - 31 bytes
//! - Uses constant-time implementations from RustCrypto

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use aes_gcm_siv::{
    aead::{Aead, KeyInit, Payload},
    Aes128GcmSiv, Aes256GcmSiv, Nonce,
};
use rand::TryRngCore;
use std::fmt;

/// Fixed nonce length in bytes (12 bytes/96 bits)
pub const NONCE_LENGTH: usize = 12;

/// Fixed tag length in bytes (16 bytes/128 bits)
pub const TAG_LENGTH: usize = 16;

/// Supported key sizes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySize {
    /// AES-128-GCM-SIV (16 bytes / 128 bits)
    Aes128,
    /// AES-256-GCM-SIV (32 bytes / 256 bits)
    Aes256,
}

/// Error types for encryption/decryption operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Authentication failed during decryption
    Auth,
    /// Invalid key size provided
    InvalidKeySize,
    /// Invalid nonce size provided
    InvalidNonceSize,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::Auth => write!(f, "Authentication failed"),
            CryptoError::InvalidKeySize => write!(f, "Invalid key size"),
            CryptoError::InvalidNonceSize => write!(f, "Invalid nonce size (must be 12 bytes)"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Result type for cryptographic operations
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Encrypt plaintext using AES-GCM-SIV
///
/// # Arguments
/// * `key` - The encryption key (must be 16 or 32 bytes)
/// * `nonce` - The nonce (must be 12 bytes)
/// * `plaintext` - The plaintext data to encrypt
/// * `aad` - Additional authenticated data (optional)
///
/// # Returns
/// The ciphertext with authentication tag appended
///
/// # Security Notes
/// - Never reuse a nonce with the same key
/// - The nonce should be randomly generated for each encryption operation
///
/// # Errors
/// Returns `CryptoError` if key or nonce length is invalid
pub fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
    if nonce.len() != NONCE_LENGTH {
        return Err(CryptoError::InvalidNonceSize);
    }

    let key_size = match key.len() {
        16 => KeySize::Aes128,
        32 => KeySize::Aes256,
        _ => return Err(CryptoError::InvalidKeySize),
    };

    let nonce_array = Nonce::from_slice(nonce);

    match key_size {
        KeySize::Aes128 => {
            let cipher =
                Aes128GcmSiv::new_from_slice(key).map_err(|_| CryptoError::InvalidKeySize)?;
            cipher
                .encrypt(
                    nonce_array,
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| CryptoError::Auth)
        }
        KeySize::Aes256 => {
            let cipher =
                Aes256GcmSiv::new_from_slice(key).map_err(|_| CryptoError::InvalidKeySize)?;
            cipher
                .encrypt(
                    nonce_array,
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| CryptoError::Auth)
        }
    }
}

/// Decrypt ciphertext using AES-GCM-SIV
///
/// # Arguments
/// * `key` - The encryption key (must be 16 or 32 bytes)
/// * `nonce` - The nonce (must be 12 bytes)
/// * `ciphertext` - The ciphertext data with authentication tag appended
/// * `aad` - Additional authenticated data (must match what was used for encryption)
///
/// # Returns
/// The decrypted plaintext
///
/// # Errors
/// Returns `CryptoError::Auth` if authentication fails or
/// `CryptoError::InvalidKeySize` if key is invalid
pub fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
    if nonce.len() != NONCE_LENGTH {
        return Err(CryptoError::InvalidNonceSize);
    }

    let key_size = match key.len() {
        16 => KeySize::Aes128,
        32 => KeySize::Aes256,
        _ => return Err(CryptoError::InvalidKeySize),
    };

    let nonce_array = Nonce::from_slice(nonce);

    match key_size {
        KeySize::Aes128 => {
            let cipher =
                Aes128GcmSiv::new_from_slice(key).map_err(|_| CryptoError::InvalidKeySize)?;
            cipher
                .decrypt(
                    nonce_array,
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| CryptoError::Auth)
        }
        KeySize::Aes256 => {
            let cipher =
                Aes256GcmSiv::new_from_slice(key).map_err(|_| CryptoError::InvalidKeySize)?;
            cipher
                .decrypt(
                    nonce_array,
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| CryptoError::Auth)
        }
    }
}

/// Generate a random nonce suitable for AES-GCM-SIV
///
/// # Returns
/// A 12-byte random nonce
pub fn generate_nonce() -> Vec<u8> {
    let mut os_rng = rand::rngs::OsRng;
    let mut unique_seed = [0u8; NONCE_LENGTH];
    os_rng.try_fill_bytes(&mut unique_seed).unwrap(); // CSPRNG seed

    Nonce::from_slice(&unique_seed).to_vec()
}
