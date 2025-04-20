# AES-GCM-SIV Implementation

This crate provides a Rust implementation of AES-GCM-SIV as specified in [RFC 8452](https://tools.ietf.org/html/rfc8452).

## Features

- AES-GCM-SIV encryption and decryption
- Support for both 128-bit and 256-bit keys
- Command-line interface for file encryption/decryption
- Based on RustCrypto's `aes-gcm-siv` crate for optimal security and performance

## Security Notes

- **NEVER** reuse a nonce with the same key. This would catastrophically compromise security.
- Use a secure random number generator to generate nonces.
- The maximum data size is 2^36 - 31 bytes.
- The nonce size is fixed at 12 bytes (96 bits).
- The tag size is fixed at 16 bytes (128 bits).

## Usage

### Library

```rust
use aes_gcm_siv_impl::{encrypt, decrypt};

// Example with a 256-bit key
let key = [0u8; 32]; // Use a secure random key in production
let nonce = [0u8; 12]; // Use a secure random nonce in production
let plaintext = b"Secret message";
let aad = b"Additional data"; // Optional authenticated data

// Encrypt
let ciphertext = encrypt(&key, &nonce, plaintext, aad)?;

// Decrypt
let decrypted = decrypt(&key, &nonce, &ciphertext, aad)?;
assert_eq!(plaintext, &decrypted[..]);
```

### Command Line

Encrypt a file:

```bash
# Generate a random nonce
$ cargo run -- gen-nonce
0123456789abcdef0123456789ab

# Encrypt with a 256-bit key
$ cargo run -- encrypt input.txt encrypted.bin --key 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f --nonce 0123456789abcdef0123456789ab --aad "Optional AAD"
```

Decrypt a file:

```bash
$ cargo run -- decrypt encrypted.bin output.txt --key 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f --nonce 0123456789abcdef0123456789ab --aad "Optional AAD"
```

## Key Sizes

- **AES-128-GCM-SIV**: 16-byte key (128 bits)
- **AES-256-GCM-SIV**: 32-byte key (256 bits)

## Compliance

This implementation follows RFC 8452 and includes test vectors from the specification to ensure compliance.

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT License

at your option.