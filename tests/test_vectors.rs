//! Test vectors from RFC 8452 Appendix A
//! https://tools.ietf.org/html/rfc8452#appendix-A

#![forbid(unsafe_code)]

use aes_gcm_siv_impl::{decrypt, encrypt};
use hex_literal::hex;

#[test]
fn test_aes_128_gcm_siv_test_vector_1() {
    // RFC 8452 Appendix A.1
    let key = hex!("01000000000000000000000000000000");
    let nonce = hex!("030000000000000000000000");
    let plaintext = &[];
    let aad = &[];

    let ciphertext = encrypt(&key, &nonce, plaintext, aad).unwrap();
    assert_eq!(ciphertext, hex!("dc20e2d83f25705bb49e439eca56de25"));

    let decrypted = decrypt(&key, &nonce, &ciphertext, aad).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes_128_gcm_siv_test_vector_2() {
    // RFC 8452 Appendix A.2
    let key = hex!("01000000000000000000000000000000");
    let nonce = hex!("030000000000000000000000");
    let plaintext = hex!("0100000000000000");
    let aad = &[];

    let ciphertext = encrypt(&key, &nonce, &plaintext, aad).unwrap();
    assert_eq!(
        ciphertext,
        hex!("b5d839330ac7b786578782fff6013b815b287c22493a364c")
    );

    let decrypted = decrypt(&key, &nonce, &ciphertext, aad).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes_128_gcm_siv_test_vector_3() {
    // RFC 8452 Appendix A.3
    let key = hex!("01000000000000000000000000000000");
    let nonce = hex!("030000000000000000000000");
    let plaintext = hex!("010000000000000000000000");
    let aad = &[];

    let ciphertext = encrypt(&key, &nonce, &plaintext, aad).unwrap();
    assert_eq!(
        ciphertext,
        hex!("7323ea61d05932260047d942a4978db357391a0bc4fdec8b0d106639")
    );

    let decrypted = decrypt(&key, &nonce, &ciphertext, aad).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes_128_gcm_siv_test_vector_4() {
    // RFC 8452 Appendix A.4
    let key = hex!("01000000000000000000000000000000");
    let nonce = hex!("030000000000000000000000");
    let plaintext = hex!("01000000000000000000000000000000");
    let aad = &[];

    let ciphertext = encrypt(&key, &nonce, &plaintext, aad).unwrap();
    assert_eq!(
        ciphertext,
        hex!("743f7c8077ab25f8624e2e948579cf77303aaf90f6fe21199c6068577437a0c4")
    );

    let decrypted = decrypt(&key, &nonce, &ciphertext, aad).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes_128_gcm_siv_test_vector_with_aad() {
    // RFC 8452 Appendix A.5
    let key = hex!("01000000000000000000000000000000");
    let nonce = hex!("030000000000000000000000");
    let plaintext = hex!("01000000000000000000000000000000");
    let aad = hex!("010000000000000000000000");

    let ciphertext = encrypt(&key, &nonce, &plaintext, &aad).unwrap();
    assert_eq!(
        ciphertext,
        hex!("884fe3d5f9d0b10ddd177e70f114f419917545b792bbaa8eaebb151c55433de3")
    );

    let decrypted = decrypt(&key, &nonce, &ciphertext, &aad).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes_256_gcm_siv_test_vector_1() {
    // RFC 8452 Appendix A.6
    let key = hex!("0100000000000000000000000000000000000000000000000000000000000000");
    let nonce = hex!("030000000000000000000000");
    let plaintext = &[];
    let aad = &[];

    let ciphertext = encrypt(&key, &nonce, plaintext, aad).unwrap();
    assert_eq!(ciphertext, hex!("07f5f4169bbf55a8400cd47ea6fd400f"));

    let decrypted = decrypt(&key, &nonce, &ciphertext, aad).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes_256_gcm_siv_test_vector_2() {
    // RFC 8452 Appendix A.7
    let key = hex!("0100000000000000000000000000000000000000000000000000000000000000");
    let nonce = hex!("030000000000000000000000");
    let plaintext = hex!("0100000000000000");
    let aad = &[];

    let ciphertext = encrypt(&key, &nonce, &plaintext, aad).unwrap();
    assert_eq!(
        ciphertext,
        hex!("c2ef328e5c71c83b843122130f7364b761e0b97427e3df28")
    );

    let decrypted = decrypt(&key, &nonce, &ciphertext, aad).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes_256_gcm_siv_test_vector_with_aad() {
    // RFC 8452 Appendix A.10
    let key = hex!("0100000000000000000000000000000000000000000000000000000000000000");
    let nonce = hex!("030000000000000000000000");
    let plaintext = hex!("01000000000000000000000000000000");
    let aad = hex!("010000000000000000000000");

    let ciphertext = encrypt(&key, &nonce, &plaintext, &aad).unwrap();
    assert_eq!(
        ciphertext,
        hex!("38ea3fbf60dc9f955869858771b5145f588a417df0c5164d812fa3661429ec44")
    );

    let decrypted = decrypt(&key, &nonce, &ciphertext, &aad).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_authentication_failure() {
    let key = hex!("0100000000000000000000000000000000000000000000000000000000000000");
    let nonce = hex!("030000000000000000000000");
    let plaintext = hex!("01000000000000000000000000000000");
    let aad = hex!("010000000000000000000000");

    // Encrypt the data
    let mut ciphertext = encrypt(&key, &nonce, &plaintext, &aad).unwrap();

    // Tamper with the ciphertext
    if !ciphertext.is_empty() {
        ciphertext[0] ^= 1;
    }

    // Attempt to decrypt tampered ciphertext - should fail
    let result = decrypt(&key, &nonce, &ciphertext, &aad);
    assert!(result.is_err());
}

#[test]
fn test_incorrect_aad() {
    let key = hex!("0100000000000000000000000000000000000000000000000000000000000000");
    let nonce = hex!("030000000000000000000000");
    let plaintext = hex!("01000000000000000000000000000000");
    let aad = hex!("010000000000000000000000");
    let incorrect_aad = hex!("010000000000000000000001"); // Changed last byte

    // Encrypt with correct AAD
    let ciphertext = encrypt(&key, &nonce, &plaintext, &aad).unwrap();

    // Attempt to decrypt with incorrect AAD - should fail
    let result = decrypt(&key, &nonce, &ciphertext, &incorrect_aad);
    assert!(result.is_err());
}

#[test]
fn test_invalid_key_size() {
    let key = hex!("010000000000000000000000"); // 12 bytes - invalid key size
    let nonce = hex!("030000000000000000000000");
    let plaintext = hex!("01000000000000000000000000000000");
    let aad = &[];

    // Should fail with invalid key size error
    let result = encrypt(&key, &nonce, &plaintext, aad);
    assert!(result.is_err());
}

#[test]
fn test_invalid_nonce_size() {
    let key = hex!("0100000000000000000000000000000000000000000000000000000000000000");
    let nonce = hex!("0300000000000000"); // 8 bytes - invalid nonce size
    let plaintext = hex!("01000000000000000000000000000000");
    let aad = &[];

    // Should fail with invalid nonce size error
    let result = encrypt(&key, &nonce, &plaintext, aad);
    assert!(result.is_err());
}

#[test]
fn test_generate_nonce() {
    let nonce = aes_gcm_siv_impl::generate_nonce();
    assert_eq!(nonce.len(), 12); // Verify nonce is 12 bytes

    // Generate another nonce to ensure they're different
    let nonce2 = aes_gcm_siv_impl::generate_nonce();
    assert_ne!(nonce, nonce2); // Verify nonces are different
}
