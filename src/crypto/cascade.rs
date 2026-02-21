// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 AnmiTaliDev <anmitalidev@nuros.org>

use aes::Aes256;
use twofish::Twofish;
use serpent::Serpent;
use cbc::{Encryptor, Decryptor};
use cipher::{KeyIvInit, BlockModeEncrypt, BlockModeDecrypt, block_padding::Pkcs7};

use crate::models::CipherAlgorithm;
use super::kdf::{KEY_SIZE, IV_SIZE};

type Aes256CbcEnc  = Encryptor<Aes256>;
type Aes256CbcDec  = Decryptor<Aes256>;
type TwofishCbcEnc = Encryptor<Twofish>;
type TwofishCbcDec = Decryptor<Twofish>;
type SerpentCbcEnc = Encryptor<Serpent>;
type SerpentCbcDec = Decryptor<Serpent>;

fn enc<C: BlockModeEncrypt + KeyIvInit>(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    C::new_from_slices(key, iv)
        .expect("key/iv length is always valid")
        .encrypt_padded_vec::<Pkcs7>(data)
}

fn dec<C: BlockModeDecrypt + KeyIvInit>(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    label: &str,
) -> anyhow::Result<Vec<u8>> {
    C::new_from_slices(key, iv)
        .expect("key/iv length is always valid")
        .decrypt_padded_vec::<Pkcs7>(data)
        .map_err(|e| anyhow::anyhow!("{label} decrypt error: {e}"))
}

/// Encrypt `data` with the chosen algorithm (or cascade of algorithms).
pub fn encrypt(data: &[u8], key: &[u8; KEY_SIZE], iv: &[u8; IV_SIZE], algo: CipherAlgorithm) -> Vec<u8> {
    match algo {
        CipherAlgorithm::Aes => {
            enc::<Aes256CbcEnc>(key, iv, data)
        }
        CipherAlgorithm::Twofish => {
            enc::<TwofishCbcEnc>(key, iv, data)
        }
        CipherAlgorithm::Serpent => {
            enc::<SerpentCbcEnc>(key, iv, data)
        }
        CipherAlgorithm::AesTwofish => {
            enc::<TwofishCbcEnc>(key, iv, &enc::<Aes256CbcEnc>(key, iv, data))
        }
        CipherAlgorithm::AesSerpent => {
            enc::<SerpentCbcEnc>(key, iv, &enc::<Aes256CbcEnc>(key, iv, data))
        }
        CipherAlgorithm::Maximum => {
            enc::<SerpentCbcEnc>(key, iv,
                &enc::<TwofishCbcEnc>(key, iv,
                    &enc::<Aes256CbcEnc>(key, iv, data)))
        }
    }
}

/// Decrypt `data` with the chosen algorithm (cascade is applied in reverse).
pub fn decrypt(data: &[u8], key: &[u8; KEY_SIZE], iv: &[u8; IV_SIZE], algo: CipherAlgorithm) -> anyhow::Result<Vec<u8>> {
    match algo {
        CipherAlgorithm::Aes => {
            dec::<Aes256CbcDec>(key, iv, data, "AES")
        }
        CipherAlgorithm::Twofish => {
            dec::<TwofishCbcDec>(key, iv, data, "Twofish")
        }
        CipherAlgorithm::Serpent => {
            dec::<SerpentCbcDec>(key, iv, data, "Serpent")
        }
        CipherAlgorithm::AesTwofish => {
            dec::<Aes256CbcDec>(key, iv, &dec::<TwofishCbcDec>(key, iv, data, "Twofish")?, "AES")
        }
        CipherAlgorithm::AesSerpent => {
            dec::<Aes256CbcDec>(key, iv, &dec::<SerpentCbcDec>(key, iv, data, "Serpent")?, "AES")
        }
        CipherAlgorithm::Maximum => {
            dec::<Aes256CbcDec>(key, iv,
                &dec::<TwofishCbcDec>(key, iv,
                    &dec::<SerpentCbcDec>(key, iv, data, "Serpent")?,
                "Twofish")?,
            "AES")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixed key and IV for deterministic tests
    const KEY: &[u8; KEY_SIZE] = b"an_exactly_32_byte_test_key_here";
    const IV:  &[u8; IV_SIZE]  = b"16_byte_test_iv!";

    fn roundtrip(algo: CipherAlgorithm, plaintext: &[u8]) {
        let ciphertext = encrypt(plaintext, KEY, IV, algo);
        assert_ne!(ciphertext, plaintext, "ciphertext must differ from plaintext");
        let recovered = decrypt(&ciphertext, KEY, IV, algo).expect("decrypt must succeed");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn roundtrip_aes() {
        roundtrip(CipherAlgorithm::Aes, b"hello world");
    }

    #[test]
    fn roundtrip_twofish() {
        roundtrip(CipherAlgorithm::Twofish, b"hello world");
    }

    #[test]
    fn roundtrip_serpent() {
        roundtrip(CipherAlgorithm::Serpent, b"hello world");
    }

    #[test]
    fn roundtrip_aes_twofish() {
        roundtrip(CipherAlgorithm::AesTwofish, b"hello world");
    }

    #[test]
    fn roundtrip_aes_serpent() {
        roundtrip(CipherAlgorithm::AesSerpent, b"hello world");
    }

    #[test]
    fn roundtrip_maximum() {
        roundtrip(CipherAlgorithm::Maximum, b"hello world");
    }

    #[test]
    fn roundtrip_empty_input() {
        roundtrip(CipherAlgorithm::Maximum, b"");
    }

    #[test]
    fn roundtrip_large_input() {
        let data = vec![0xABu8; 1024 * 1024]; // 1 MiB
        roundtrip(CipherAlgorithm::Maximum, &data);
    }

    #[test]
    fn roundtrip_exact_block_boundary() {
        // 32 bytes — exactly two AES blocks
        roundtrip(CipherAlgorithm::Maximum, &[0u8; 32]);
    }

    #[test]
    fn different_algos_produce_different_ciphertext() {
        let plaintext = b"same plaintext";
        let ct_aes = encrypt(plaintext, KEY, IV, CipherAlgorithm::Aes);
        let ct_max = encrypt(plaintext, KEY, IV, CipherAlgorithm::Maximum);
        assert_ne!(ct_aes, ct_max);
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let ciphertext = encrypt(b"secret", KEY, IV, CipherAlgorithm::Aes);
        let wrong_key: &[u8; KEY_SIZE] = b"wrong_key_32_bytes_padding_here!";
        let result = decrypt(&ciphertext, wrong_key, IV, CipherAlgorithm::Aes);
        assert!(result.is_err(), "decrypt with wrong key must fail");
    }

    #[test]
    fn wrong_iv_fails_to_decrypt() {
        let ciphertext = encrypt(b"secret", KEY, IV, CipherAlgorithm::Aes);
        let wrong_iv: &[u8; IV_SIZE] = b"wrong_iv_16byte!";
        let result = decrypt(&ciphertext, KEY, wrong_iv, CipherAlgorithm::Aes);
        // With wrong IV, padding will likely be invalid or plaintext will be garbled
        assert!(result.is_err() || result.unwrap() != b"secret");
    }

    #[test]
    fn encrypt_is_deterministic() {
        let ct1 = encrypt(b"data", KEY, IV, CipherAlgorithm::Maximum);
        let ct2 = encrypt(b"data", KEY, IV, CipherAlgorithm::Maximum);
        assert_eq!(ct1, ct2);
    }
}
