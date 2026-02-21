// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2025 AnmiTaliDev <anmitalidev@nuros.org>

use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use zeroize::Zeroizing;

pub const KEY_SIZE: usize  = 32; // 256 bits
pub const IV_SIZE: usize   = 16; // 128 bits
pub const SALT_SIZE: usize = 32; // 256 bits
pub const PBKDF2_ITERS: u32 = 100_000;

/// Derive a 256-bit encryption key from `password` and a per-file random `salt`
/// using PBKDF2-HMAC-SHA256. The key is wrapped in `Zeroizing` so it is wiped
/// from memory when dropped.
pub fn derive_key(password: &str, salt: &[u8]) -> Zeroizing<[u8; KEY_SIZE]> {
    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ITERS, key.as_mut());
    key
}

/// Derive a 128-bit IV from `master_key` and the same per-file `salt` using
/// PBKDF2-HMAC-SHA256. Storing the derived IV in the file header lets us verify
/// the master key on decryption without a separate MAC.
pub fn derive_iv(master_key: &str, salt: &[u8]) -> [u8; IV_SIZE] {
    let mut iv = [0u8; IV_SIZE];
    pbkdf2_hmac::<Sha256>(master_key.as_bytes(), salt, PBKDF2_ITERS, &mut iv);
    iv
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: &[u8] = b"test_salt_32bytes_padding_filler";

    #[test]
    fn derive_key_is_deterministic() {
        let k1 = derive_key("password", SALT);
        let k2 = derive_key("password", SALT);
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn derive_key_differs_by_password() {
        let k1 = derive_key("password1", SALT);
        let k2 = derive_key("password2", SALT);
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn derive_key_differs_by_salt() {
        let k1 = derive_key("password", b"salt_a_32bytes_padding__filler__");
        let k2 = derive_key("password", b"salt_b_32bytes_padding__filler__");
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn derive_key_correct_length() {
        let k = derive_key("password", SALT);
        assert_eq!(k.len(), KEY_SIZE);
    }

    #[test]
    fn derive_iv_is_deterministic() {
        let iv1 = derive_iv("masterkey", SALT);
        let iv2 = derive_iv("masterkey", SALT);
        assert_eq!(iv1, iv2);
    }

    #[test]
    fn derive_iv_differs_by_master_key() {
        let iv1 = derive_iv("masterkey1", SALT);
        let iv2 = derive_iv("masterkey2", SALT);
        assert_ne!(iv1, iv2);
    }

    #[test]
    fn derive_iv_differs_by_salt() {
        let iv1 = derive_iv("masterkey", b"salt_a_32bytes_padding__filler__");
        let iv2 = derive_iv("masterkey", b"salt_b_32bytes_padding__filler__");
        assert_ne!(iv1, iv2);
    }

    #[test]
    fn derive_iv_correct_length() {
        let iv = derive_iv("masterkey", SALT);
        assert_eq!(iv.len(), IV_SIZE);
    }

    #[test]
    fn key_and_iv_differ_when_inputs_differ() {
        // key uses password as input, iv uses master_key — so different strings → different output
        let key = derive_key("my_password", SALT);
        let iv  = derive_iv("my_master_key", SALT);
        assert_ne!(&key[..IV_SIZE], &iv[..]);
    }
}
