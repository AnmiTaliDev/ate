// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2025 AnmiTaliDev <anmitalidev@nuros.org>

use std::io::{Read, Write};
use std::fs::File;
use std::path::Path;

use rand::RngCore;
use anyhow::Context;
use indicatif::ProgressBar;

use crate::models::CipherAlgorithm;
use super::kdf::{SALT_SIZE, IV_SIZE, derive_key, derive_iv};
use super::cascade;

const CHUNK_SIZE: usize = 64 * 1024; // 64 KiB

/// Read all bytes from `reader`, reporting progress to `pb`.
fn read_all(reader: &mut impl Read, pb: &ProgressBar) -> anyhow::Result<Vec<u8>> {
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut data = Vec::new();
    loop {
        let n = reader.read(&mut buf).context("Read error")?;
        if n == 0 { break; }
        data.extend_from_slice(&buf[..n]);
        pb.inc(n as u64);
    }
    Ok(data)
}

/// File format on disk:
///   [32 bytes random salt][16 bytes IV derived from master_key+salt][ciphertext]
pub fn encrypt_file(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    master_key: &str,
    algorithm: CipherAlgorithm,
    pb: &ProgressBar,
) -> anyhow::Result<()> {
    let mut salt = [0u8; SALT_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);

    let key = derive_key(password, &salt);
    let iv  = derive_iv(master_key, &salt);

    let mut input = File::open(input_path).context("Cannot open input file")?;
    pb.set_length(input.metadata().map(|m| m.len()).unwrap_or(0));

    let plaintext  = read_all(&mut input, pb)?;
    let ciphertext = cascade::encrypt(&plaintext, &key, &iv, algorithm);

    let mut output = File::create(output_path).context("Cannot create output file")?;
    output.write_all(&salt).context("Cannot write salt")?;
    output.write_all(&iv).context("Cannot write IV")?;
    output.write_all(&ciphertext).context("Cannot write ciphertext")?;

    pb.finish_and_clear();
    Ok(())
}

/// Reads and validates the file header (salt + IV), then decrypts.
pub fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    master_key: &str,
    algorithm: CipherAlgorithm,
    pb: &ProgressBar,
) -> anyhow::Result<()> {
    let mut input = File::open(input_path).context("Cannot open input file")?;
    pb.set_length(input.metadata().map(|m| m.len()).unwrap_or(0));

    let mut salt = [0u8; SALT_SIZE];
    let mut iv   = [0u8; IV_SIZE];
    input.read_exact(&mut salt)
        .context("Cannot read salt — file may be corrupted or was not encrypted by ATE")?;
    input.read_exact(&mut iv)
        .context("Cannot read IV — file may be corrupted")?;
    pb.inc((SALT_SIZE + IV_SIZE) as u64);

    // Verify master key before deriving the actual encryption key
    let expected_iv = derive_iv(master_key, &salt);
    if iv != expected_iv {
        anyhow::bail!("Wrong master key or corrupted file");
    }

    let key = derive_key(password, &salt);
    let ciphertext = read_all(&mut input, pb)?;
    let plaintext  = cascade::decrypt(&ciphertext, &key, &iv, algorithm)?;

    let mut output = File::create(output_path).context("Cannot create output file")?;
    output.write_all(&plaintext).context("Cannot write plaintext")?;

    pb.finish_and_clear();
    Ok(())
}
