// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2025 AnmiTaliDev <anmitalidev@nuros.org>

use std::path::PathBuf;
use std::str::FromStr;
use anyhow::anyhow;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherAlgorithm {
    Aes,
    Twofish,
    Serpent,
    AesTwofish,
    AesSerpent,
    Maximum,
}

impl FromStr for CipherAlgorithm {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "aes"         => Ok(Self::Aes),
            "twofish"     => Ok(Self::Twofish),
            "serpent"     => Ok(Self::Serpent),
            "aes_twofish" => Ok(Self::AesTwofish),
            "aes_serpent" => Ok(Self::AesSerpent),
            "maximum"     => Ok(Self::Maximum),
            other => Err(anyhow!(
                "Unknown algorithm: {other}. Supported: AES, Twofish, Serpent, AES_Twofish, AES_Serpent, Maximum"
            )),
        }
    }
}

impl std::fmt::Display for CipherAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Aes        => "AES",
            Self::Twofish    => "Twofish",
            Self::Serpent    => "Serpent",
            Self::AesTwofish => "AES_Twofish",
            Self::AesSerpent => "AES_Serpent",
            Self::Maximum    => "Maximum",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationMode {
    Encrypt,
    Decrypt,
}

#[derive(Debug)]
pub struct EncryptionParams {
    pub input:      PathBuf,
    pub output:     PathBuf,
    pub password:   String,
    pub master_key: String,
    pub algorithm:  CipherAlgorithm,
    pub mode:       OperationMode,
}

impl EncryptionParams {
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.input.exists() {
            anyhow::bail!("Input file not found: {}", self.input.display());
        }
        if !self.input.is_file() {
            anyhow::bail!("Input path is not a file: {}", self.input.display());
        }
        if let Some(parent) = self.output.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                anyhow::bail!("Output directory does not exist: {}", parent.display());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- CipherAlgorithm::from_str ---

    #[test]
    fn parse_all_algorithms() {
        let cases = [
            ("AES",         CipherAlgorithm::Aes),
            ("aes",         CipherAlgorithm::Aes),
            ("Twofish",     CipherAlgorithm::Twofish),
            ("TWOFISH",     CipherAlgorithm::Twofish),
            ("Serpent",     CipherAlgorithm::Serpent),
            ("SERPENT",     CipherAlgorithm::Serpent),
            ("AES_Twofish", CipherAlgorithm::AesTwofish),
            ("aes_twofish", CipherAlgorithm::AesTwofish),
            ("AES_Serpent", CipherAlgorithm::AesSerpent),
            ("aes_serpent", CipherAlgorithm::AesSerpent),
            ("Maximum",     CipherAlgorithm::Maximum),
            ("maximum",     CipherAlgorithm::Maximum),
        ];
        for (s, expected) in cases {
            assert_eq!(s.parse::<CipherAlgorithm>().unwrap(), expected, "failed for: {s}");
        }
    }

    #[test]
    fn parse_unknown_algorithm_fails() {
        assert!("CHACHA20".parse::<CipherAlgorithm>().is_err());
        assert!("".parse::<CipherAlgorithm>().is_err());
    }

    // --- CipherAlgorithm::Display ---

    #[test]
    fn display_roundtrips() {
        let algos = [
            CipherAlgorithm::Aes,
            CipherAlgorithm::Twofish,
            CipherAlgorithm::Serpent,
            CipherAlgorithm::AesTwofish,
            CipherAlgorithm::AesSerpent,
            CipherAlgorithm::Maximum,
        ];
        for algo in algos {
            let s = algo.to_string();
            let parsed = s.parse::<CipherAlgorithm>().unwrap();
            assert_eq!(parsed, algo, "Display roundtrip failed for {s}");
        }
    }

    // --- EncryptionParams::validate ---

    #[test]
    fn validate_missing_input_fails() {
        let params = EncryptionParams {
            input:      PathBuf::from("/tmp/ate_nonexistent_input_file.txt"),
            output:     PathBuf::from("/tmp/ate_output.enc"),
            password:   "pass".into(),
            master_key: "key".into(),
            algorithm:  CipherAlgorithm::Aes,
            mode:       OperationMode::Encrypt,
        };
        assert!(params.validate().is_err());
    }

    #[test]
    fn validate_nonexistent_output_dir_fails() {
        // Create a real input file
        let input = PathBuf::from("/tmp/ate_validate_input.txt");
        std::fs::write(&input, b"data").unwrap();

        let params = EncryptionParams {
            input,
            output:     PathBuf::from("/tmp/ate_no_such_dir_xyz/out.enc"),
            password:   "pass".into(),
            master_key: "key".into(),
            algorithm:  CipherAlgorithm::Aes,
            mode:       OperationMode::Encrypt,
        };
        assert!(params.validate().is_err());
    }

    #[test]
    fn validate_valid_params_ok() {
        let input = PathBuf::from("/tmp/ate_validate_ok_input.txt");
        std::fs::write(&input, b"data").unwrap();

        let params = EncryptionParams {
            input,
            output:     PathBuf::from("/tmp/ate_validate_ok_output.enc"),
            password:   "pass".into(),
            master_key: "key".into(),
            algorithm:  CipherAlgorithm::Maximum,
            mode:       OperationMode::Encrypt,
        };
        assert!(params.validate().is_ok());
    }
}
