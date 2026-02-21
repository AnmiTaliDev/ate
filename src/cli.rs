// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2025 AnmiTaliDev <anmitalidev@nuros.org>

use std::path::PathBuf;
use clap::{Parser, Subcommand};

use crate::models::{CipherAlgorithm, EncryptionParams, OperationMode};

#[derive(Parser)]
#[command(
    name = "ate",
    about = "AnmiTali Encryption — secure file encryption utility",
    version = "1.0.0",
    author = "AnmiTaliDev <anmitalidev@nuros.org>",
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Encrypt a file
    Encrypt {
        /// Input file to encrypt
        #[arg(short, long)]
        input: PathBuf,

        /// Output encrypted file
        #[arg(short, long)]
        output: PathBuf,

        /// Encryption password
        #[arg(short, long)]
        password: String,

        /// Master encryption key
        #[arg(short = 'm', long)]
        master_key: String,

        /// Algorithm [AES, Twofish, Serpent, AES_Twofish, AES_Serpent, Maximum]
        #[arg(short, long, default_value = "Maximum")]
        algorithm: String,
    },

    /// Decrypt a file
    Decrypt {
        /// Input file to decrypt
        #[arg(short, long)]
        input: PathBuf,

        /// Output decrypted file
        #[arg(short, long)]
        output: PathBuf,

        /// Decryption password
        #[arg(short, long)]
        password: String,

        /// Master decryption key
        #[arg(short = 'm', long)]
        master_key: String,

        /// Algorithm [AES, Twofish, Serpent, AES_Twofish, AES_Serpent, Maximum]
        #[arg(short, long, default_value = "Maximum")]
        algorithm: String,
    },
}

impl Cli {
    /// Convert parsed CLI arguments into validated `EncryptionParams`.
    pub fn into_params(self) -> anyhow::Result<EncryptionParams> {
        let params = match self.command {
            Commands::Encrypt { input, output, password, master_key, algorithm } => {
                EncryptionParams {
                    input,
                    output,
                    password,
                    master_key,
                    algorithm: algorithm.parse::<CipherAlgorithm>()?,
                    mode: OperationMode::Encrypt,
                }
            }
            Commands::Decrypt { input, output, password, master_key, algorithm } => {
                EncryptionParams {
                    input,
                    output,
                    password,
                    master_key,
                    algorithm: algorithm.parse::<CipherAlgorithm>()?,
                    mode: OperationMode::Decrypt,
                }
            }
        };
        params.validate()?;
        Ok(params)
    }
}
