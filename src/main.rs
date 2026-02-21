// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2025 AnmiTaliDev <anmitalidev@nuros.org>

mod cli;
mod crypto;
mod models;
mod progress;

use clap::Parser;
use models::OperationMode;

fn run() -> anyhow::Result<()> {
    let params = cli::Cli::parse().into_params()?;
    let pb = progress::make();

    match params.mode {
        OperationMode::Encrypt => {
            crypto::encrypt_file(&params.input, &params.output, &params.password, &params.master_key, params.algorithm, &pb)?;
            println!("Done! Encrypted → {}", params.output.display());
        }
        OperationMode::Decrypt => {
            crypto::decrypt_file(&params.input, &params.output, &params.password, &params.master_key, params.algorithm, &pb)?;
            println!("Done! Decrypted → {}", params.output.display());
        }
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}
