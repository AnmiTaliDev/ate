# AnmiTali Encrypter (ATE)

Secure Linux file encryption utility written in Rust. Supports AES-256, Twofish, and Serpent ciphers in CBC mode, including cascade (multi-layer) encryption.

## Features

- AES-256, Twofish, and Serpent ciphers in CBC mode
- Cascade encryption: AES+Twofish, AES+Serpent, AES+Twofish+Serpent
- Per-file random salt (256-bit) — no two encrypted files share the same key material
- PBKDF2-HMAC-SHA256 key derivation with 100 000 iterations
- Master key verified on decryption before any data is processed
- Encryption keys zeroed from memory after use (`zeroize`)
- Progress bar for large files

## File Format

Every encrypted file begins with a fixed-size header:

```
[32 bytes — random salt][16 bytes — IV][ciphertext]
```

The IV is derived from the master key and the random salt via PBKDF2, so it acts as an implicit master-key fingerprint. A wrong master key is detected immediately, before any decryption is attempted.

## Build

Requires Rust 1.75+ and Cargo.

```bash
git clone https://github.com/AnmiTaliDev/ate.git
cd ate
cargo build --release
```

The binary will be at `target/release/ate`. To install system-wide:

```bash
cargo install --path .
```

## Usage

```bash
# Encrypt a file (default algorithm: Maximum)
ate encrypt -i secret.txt -o secret.enc -p <password> -m <master-key>

# Encrypt with a specific algorithm
ate encrypt -i secret.txt -o secret.enc -p <password> -m <master-key> -a AES

# Decrypt a file
ate decrypt -i secret.enc -o secret.txt -p <password> -m <master-key>

# Show help
ate --help
ate encrypt --help
```

## Algorithms

| Value        | Description                              |
|--------------|------------------------------------------|
| `AES`        | AES-256-CBC                              |
| `Twofish`    | Twofish-256-CBC                          |
| `Serpent`    | Serpent-256-CBC                          |
| `AES_Twofish`| AES-256 → Twofish-256 (cascade)         |
| `AES_Serpent`| AES-256 → Serpent-256 (cascade)         |
| `Maximum`    | AES-256 → Twofish-256 → Serpent-256     |

Default is `Maximum`.

## License

Mozilla Public License 2.0. See [LICENSE](LICENSE).
Copyright (c) 2026 AnmiTaliDev <anmitalidev@nuros.org>
