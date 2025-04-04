# AnmiTali Encrypter (ATE)

Simple and secure Linux file encryption utility with support for AES, Twofish, and Serpent algorithms, including cascade encryption.

## Features

- AES-256 encryption
- Twofish encryption
- Serpent encryption 
- Cascade encryption support
- Linux command-line interface
- Memory-safe implementation

## Build

```bash
# Clone repository
git clone https://github.com/AnmiTaliDev/ate.git
cd ate

# Make build script executable
chmod +x build/build.sh

# Build project
./build/build.sh

# Install system-wide (optional)
sudo ./build/build.sh --target=Install
```

## Usage

```bash
# Encrypt file
ate encrypt -i file.txt -o file.enc -p mypassword -m masterkey -a AES

# Decrypt file
ate decrypt -i file.enc -o file.txt -p mypassword -m masterkey

# Show help
ate --help
```

## Algorithms

- AES: Standard AES-256 encryption
- Twofish: Strong block cipher
- Serpent: Alternative to AES
- Cascade: AES+Twofish, AES+Serpent, or AES+Twofish+Serpent

## Build Info
- Builder: AnmiTaliDev

## License

Mozilla Public License 2.0