# Hybrid Encryption in Rust
This Rust project demonstrates a hybrid encryption system using AES for data encryption and RSA.

## Features
- AES-256-CBC: Symmetric encryption with Cipher Block Chaining (CBC)
- AES-256-GCM: Secure encryption with authentication
- AES-256-CTR: Counter mode for stream encryption
- RSA-OAEP (2048-bit): Asymmetric encryption for secure key exchange
- Hybrid Encryption: Combines AES-GCM with RSA-OAEP

## Installation
Ensure Rust and Cargo are installed:
```sh
cargo install
```

## Usage
Run the program with:
```sh
cargo run
```
It will execute:
1. AES-256-CBC encryption and decryption
2. AES-256-GCM encryption and decryption
3. AES-256-CTR encryption and decryption
4. RSA-OAEP encryption and decryption
5. Hybrid Encryption (AES-GCM + RSA-OAEP)

## Hybrid Encryption Process
1. Generate RSA key pair
2. Generate AES key
3. Encrypt plaintext using AES
4. Encrypt AES key using RSA
5. Decrypt AES key using RSA
6. Decrypt plaintext using AES