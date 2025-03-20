use aes::Aes256;
use aes::cipher::{
    BlockDecryptMut, BlockEncryptMut, KeyIvInit, StreamCipher, block_padding::Pkcs7,
};
use aes_gcm::aead::{Aead, AeadInPlace, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Nonce}; // AES-GCM
use cbc::{Decryptor, Encryptor};
use ctr::Ctr128BE;
use hex;
use rand::RngCore;
use rsa::{RsaPrivateKey, RsaPublicKey, oaep::Oaep};
use sha2::Sha256;

fn main() {
    let key = [0x00; 32]; // 256-bit AES key
    let plaintext = b"Hello, Testing Encryption!";

    println!("Original Text: {}", String::from_utf8_lossy(plaintext));

    // AES-CBC Mode
    let iv = generate_iv(16);
    let encrypted_cbc = encrypt_aes_cbc::<Encryptor<Aes256>>(&key, &iv, plaintext)
        .expect("AES-CBC encryption failed");
    println!("AES-CBC Ciphertext (hex): {}", hex::encode(&encrypted_cbc));
    let decrypted_cbc = decrypt_aes_cbc::<Decryptor<Aes256>>(&key, &iv, &encrypted_cbc)
        .expect("AES-CBC decryption failed");
    println!(
        "AES-CBC Decrypted: {}",
        String::from_utf8_lossy(&decrypted_cbc)
    );

    // AES-GCM Mode
    let iv_gcm = generate_iv(12);
    let encrypted_gcm =
        encrypt_aes_gcm(&key, &iv_gcm, plaintext).expect("AES-GCM encryption failed");
    println!("AES-GCM Ciphertext (hex): {}", hex::encode(&encrypted_gcm));
    let decrypted_gcm =
        decrypt_aes_gcm(&key, &iv_gcm, &encrypted_gcm).expect("AES-GCM decryption failed");
    println!(
        "AES-GCM Decrypted: {}",
        String::from_utf8_lossy(&decrypted_gcm)
    );

    // AES-CTR Mode
    let counter = generate_iv(16);
    let encrypted_ctr =
        encrypt_aes_ctr(&key, &counter, plaintext).expect("AES-CTR encryption failed");
    println!("AES-CTR Ciphertext (hex): {}", hex::encode(&encrypted_ctr));
    let decrypted_ctr =
        decrypt_aes_ctr(&key, &counter, &encrypted_ctr).expect("AES-CTR decryption failed");
    println!(
        "AES-CTR Decrypted: {}",
        String::from_utf8_lossy(&decrypted_ctr)
    );

    // RSA Encryption Test with OAEP
    let (rsa_pub_key, rsa_priv_key) = generate_rsa_keys();
    let encrypted_rsa = rsa_pub_key
        .encrypt(&mut rand::thread_rng(), Oaep::new::<Sha256>(), plaintext)
        .expect("RSA encryption failed");
    println!("RSA-OAEP Ciphertext (hex): {}", hex::encode(&encrypted_rsa));
    let decrypted_rsa = rsa_priv_key
        .decrypt(Oaep::new::<Sha256>(), &encrypted_rsa)
        .expect("RSA decryption failed");
    println!(
        "RSA-OAEP Decrypted: {}",
        String::from_utf8_lossy(&decrypted_rsa)
    );

    // Hybrid Encryption
    let plaintext = b"Hello, Hybrid Encryption!";
    println!("🔹 Original Text: {}", String::from_utf8_lossy(plaintext));

    // 1️. generate RSA key
    let (rsa_pub_key, rsa_priv_key) = generate_rsa_keys();

    // 2️. generate AES-256-GCM key and IV
    let aes_key = generate_aes_key();
    let iv = generate_iv(12); // GCM 모드에서 12바이트 IV 사용

    // 3️. encrypt(AES-256-GCM) plaintext
    let encrypted_data =
        encrypt_aes_gcm(&aes_key, &iv, plaintext).expect("AES-GCM encryption failed");
    println!(
        "🔐 AES-GCM Encrypted Data: {}",
        hex::encode(&encrypted_data)
    );

    // 4️. encrypt(RSA-OAEP) AES key
    let encrypted_aes_key = rsa_pub_key
        .encrypt(&mut rand::thread_rng(), Oaep::new::<Sha256>(), &aes_key)
        .expect("RSA encryption failed");
    println!(
        "🔑 Encrypted AES Key (RSA-OAEP): {}",
        hex::encode(&encrypted_aes_key)
    );

    // 5️. decrypt(RSA-OAEP) AES key
    let decrypted_aes_key = rsa_priv_key
        .decrypt(Oaep::new::<Sha256>(), &encrypted_aes_key)
        .expect("RSA decryption failed");

    // 6️. decrypt(AES-256-GCM) plaintext
    let decrypted_data = decrypt_aes_gcm(&decrypted_aes_key, &iv, &encrypted_data)
        .expect("AES-GCM decryption failed");
    println!(
        "🔓 Decrypted Data: {}",
        String::from_utf8_lossy(&decrypted_data)
    );
}

fn generate_aes_key() -> Vec<u8> {
    let mut key = vec![0u8; 32]; // AES-256 (256-bit = 32 bytes)
    OsRng.fill_bytes(&mut key);
    key
}

// Function to generate a random IV (Nonce)
fn generate_iv(size: usize) -> Vec<u8> {
    let mut iv = vec![0u8; size];
    OsRng.fill_bytes(&mut iv);
    iv
}

// AES-CBC Encryption
fn encrypt_aes_cbc<C: BlockEncryptMut + KeyIvInit>(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher = C::new_from_slices(key, iv).map_err(|_| "Invalid key/IV".to_string())?;
    Ok(cipher.encrypt_padded_vec_mut::<Pkcs7>(data))
}

// AES-CBC Decryption
fn decrypt_aes_cbc<C: BlockDecryptMut + KeyIvInit>(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher = C::new_from_slices(key, iv).map_err(|_| "Invalid key/IV".to_string())?;
    cipher
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| "Decryption failed".to_string())
}

// AES-GCM Encryption
fn encrypt_aes_gcm(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "Invalid key".to_string())?;
    let nonce = Nonce::from_slice(iv);
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: data,
                aad: b"",
            },
        )
        .map_err(|_| "Encryption failed".to_string())
}

// AES-GCM Decryption
fn decrypt_aes_gcm(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "Invalid key".to_string())?;
    let nonce = Nonce::from_slice(iv);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: b"",
            },
        )
        .map_err(|_| "Decryption failed".to_string())
}

// AES-CTR Encryption
fn encrypt_aes_ctr(key: &[u8], counter: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let mut cipher = Ctr128BE::<Aes256>::new_from_slices(key, counter)
        .map_err(|_| "Invalid key/counter".to_string())?;
    let mut ciphertext = data.to_vec();
    cipher.apply_keystream(&mut ciphertext);
    Ok(ciphertext)
}

// AES-CTR Decryption (Same as Encryption)
fn decrypt_aes_ctr(key: &[u8], counter: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    encrypt_aes_ctr(key, counter, ciphertext) // CTR decryption is identical to encryption
}

// RSA Key Generation
fn generate_rsa_keys() -> (RsaPublicKey, RsaPrivateKey) {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate RSA key");
    let pub_key = priv_key.to_public_key();
    (pub_key, priv_key)
}
