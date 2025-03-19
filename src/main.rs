use aes::Aes128;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit, StreamCipher};
use aes_gcm::aead::{Aead, AeadInPlace, KeyInit, OsRng, Payload};
use aes_gcm::{Aes128Gcm, Nonce}; // AES-GCM
use cbc::{Encryptor, Decryptor};
use ctr::Ctr128BE;
use hex;
use rand::RngCore;

fn main() {
    let key = [0x00; 16]; // 128-bit AES key
    let plaintext = b"Hello, AES Encryption!";
    
    println!("Original Text: {}", String::from_utf8_lossy(plaintext));

    // AES-CBC Mode
    let iv = generate_iv(16);
    let encrypted_cbc = encrypt_aes_cbc::<Encryptor<Aes128>>(&key, &iv, plaintext).expect("AES-CBC encryption failed");
    println!("AES-CBC Ciphertext (hex): {}", hex::encode(&encrypted_cbc));
    let decrypted_cbc = decrypt_aes_cbc::<Decryptor<Aes128>>(&key, &iv, &encrypted_cbc).expect("AES-CBC decryption failed");
    println!("AES-CBC Decrypted: {}", String::from_utf8_lossy(&decrypted_cbc));

    // AES-GCM Mode
    let iv_gcm = generate_iv(12);
    let encrypted_gcm = encrypt_aes_gcm(&key, &iv_gcm, plaintext).expect("AES-GCM encryption failed");
    println!("AES-GCM Ciphertext (hex): {}", hex::encode(&encrypted_gcm));
    let decrypted_gcm = decrypt_aes_gcm(&key, &iv_gcm, &encrypted_gcm).expect("AES-GCM decryption failed");
    println!("AES-GCM Decrypted: {}", String::from_utf8_lossy(&decrypted_gcm));

    // AES-CTR Mode
    let counter = generate_iv(16);
    let encrypted_ctr = encrypt_aes_ctr(&key, &counter, plaintext).expect("AES-CTR encryption failed");
    println!("AES-CTR Ciphertext (hex): {}", hex::encode(&encrypted_ctr));
    let decrypted_ctr = decrypt_aes_ctr(&key, &counter, &encrypted_ctr).expect("AES-CTR decryption failed");
    println!("AES-CTR Decrypted: {}", String::from_utf8_lossy(&decrypted_ctr));
}

// Function to generate a random IV (Nonce)
fn generate_iv(size: usize) -> Vec<u8> {
    let mut iv = vec![0u8; size];
    OsRng.fill_bytes(&mut iv);
    iv
}

// AES-CBC Encryption
fn encrypt_aes_cbc<C: BlockEncryptMut + KeyIvInit>(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = C::new_from_slices(key, iv)
        .map_err(|_| "Invalid key/IV".to_string())?;
    Ok(cipher.encrypt_padded_vec_mut::<Pkcs7>(data))
}

// AES-CBC Decryption
fn decrypt_aes_cbc<C: BlockDecryptMut + KeyIvInit>(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = C::new_from_slices(key, iv)
        .map_err(|_| "Invalid key/IV".to_string())?;
    cipher.decrypt_padded_vec_mut::<Pkcs7>(ciphertext).map_err(|_| "Decryption failed".to_string())
}

// AES-GCM Encryption
fn encrypt_aes_gcm(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| "Invalid key".to_string())?;
    let nonce = Nonce::from_slice(iv);
    cipher.encrypt(nonce, Payload { msg: data, aad: b"" }).map_err(|_| "Encryption failed".to_string())
}

// AES-GCM Decryption
fn decrypt_aes_gcm(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| "Invalid key".to_string())?;
    let nonce = Nonce::from_slice(iv);
    cipher.decrypt(nonce, Payload { msg: ciphertext, aad: b"" }).map_err(|_| "Decryption failed".to_string())
}

// AES-CTR Encryption
fn encrypt_aes_ctr(key: &[u8], counter: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let mut cipher = Ctr128BE::<Aes128>::new_from_slices(key, counter).map_err(|_| "Invalid key/counter".to_string())?;
    let mut ciphertext = data.to_vec();
    cipher.apply_keystream(&mut ciphertext);
    Ok(ciphertext)
}

// AES-CTR Decryption (Same as Encryption)
fn decrypt_aes_ctr(key: &[u8], counter: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    encrypt_aes_ctr(key, counter, ciphertext) // CTR decryption is identical to encryption
}
