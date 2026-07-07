use aes::Aes256;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use cbc::Decryptor;
use cbc::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};
use ring::{hkdf, hmac, pbkdf2};
use std::num::NonZeroU32;

type Aes256CbcDec = Decryptor<Aes256>;

/// Derive the 256-bit Master Key from password and email using PBKDF2-HMAC-SHA256
pub fn derive_master_key_pbkdf2(
    password: &str,
    email: &str,
    iterations: u32,
) -> Result<[u8; 32], String> {
    let non_zero_iter = NonZeroU32::new(iterations)
        .ok_or_else(|| "PBKDF2 iterations count cannot be zero".to_string())?;

    let mut master_key = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        non_zero_iter,
        email.to_lowercase().as_bytes(),
        password.as_bytes(),
        &mut master_key,
    );

    Ok(master_key)
}

/// Derive the 256-bit Master Key from password and email using Argon2id
pub fn derive_master_key_argon2(
    password: &str,
    email: &str,
    iterations: u32,
    memory_mb: u32,
    parallelism: u32,
) -> Result<[u8; 32], String> {
    // Argon2 parameters expect memory in KiB, so multiply by 1024
    let memory_kib = memory_mb * 1024;

    let params = Params::new(
        memory_kib,
        iterations,
        parallelism,
        Some(32), // 32-byte (256-bit) key
    )
    .map_err(|e| format!("Invalid Argon2 KDF parameters: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut master_key = [0u8; 32];

    use ring::digest;
    let email_hash = digest::digest(&digest::SHA256, email.to_lowercase().as_bytes());

    argon2
        .hash_password_into(
            password.as_bytes(),
            email_hash.as_ref(),
            &mut master_key,
        )
        .map_err(|e| format!("Argon2 key derivation failed: {}", e))?;

    Ok(master_key)
}

/// Derive the Login Hash sent to the server for authentication
pub fn derive_login_hash(master_key: &[u8], password: &str) -> String {
    let mut login_hash = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(1).unwrap(),
        password.as_bytes(),
        master_key,
        &mut login_hash,
    );

    BASE64_STANDARD.encode(login_hash)
}

/// Derive the Stretched Master Key (split into 256-bit enc_key and 256-bit mac_key) using HKDF-SHA256
pub fn derive_stretched_key(master_key: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    // HKDF Extract is bypassed because Master Key is already high-entropy.
    let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, master_key);

    // Expand for Encryption Key
    let okm_enc = prk
        .expand(&[b"enc"], hkdf::HKDF_SHA256)
        .map_err(|e| format!("HKDF encryption key expansion failed: {}", e))?;
    let mut enc_key = [0u8; 32];
    okm_enc
        .fill(&mut enc_key)
        .map_err(|e| format!("Failed to fill HKDF encryption key: {}", e))?;

    // Expand for MAC Key
    let okm_mac = prk
        .expand(&[b"mac"], hkdf::HKDF_SHA256)
        .map_err(|e| format!("HKDF MAC key expansion failed: {}", e))?;
    let mut mac_key = [0u8; 32];
    okm_mac
        .fill(&mut mac_key)
        .map_err(|e| format!("Failed to fill HKDF MAC key: {}", e))?;

    Ok((enc_key, mac_key))
}

/// Decrypts a Bitwarden CipherString formatted as `encType.iv|ciphertext|mac` or `encType.ciphertext|mac`
pub fn decrypt_cipher_string(
    cipher_string: &str,
    enc_key: &[u8],
    mac_key: &[u8],
) -> Result<Vec<u8>, String> {
    // Parse parts
    let parts: Vec<&str> = cipher_string.split('.').collect();
    if parts.len() < 2 {
        return Err("Invalid CipherString: Missing encType prefix".to_string());
    }

    let enc_type: u32 = parts[0]
        .parse()
        .map_err(|_| "Invalid encryption type prefix".to_string())?;

    let data_parts: Vec<&str> = parts[1].split('|').collect();

    match enc_type {
        0 => {
            // Aes256_Cbc_NotApproved: No MAC. Format could be iv|ciphertext or just ciphertext
            if data_parts.len() == 2 {
                let iv = BASE64_STANDARD
                    .decode(data_parts[0])
                    .map_err(|e| format!("Failed to decode IV: {}", e))?;
                let ciphertext = BASE64_STANDARD
                    .decode(data_parts[1])
                    .map_err(|e| format!("Failed to decode ciphertext: {}", e))?;
                decrypt_aes_cbc(&enc_key[0..32], &iv, &ciphertext)
            } else if data_parts.len() == 1 {
                // If no IV is present, the IV is assumed to be empty (all zeros) or prepended to the ciphertext
                let ciphertext = BASE64_STANDARD
                    .decode(data_parts[0])
                    .map_err(|e| format!("Failed to decode ciphertext: {}", e))?;
                if ciphertext.len() < 16 {
                    return Err("Ciphertext too short".to_string());
                }
                let iv = vec![0u8; 16];
                decrypt_aes_cbc(&enc_key[0..32], &iv, &ciphertext)
            } else {
                Err("Unsupported Aes256_Cbc_NotApproved format".to_string())
            }
        }
        1 | 2 => {
            // Aes256_Cbc_Hmac_Sha256_B64: Format: iv|ciphertext|mac
            if data_parts.len() < 3 {
                return Err("Missing IV, ciphertext, or MAC in CipherString".to_string());
            }

            let iv = BASE64_STANDARD
                .decode(data_parts[0])
                .map_err(|e| format!("Failed to decode IV: {}", e))?;
            let ciphertext = BASE64_STANDARD
                .decode(data_parts[1])
                .map_err(|e| format!("Failed to decode ciphertext: {}", e))?;
            let mac = BASE64_STANDARD
                .decode(data_parts[2])
                .map_err(|e| format!("Failed to decode MAC: {}", e))?;

            // 1. Verify HMAC-SHA256
            // HMAC data is: iv + ciphertext
            let mut mac_data = Vec::with_capacity(iv.len() + ciphertext.len());
            mac_data.extend_from_slice(&iv);
            mac_data.extend_from_slice(&ciphertext);

            let s_key = hmac::Key::new(hmac::HMAC_SHA256, mac_key);
            if hmac::verify(&s_key, &mac_data, &mac).is_err() {
                return Err(
                    "HMAC verification failed. The ciphertext might have been tampered with."
                        .to_string(),
                );
            }

            // 2. Decrypt
            decrypt_aes_cbc(&enc_key[0..32], &iv, &ciphertext)
        }
        _ => Err(format!("Unsupported encryption type: {}", enc_type)),
    }
}

/// Decrypt raw AES-256-CBC ciphertext using the given key and IV
fn decrypt_aes_cbc(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err(format!(
            "Invalid AES-256 key length: {} (expected 32)",
            key.len()
        ));
    }
    if iv.len() != 16 {
        return Err(format!("Invalid AES IV length: {} (expected 16)", iv.len()));
    }

    let decryptor = Aes256CbcDec::new_from_slices(key, iv)
        .map_err(|e| format!("Failed to initialize AES decryptor: {:?}", e))?;

    let mut buffer = ciphertext.to_vec();
    let plaintext = decryptor
        .decrypt_padded::<Pkcs7>(&mut buffer)
        .map_err(|e| {
            format!(
                "AES decryption failed (incorrect key or corrupted data): {:?}",
                e
            )
        })?;

    Ok(plaintext.to_vec())
}

/// Decrypts the Protected Symmetric Key (wrapped user key) using the Master Key (stretched via HKDF)
/// Returns the derived symmetric encryption and MAC keys (32 bytes each)
pub fn decrypt_symmetric_key(
    master_key: &[u8],
    wrapped_key: &str,
) -> Result<([u8; 32], [u8; 32]), String> {
    // 1. Stretch Master Key using HKDF
    let (stretched_enc, stretched_mac) = derive_stretched_key(master_key)?;

    // 2. Decrypt wrapped symmetric key using stretched keys
    let decrypted_bytes = decrypt_cipher_string(wrapped_key, &stretched_enc, &stretched_mac)?;

    if decrypted_bytes.len() != 64 {
        return Err(format!(
            "Decrypted symmetric key has invalid length: {} (expected 64)",
            decrypted_bytes.len()
        ));
    }

    let mut enc_key = [0u8; 32];
    let mut mac_key = [0u8; 32];
    enc_key.copy_from_slice(&decrypted_bytes[0..32]);
    mac_key.copy_from_slice(&decrypted_bytes[32..64]);

    Ok((enc_key, mac_key))
}

/// Decrypts RSA-OAEP with SHA-1
pub fn decrypt_rsa_oaep_sha1(priv_key_der: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;
    let priv_key = RsaPrivateKey::from_pkcs8_der(priv_key_der)
        .map_err(|e| format!("Failed to parse RSA private key from PKCS#8 DER: {}", e))?;
    
    let padding = rsa::Oaep::new::<sha1::Sha1>();
    priv_key.decrypt(padding, ciphertext)
        .map_err(|e| format!("RSA-OAEP-SHA1 decryption failed: {}", e))
}

/// Decrypts RSA-OAEP with SHA-256
pub fn decrypt_rsa_oaep_sha256(priv_key_der: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;
    let priv_key = RsaPrivateKey::from_pkcs8_der(priv_key_der)
        .map_err(|e| format!("Failed to parse RSA private key from PKCS#8 DER: {}", e))?;
    
    let padding = rsa::Oaep::new::<sha2::Sha256>();
    priv_key.decrypt(padding, ciphertext)
        .map_err(|e| format!("RSA-OAEP-SHA256 decryption failed: {}", e))
}

/// Generates a PKCE code verifier (base64url unpadded) and its SHA-256 code challenge (base64url unpadded)
pub fn generate_pkce_pair() -> (String, String) {
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use ring::rand::{SecureRandom, SystemRandom};
    use ring::digest;

    let rand_gen = SystemRandom::new();
    let mut verifier_bytes = [0u8; 32];
    let _ = rand_gen.fill(&mut verifier_bytes);
    
    let code_verifier = BASE64_URL_SAFE_NO_PAD.encode(verifier_bytes);
    
    let sha256_hash = digest::digest(&digest::SHA256, code_verifier.as_bytes());
    let code_challenge = BASE64_URL_SAFE_NO_PAD.encode(sha256_hash.as_ref());
    
    (code_verifier, code_challenge)
}

/// Securely prompts the user for their master password in the terminal
pub fn prompt_master_password(custom_prompt: Option<&str>) -> Result<String, String> {
    let prompt = custom_prompt.unwrap_or("Master Password: ");
    rpassword::prompt_password(prompt)
        .map_err(|e| format!("Password prompt failed: {}", e))
}

/// Securely prompts the user for their password (if not already provided) and derives the 256-bit Master Key.
pub fn prompt_and_derive_master_key(
    password_arg: Option<String>,
    email: &str,
    kdf_type: u32,
    iterations: u32,
    memory: Option<u32>,
    parallelism: Option<u32>,
    prompt_msg: Option<&str>,
) -> Result<[u8; 32], String> {
    let password = match password_arg {
        Some(pass) => pass,
        None => prompt_master_password(prompt_msg)?,
    };

    match kdf_type {
        0 => derive_master_key_pbkdf2(&password, email, iterations),
        1 => {
            let mem = memory.ok_or_else(|| {
                "Argon2 memory parameter missing from KDF settings".to_string()
            })?;
            let para = parallelism.ok_or_else(|| {
                "Argon2 parallelism parameter missing from KDF settings".to_string()
            })?;
            derive_master_key_argon2(&password, email, iterations, mem, para)
        }
        t => Err(format!("Unsupported KDF type: {}", t)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2_derivation() {
        let password = "masterpassword123";
        let email = "test@example.com";
        let iterations = 5000;
        let master_key = derive_master_key_pbkdf2(password, email, iterations).unwrap();
        assert_eq!(master_key.len(), 32);

        // Derive login hash
        let login_hash = derive_login_hash(&master_key, password);
        assert!(!login_hash.is_empty());
    }

    #[test]
    fn test_argon2_derivation() {
        let password = "masterpassword123";
        let email = "test@example.com";
        let iterations = 2;
        let memory_mb = 8;
        let parallelism = 1;
        let master_key = derive_master_key_argon2(password, email, iterations, memory_mb, parallelism).unwrap();
        assert_eq!(master_key.len(), 32);
    }

    #[test]
    fn test_aes_cbc_decryption_error() {
        let key = [0u8; 32];
        let res = decrypt_symmetric_key(&key, "invalid_cipher_string");
        assert!(res.is_err());
    }
}
