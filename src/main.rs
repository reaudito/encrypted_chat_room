use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // AES-GCM
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use x25519_dalek::{EphemeralSecret, PublicKey};

// Room message encrypted with symmetric key
fn encrypt_room_message(msg: &[u8], sym_key: &Key<Aes256Gcm>) -> Vec<u8> {
    let cipher = Aes256Gcm::new(sym_key);
    let nonce = Nonce::from_slice(b"unique nonce"); // must be 12 bytes, use random in real app
    cipher.encrypt(nonce, msg).expect("encryption failed")
}

// Decrypt room message
fn decrypt_room_message(ciphertext: &[u8], sym_key: &Key<Aes256Gcm>) -> Vec<u8> {
    let cipher = Aes256Gcm::new(sym_key);
    let nonce = Nonce::from_slice(b"unique nonce");
    cipher
        .decrypt(nonce, ciphertext)
        .expect("decryption failed")
}

// Ticket sent to each user (permitted users only)
#[derive(Debug, Serialize, Deserialize)]
struct AccessTicket {
    room_address: String,
    encrypted_keys: HashMap<String, String>, // pubkey_base64 -> encrypted AES key (base64)
}

// Encrypt AES room key per participant
fn encrypt_room_key_for_participant(
    room_key: &[u8],
    participant_pubkey: &PublicKey,
    sender_secret: EphemeralSecret,
) -> Vec<u8> {
    let shared_secret = sender_secret.diffie_hellman(participant_pubkey);
    println!("Shared secret: {:?}", shared_secret.as_bytes());
    let shared_key = Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes());
    let cipher = Aes256Gcm::new(shared_key);
    let nonce = Nonce::from_slice(b"keynonce1234");
    cipher.encrypt(nonce, room_key).expect("encrypt room key")
}

fn decrypt_room_key(
    encrypted: &[u8],
    sender_pub: &PublicKey,
    receiver_secret: EphemeralSecret,
) -> Vec<u8> {
    let shared_secret = receiver_secret.diffie_hellman(sender_pub);
    println!("Shared secret: {:?}", shared_secret.as_bytes());
    let shared_key = Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes());
    let cipher = Aes256Gcm::new(shared_key);
    let nonce = Nonce::from_slice(b"keynonce1234");
    let decrypted = cipher.decrypt(nonce, encrypted).expect("decrypt room key");
    decrypted
}

fn main() {
    // ==== Setup ====

    // Generate sender keypair (could be room creator)
    let room_creator_secret = EphemeralSecret::random_from_rng(OsRng);
    let room_create_public = PublicKey::from(&room_creator_secret);

    // Generate participant keypair
    let participant_1_secret = EphemeralSecret::random_from_rng(OsRng);
    let participant_1_public = PublicKey::from(&participant_1_secret);

    // Generate room AES key
    let room_key = Aes256Gcm::generate_key(OsRng);

    let room_key_vec = room_key.to_vec();
    println!("Room Key: {:?}", room_key_vec);

    // Encrypt AES room key for participant
    let encrypted_key =
        encrypt_room_key_for_participant(&room_key, &participant_1_public, room_creator_secret);

    // === Create Access Ticket ===
    let mut ticket = AccessTicket {
        room_address: "iroh://abcdef123456".into(),
        encrypted_keys: HashMap::new(),
    };

    let participant_pub_b64 = STANDARD.encode(participant_1_public.as_bytes());
    ticket
        .encrypted_keys
        .insert(participant_pub_b64.clone(), STANDARD.encode(&encrypted_key));

    println!(
        "🔑 Access Ticket (JSON):\n{}",
        serde_json::to_string_pretty(&ticket).unwrap()
    );

    let decrypted_room_key =
        decrypt_room_key(&encrypted_key, &room_create_public, participant_1_secret);
    println!(
        "✅ Decrypted room key matches original {:?}, {:?}",
        decrypted_room_key, decrypted_room_key
    );
    assert_eq!(&decrypted_room_key, &decrypted_room_key);

    // === Chat Message Encryption ===
    let msg = b"Hello, Iroh secure world!";
    let ciphertext = encrypt_room_message(msg, &room_key);
    let plaintext = decrypt_room_message(&ciphertext, &room_key);
    assert_eq!(msg.to_vec(), plaintext);
    println!(
        "✅ Message decrypted: {}",
        String::from_utf8_lossy(&plaintext)
    );
}
