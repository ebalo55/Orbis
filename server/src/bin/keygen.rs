use plugin_api::{SigningKeyPair};
use std::fs;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 4 {
        eprintln!("Usage: keygen <private_key_file> <public_key_file> <label>");
        std::process::exit(1);
    }

    let private_key_file = &args[1];
    let public_key_file = &args[2];
    let label = &args[3];

    println!("Generating Ed25519 key pair for: {}", label);

    // Generate key pair
    let keypair = SigningKeyPair::generate();

    // Save private key (hex-encoded)
    let private_hex = keypair.private_key_hex();
    fs::write(private_key_file, &private_hex)
        .expect("Failed to write private key file");

    // Save public key (hex-encoded)
    let public_hex = keypair.public_key_hex();
    fs::write(public_key_file, &public_hex)
        .expect("Failed to write public key file");

    println!("✓ Key pair generated successfully");
    println!("  Public key: {}", public_hex);
    println!("  Label: {}", label);
}

