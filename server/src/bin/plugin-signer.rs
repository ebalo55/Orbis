use plugin_api::SigningKeyPair;
use std::fs;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    match args[1].as_str() {
        "sign" => {
            if args.len() != 4 {
                eprintln!("Usage: plugin-signer sign <plugin_file> <private_key_file>");
                std::process::exit(1);
            }
            sign_plugin(&args[2], &args[3]);
        }
        "verify" => {
            if args.len() != 4 {
                eprintln!("Usage: plugin-signer verify <plugin_file> <signature_hex>");
                std::process::exit(1);
            }
            verify_plugin(&args[2], &args[3]);
        }
        _ => {
            print_usage();
            std::process::exit(1);
        }
    }
}

fn print_usage() {
    eprintln!("Plugin Signer Tool");
    eprintln!("");
    eprintln!("Usage: plugin-signer <command> [options]");
    eprintln!("");
    eprintln!("Commands:");
    eprintln!("  sign <plugin> <key_file>     Sign a plugin with private key");
    eprintln!("  verify <plugin> <sig_hex>    Verify a plugin signature");
}

fn sign_plugin(plugin_file: &str, key_file: &str) {
    // Read private key
    let private_hex = fs::read_to_string(key_file)
        .expect("Failed to read private key file");
    let private_hex = private_hex.trim();

    // Load key pair
    let keypair = SigningKeyPair::from_private_key_hex(private_hex)
        .expect("Failed to load private key");

    // Sign the plugin
    let signature = keypair.sign_file(plugin_file)
        .expect("Failed to sign plugin");

    println!("Plugin signed successfully!");
    println!("");
    println!("Signature (hex): {}", signature.to_hex());
    println!("Public key (hex): {}", signature.public_key().to_hex());
    println!("");
    println!("Add this to your TrustedPluginEntry:");
    println!("  signature: PluginSignature::from_hex(");
    println!("    \"{}\",", signature.to_hex());
    println!("    PublicKey::from_hex(\"{}\").unwrap(),", signature.public_key().to_hex());
    println!("  ).unwrap(),");
}

fn verify_plugin(_plugin_file: &str, _signature_hex: &str) {
    // For verification, we need both signature and public key
    // This is a simplified version - in practice, the signature contains the public key
    println!("Note: Full verification requires signature metadata");
    println!("For now, use the plugin security system's validate_plugin method");
    println!("");
    println!("To verify:");
    println!("1. Add the public key to hardcoded_public_keys");
    println!("2. Add the TrustedPluginEntry with signature");
    println!("3. The system will verify on plugin load");
}

