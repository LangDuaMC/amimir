use std::env;

use base64_simd::URL_SAFE_NO_PAD;
use clap::Parser;
use sha2::{Digest, Sha256};

/// Simple CLI to generate a signed value from a private key and user ID.
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// The private key to use for signing
    #[arg(short, long)]
    private_key: Option<String>,

    /// The user ID to be signed
    #[arg(short, long)]
    user_id: String,
}

fn main() {
    let _ = dotenvy::dotenv();
    let args = Cli::parse();
    let keys = args.private_key.or_else(|| env::var("PRIVATE_KEY").ok());
    let signature = generate_signature(&keys.expect("No private key specified. no PRIVATE_KEY in env file or environment, or --private-key flag"), &args.user_id);
    println!("{}", signature);
}

/// Generates a signature by hashing the concatenation of the private key and user ID using SHA-256
/// and then encoding the resulting hash in base64.
fn generate_signature(private_key: &str, user_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(private_key.as_bytes());
    hasher.update(user_id.as_bytes());
    let hash_result = hasher.finalize();
    URL_SAFE_NO_PAD.encode_to_string(hash_result)
}
