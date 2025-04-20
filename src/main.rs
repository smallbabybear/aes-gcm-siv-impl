//! CLI for AES-GCM-SIV encryption and decryption operations

#![forbid(unsafe_code)]

use aes_gcm_siv_impl::{decrypt, encrypt, NONCE_LENGTH};
use clap::{Parser, Subcommand};
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    author,
    version,
    about = "AES-GCM-SIV encryption/decryption tool (RFC 8452)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a file
    Encrypt {
        /// Input file to encrypt
        input: PathBuf,

        /// Output file for ciphertext
        output: PathBuf,

        /// Hex-encoded key (32 or 64 characters for 128-bit or 256-bit key)
        #[arg(short, long)]
        key: String,

        /// Hex-encoded nonce (24 characters for 96-bit nonce)
        #[arg(short, long)]
        nonce: Option<String>,

        /// Additional authenticated data
        #[arg(short, long)]
        aad: Option<String>,
    },

    /// Decrypt a file
    Decrypt {
        /// Input file to decrypt
        input: PathBuf,

        /// Output file for plaintext
        output: PathBuf,

        /// Hex-encoded key (32 or 64 characters for 128-bit or 256-bit key)
        #[arg(short, long)]
        key: String,

        /// Hex-encoded nonce (24 characters for 96-bit nonce)
        #[arg(short, long)]
        nonce: String,

        /// Additional authenticated data
        #[arg(short, long)]
        aad: Option<String>,
    },

    /// Generate a random nonce
    GenNonce,
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt {
            input,
            output,
            key,
            nonce,
            aad,
        } => {
            let key_bytes = hex::decode(&key).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Invalid key hex: {}", e),
                )
            })?;

            let nonce_bytes = match nonce {
                Some(n) => hex::decode(&n).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("Invalid nonce hex: {}", e),
                    )
                })?,
                None => {
                    let random_nonce = aes_gcm_siv_impl::generate_nonce();
                    println!("Generated nonce: {}", hex::encode(&random_nonce));
                    random_nonce
                }
            };

            if nonce_bytes.len() != NONCE_LENGTH {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Nonce must be exactly {} bytes", NONCE_LENGTH),
                ));
            }

            let aad_bytes = aad.as_deref().unwrap_or("").as_bytes();
            let mut plaintext = Vec::new();
            fs::File::open(&input)?.read_to_end(&mut plaintext)?;

            let ciphertext = encrypt(&key_bytes, &nonce_bytes, &plaintext, aad_bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

            fs::write(&output, ciphertext)?;
            println!("Encrypted {} -> {}", input.display(), output.display());
            Ok(())
        }

        Commands::Decrypt {
            input,
            output,
            key,
            nonce,
            aad,
        } => {
            let key_bytes = hex::decode(&key).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Invalid key hex: {}", e),
                )
            })?;

            let nonce_bytes = hex::decode(&nonce).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Invalid nonce hex: {}", e),
                )
            })?;

            if nonce_bytes.len() != NONCE_LENGTH {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Nonce must be exactly {} bytes", NONCE_LENGTH),
                ));
            }

            let aad_bytes = aad.as_deref().unwrap_or("").as_bytes();
            let mut ciphertext = Vec::new();
            fs::File::open(&input)?.read_to_end(&mut ciphertext)?;

            let plaintext = decrypt(&key_bytes, &nonce_bytes, &ciphertext, aad_bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

            fs::write(&output, plaintext)?;
            println!("Decrypted {} -> {}", input.display(), output.display());
            Ok(())
        }

        Commands::GenNonce => {
            let nonce = aes_gcm_siv_impl::generate_nonce();
            println!("{}", hex::encode(&nonce));
            Ok(())
        }
    }
}
