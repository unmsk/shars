use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::{BufReader, Read};
use anyhow::Result;
use indicatif::ProgressBar;

pub fn hash_file_sha256(path: &std::path::Path) -> Result<String> {
    hash_file_sha256_with_progress(path, None)
}

pub fn hash_file_sha256_with_progress(path: &std::path::Path, pb: Option<&ProgressBar>) -> Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();

    let mut buffer = [0u8; 65536];
    let mut bytes_read = 0u64;
    
    while let Ok(n) = reader.read(&mut buffer) {
        if n == 0 { break; }
        hasher.update(&buffer[..n]);
        bytes_read += n as u64;
        
        if let Some(progress_bar) = pb {
            progress_bar.set_position(bytes_read);
        }
    }

    Ok(format!("{:x}", hasher.finalize()))
}

pub fn hash_text_sha256(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    format!("{:x}", hasher.finalize())
}
