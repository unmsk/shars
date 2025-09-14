use anyhow::{Context, Result, bail};
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use encoding_rs::UTF_16LE;

const MAX_FILE_SIZE: u64 = 5 * 1024 * 1024; // 5 MB

pub fn read_sha256_file(file_path: &PathBuf, filename: &str) -> Result<String> {
    let file_metadata = fs::metadata(file_path)
        .with_context(|| format!("Failed to get metadata for file '{}'", filename))?;

    if file_metadata.len() > MAX_FILE_SIZE {
        bail!("cannot process '{}': file exceeds maximum size (5MB)", filename);
    }

    let mut file = File::open(file_path)
        .with_context(|| format!("Failed to open file '{}'", filename))?;
    
    let mut raw_content = Vec::new();
    file.read_to_end(&mut raw_content)
        .with_context(|| format!("Failed to read file '{}'", filename))?;

    if raw_content.is_empty() {
        bail!("cannot process '{}': file is empty", filename);
    }

    if let Ok(utf8_content) = std::str::from_utf8(&raw_content) {
        return Ok(utf8_content.to_string());
    }

    let (utf16_decoded, _, had_errors) = UTF_16LE.decode(&raw_content);
    if had_errors {
        bail!("failed to decode '{}'", filename);
    }

    Ok(utf16_decoded.to_string())
}