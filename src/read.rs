use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use colored::Colorize;
use encoding_rs::UTF_16LE;
use crate::error::SharsError;

const MAX_FILE_SIZE: u64 = 5 * 1024 * 1024; // 5 MB

pub fn read_sha256_file(file_path: &PathBuf, filename: &str) -> Result<String, SharsError> {
    #[derive(Debug)]
    enum FileContentError {
        Empty,
        TooLarge,
        DecodingFailed,
    }

    impl std::fmt::Display for FileContentError {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            match self {
                Self::Empty => write!(f, "file is empty"),
                Self::TooLarge => write!(f, "file exceeds maximum size (5MB)"),
                Self::DecodingFailed => write!(f, "failed to decode file content"),
            }
        }
    }

    impl std::error::Error for FileContentError {}

    let file_metadata = fs::metadata(file_path)?;

    if file_metadata.len() > MAX_FILE_SIZE {
        return Err(SharsError::ChecksumError(format!("cannot process '{}': file exceeds maximum size (5MB)", filename)));
    }

    let mut file = File::open(file_path)?;
    let mut raw_content = Vec::new();
    file.read_to_end(&mut raw_content)?;

    if raw_content.is_empty() {
        return Err(SharsError::ChecksumError(format!("cannot process '{}': file is empty", filename)));
    }

    if let Ok(utf8_content) = std::str::from_utf8(&raw_content) {
        return Ok(utf8_content.to_string());
    }

    let (utf16_decoded, _, had_errors) = UTF_16LE.decode(&raw_content);
    if had_errors {
        return Err(SharsError::ChecksumError(format!("failed to decode '{}'", filename)));
    }

    Ok(utf16_decoded.to_string())
}