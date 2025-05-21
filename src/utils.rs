use std::{fs};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;
use colored::Colorize;
use regex_lite::Regex;
use indicatif::{ProgressBar, ProgressStyle};
use crate::read::read_sha256_file;
use crate::error::SharsError;
use encoding_rs::UTF_16LE;

const MAX_FILE_SIZE: u64 = 5 * 1024 * 1024; // 5 MB

pub fn is_file_sha(filepath: &PathBuf) -> bool {
    let metadata = match fs::metadata(filepath) {
        Ok(metadata) => metadata,
        Err(_) => return false,
    };

    if metadata.len() > MAX_FILE_SIZE || metadata.len() == 0 {
        return false;
    }

    let ext = filepath.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase());

    if !matches!(ext.as_deref(), Some("sha256") | Some("txt") | Some("checksum") | Some("checksums")) {
        return false;
    }

    let mut file = match File::open(filepath) {
        Ok(file) => file,
        Err(_) => return false,
    };

    let mut bom = [0u8; 2];
    if file.read_exact(&mut bom).is_ok() && bom[0] == 0xFF && bom[1] == 0xFE {
        let mut buffer = Vec::new();
        if file.read_to_end(&mut buffer).is_err() {
            return false;
        }
        let (utf16_decoded, _, had_errors) = UTF_16LE.decode(&buffer);
        if had_errors {
            return false;
        }
        let content = utf16_decoded.into_owned();
        let sha256_regex = Regex::new(r"(?m)^[0-9a-fA-F]{64}\s+").unwrap();
        
        for line in content.lines().take(10) {
            if sha256_regex.is_match(line) {
                return true;
            }
        }
    } else {
        let file = match File::open(filepath) {
            Ok(file) => file,
            Err(_) => return false,
        };
        let reader = BufReader::new(file);
        let sha256_regex = Regex::new(r"^[0-9a-fA-F]{64}\s+").unwrap();
        
        for line in reader.lines().take(10) {
            if let Ok(line) = line {
                if sha256_regex.is_match(&line) {
                    return true;
                }
            }
        }
    }

    false
}

pub fn return_checksum(file_path: &PathBuf, shortened_filename: &str, checksum_1: &str) -> Result<String, SharsError> {
    let content = read_sha256_file(file_path, shortened_filename)?;
    let re = Regex::new(&format!(
        r"\b{}[0-9a-fA-F]{{{}}}\b",
        regex_lite::escape(checksum_1),
        64 - checksum_1.len()
    )).map_err(|e| SharsError::ChecksumError(format!("Failed to create regex pattern: {}", e)))?;

    if let Some(mat) = re.find(&content) {
        return Ok(mat.as_str().trim().to_string());
    }
    
    let re_any = Regex::new(r"\b[0-9a-fA-F]{64}\b")
        .map_err(|e| SharsError::ChecksumError(format!("Failed to create regex pattern: {}", e)))?;
    
    if let Some(mat) = re_any.find(&content) {
        return Ok(mat.as_str().trim().to_string());
    }

    Err(SharsError::ChecksumError("No valid checksum found in file".to_string()))
}

pub fn highlight_differences(a: &str, b: &str) -> String {
    let max_len = std::cmp::max(a.len(), b.len());
    let a_padded = format!("{:width$}", a, width = max_len);
    let b_padded = format!("{:width$}", b, width = max_len);
    let mut squiggles = String::new();
    for (char_a, char_b) in a_padded.chars().zip(b_padded.chars()) {
        if char_a == char_b {
            squiggles.push(' ');
        } else {
            squiggles.push_str(&"~".truecolor(173, 127, 172).to_string());
        }
    }

    squiggles
}

pub fn start_spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new(0);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{msg}\n[{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec})")
            .unwrap()
            .progress_chars("#>-")
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(100));
    pb
}

pub fn strip_prefix<'a>(full_path: &'a Path, base_path: &Path) -> &'a Path {
    full_path.strip_prefix(base_path).unwrap_or(full_path)
}

pub fn shorten_str(file_name: &str, max_len: usize) -> String {
    if file_name.len() > max_len {
        let start = &file_name[..9];
        let end = &file_name[file_name.len() - 9..];
        format!("{}...{}", start, end)
    } else {
        file_name.to_string()
    }
}

pub fn parse_path(s: &str) -> Result<PathBuf, SharsError> {
    let clean_str = s.trim_matches('"').trim_matches('\'');
    if clean_str.len() == 64 && clean_str.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(PathBuf::from(clean_str));
    }
    let path_buf = PathBuf::from(clean_str);
    if !path_buf.exists() {
        return Err(SharsError::InvalidPath(format!("file '{}' not found", clean_str)));
    }

    Ok(path_buf)
}