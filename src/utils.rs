use std::{fs};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::Duration;
use colored::Colorize;
use regex_lite::Regex;
use indicatif::{ProgressBar, ProgressStyle};
use crate::read::read_sha256_file;
use crate::error::SharsError;

pub fn is_file_sha(filepath: &PathBuf) -> bool {
    let metadata = match fs::metadata(filepath) {
        Ok(metadata) => metadata,
        Err(_) => return false,
    };

    if metadata.len() > 5 * 1024 * 1024 || metadata.len() == 0 {
        return false;
    }

    let ext = filepath.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase());

    if !matches!(ext.as_deref(), Some("sha256") | Some("sha") | Some("txt")) {
        return false;
    }

    let file = match File::open(filepath) {
        Ok(file) => file,
        Err(_) => return false,
    };

    let mut reader = BufReader::new(file);
    let mut valid_hash_found = false;

    for _ in 0..10 {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let mut parts = line.split_whitespace();
                if let Some(hash_part) = parts.next() {
                    if hash_part.chars().all(|c| c.is_ascii_hexdigit()) {
                        let hash_len = hash_part.len();
                        if hash_len == 40 || hash_len == 64 || hash_len == 128 {
                            valid_hash_found = true;
                            break;
                        }
                    }
                }
            },
            Err(_) => return false,
        }
    }

    valid_hash_found
}

pub fn return_checksum(file_path: &PathBuf, shortened_filename: &str, checksum_1: &str) -> String {
    let content = read_sha256_file(file_path, shortened_filename);
    let re = match Regex::new(&format!(
        r"\b{}[0-9a-fA-F]{{{}}}\b",
        regex_lite::escape(checksum_1),
        64 - checksum_1.len()
    )) {
        Ok(re) => re,
        Err(_) => return String::new()
    };
    if let Ok(content_str) = &content {
        if let Some(mat) = re.find(content_str) {
            return mat.as_str().trim().to_string();
        }
    }
    
    let re_any = Regex::new(r"\b[0-9a-fA-F]{64}\b").unwrap();
    if let Ok(content_str) = &content {
        if let Some(mat) = re_any.find(content_str) {
            return mat.as_str().trim().to_string();
        }
    }

    String::new()
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
    let spinner = ProgressBar::new_spinner();

    let style = ProgressStyle::default_spinner()
        .tick_strings(&["|", "/", "-", "\\"])
        .template("{spinner:.white} {msg}")
        .unwrap();

    spinner.set_style(style);
    spinner.set_message(msg.to_string());
    spinner.enable_steady_tick(Duration::from_millis(100));
    spinner
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