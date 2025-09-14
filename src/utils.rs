use anyhow::{Context, Result, bail};
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;
use colored::Colorize;
use regex_lite::Regex;
use indicatif::{ProgressBar, ProgressStyle};
use crate::read::read_sha256_file;
use encoding_rs::UTF_16LE;

const MAX_FILE_SIZE: u64 = 5 * 1024 * 1024; // 5 MB
const SHA256_PATTERN: &str = r"^[0-9a-fA-F]{64}\s+";
const SHA256_ANY_PATTERN: &str = r"\b[0-9a-fA-F]{64}\b";

pub fn is_file_sha(filepath: &PathBuf) -> bool {
    let metadata = match fs::metadata(filepath) {
        Ok(metadata) => metadata,
        Err(_) => return false,
    };

    if metadata.len() > MAX_FILE_SIZE || metadata.len() == 0 {
        return false;
    }

    if !has_valid_checksum_extension(filepath) {
        return false;
    }

    check_file_content_for_checksums(filepath)
}

fn has_valid_checksum_extension(filepath: &PathBuf) -> bool {
    let ext = filepath.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase());

    matches!(ext.as_deref(), Some("sha256") | Some("txt") | Some("checksum") | Some("checksums"))
}

fn check_file_content_for_checksums(filepath: &PathBuf) -> bool {
    let mut file = match File::open(filepath) {
        Ok(file) => file,
        Err(_) => return false,
    };

    let mut bom = [0u8; 2];
    if file.read_exact(&mut bom).is_ok() && bom[0] == 0xFF && bom[1] == 0xFE {
        check_utf16_content(&mut file)
    } else {
        check_utf8_content(filepath)
    }
}

fn check_utf16_content(file: &mut File) -> bool {
    let mut buffer = Vec::new();
    if file.read_to_end(&mut buffer).is_err() {
        return false;
    }
    
    let (utf16_decoded, _, had_errors) = UTF_16LE.decode(&buffer);
    if had_errors {
        return false;
    }
    
    let content = utf16_decoded.into_owned();
    let Ok(sha256_regex) = Regex::new(SHA256_PATTERN) else { return false };
    
    content.lines().take(10).any(|line| sha256_regex.is_match(line))
}

fn check_utf8_content(filepath: &PathBuf) -> bool {
    let Ok(file) = File::open(filepath) else { return false };
    let reader = BufReader::new(file);
    let Ok(sha256_regex) = Regex::new(SHA256_PATTERN) else { return false };
    
    reader.lines()
        .take(10)
        .filter_map(Result::ok)
        .any(|line| sha256_regex.is_match(&line))
}

pub fn return_checksum(file_path: &PathBuf, shortened_filename: &str, checksum_1: &str) -> Result<String> {
    let content = read_sha256_file(file_path, shortened_filename)
        .with_context(|| format!("Failed to read SHA256 file '{}'", shortened_filename))?;
    
    let pattern = format!(
        r"\b{}[0-9a-fA-F]{{{}}}\b",
        regex_lite::escape(checksum_1),
        64 - checksum_1.len()
    );
    let re = Regex::new(&pattern)
        .context("Failed to compile regex pattern")?;

    if let Some(mat) = re.find(&content) {
        return Ok(mat.as_str().trim().to_string());
    }
    
    let re_any = Regex::new(SHA256_ANY_PATTERN)
        .context("Failed to compile fallback regex pattern")?;
    
    if let Some(mat) = re_any.find(&content) {
        return Ok(mat.as_str().trim().to_string());
    }

    bail!("No valid checksum found in file '{}'", shortened_filename);
}

pub fn highlight_differences(a: &str, b: &str) -> String {
    let max_len = a.len().max(b.len());
    let a_padded = format!("{:width$}", a, width = max_len);
    let b_padded = format!("{:width$}", b, width = max_len);
    
    let diff: String = a_padded.chars()
        .zip(b_padded.chars())
        .map(|(char_a, char_b)| if char_a == char_b { ' ' } else { '~' })
        .collect();

    if diff.trim().is_empty() {
        String::new()
    } else {
        diff.truecolor(173, 127, 172).to_string()
    }
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
    if file_name.len() <= max_len {
        file_name.to_string()
    } else {
        let start = &file_name[..9];
        let end = &file_name[file_name.len() - 9..];
        format!("{}...{}", start, end)
    }
}

pub fn parse_path(s: &str) -> Result<PathBuf> {
    let clean_str = s.trim_matches('"').trim_matches('\'');
    
    if clean_str.len() == 64 && clean_str.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(PathBuf::from(clean_str));
    }
    
    let path_buf = PathBuf::from(clean_str);
    if !path_buf.exists() {
        bail!("file '{}' not found", clean_str);
    }

    Ok(path_buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_shorten_str_short_string() {
        let result = shorten_str("short.txt", 18);
        assert_eq!(result, "short.txt");
    }

    #[test]
    fn test_shorten_str_long_string() {
        let long_name = "this_is_a_very_long_filename_that_exceeds_the_limit.txt";
        let result = shorten_str(long_name, 18);
        assert_eq!(result, "this_is_a...limit.txt");
    }

    #[test]
    fn test_shorten_str_exact_limit() {
        let exact_name = "exactly_18_chars!!";
        let result = shorten_str(exact_name, 18);
        assert_eq!(result, "exactly_18_chars!!");
    }

    #[test]
    fn test_highlight_differences_identical() {
        let result = highlight_differences("abc123", "abc123");
        assert!(!result.contains('~'));
        assert_eq!(result.trim(), "");
    }

    #[test]
    fn test_highlight_differences_different() {
        let result = highlight_differences("abc123", "abd123");
        assert!(result.contains('~'));
    }

    #[test]
    fn test_highlight_differences_different_lengths() {
        let result = highlight_differences("abc", "abcdef");
        assert!(result.len() >= 6);
    }

    #[test]
    fn test_parse_path_checksum() {
        let checksum = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678";
        let result = parse_path(checksum).unwrap();
        assert_eq!(result, PathBuf::from(checksum));
    }

    #[test]
    fn test_parse_path_with_quotes() {
        let checksum = "\"a1b2c3d4e5f67890123456789012345678901234567890123456789012345678\"";
        let result = parse_path(checksum).unwrap();
        assert_eq!(result, PathBuf::from("a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"));
    }

    #[test]
    fn test_parse_path_nonexistent_file() {
        let result = parse_path("nonexistent_file.txt");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_has_valid_checksum_extension() {
        assert!(has_valid_checksum_extension(&PathBuf::from("test.sha256")));
        assert!(has_valid_checksum_extension(&PathBuf::from("test.txt")));
        assert!(has_valid_checksum_extension(&PathBuf::from("test.checksum")));
        assert!(has_valid_checksum_extension(&PathBuf::from("test.checksums")));
        assert!(!has_valid_checksum_extension(&PathBuf::from("test.exe")));
        assert!(!has_valid_checksum_extension(&PathBuf::from("test.doc")));
    }

    #[test]
    fn test_is_file_sha_with_real_checksum_file() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempdir()?;
        let file_path = dir.path().join("test.sha256");
        
        let mut file = fs::File::create(&file_path)?;
        writeln!(file, "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678 test.txt")?;
        
        assert!(is_file_sha(&file_path));
        
        Ok(())
    }

    #[test]
    fn test_is_file_sha_with_regular_file() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempdir()?;
        let file_path = dir.path().join("test.txt");
        
        let mut file = fs::File::create(&file_path)?;
        writeln!(file, "This is just regular text content")?;
        
        assert!(!is_file_sha(&file_path));
        
        Ok(())
    }

    #[test]
    fn test_is_file_sha_empty_file() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempdir()?;
        let file_path = dir.path().join("empty.sha256");
        
        fs::File::create(&file_path)?;
        
        assert!(!is_file_sha(&file_path));
        
        Ok(())
    }
}