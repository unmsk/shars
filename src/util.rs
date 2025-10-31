use anyhow::{Context, Result};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::hasher;

pub fn warning_tag() -> ColoredString {
    "[ ! ]".bold()
}

pub fn start_progress_bar(msg: &str, total: u64) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{msg}\n[{bar:40.cyan/blue}] {bytes}/{total_bytes} ({percent}%)")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb.set_message(msg.to_string());
    pb
}

pub fn start_progress_bar_files(msg: &str, total: u64) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{msg}\n[{bar:40.cyan/blue}] {pos}/{len} files ({percent}%)")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb.set_message(msg.to_string());
    pb
}

pub fn finish_progress_bar(pb: &ProgressBar, final_msg: &str) {
    pb.finish_and_clear();
    if !final_msg.is_empty() {
        println!("{}", final_msg);
    }
}

pub fn format_file_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    const THRESHOLD: u64 = 1024;

    if bytes == 0 {
        return "0 B".to_string();
    }

    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= THRESHOLD as f64 && unit_index < UNITS.len() - 1 {
        size /= THRESHOLD as f64;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

pub fn is_hex_64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn resolve_to_checksum_with_progress_bar(input: &str, label: &str) -> Result<String> {
    let path = PathBuf::from(input);

    if path.exists() {
        let file_size = std::fs::metadata(&path)
            .context("failed to get file metadata")?
            .len();
        let file_size_str = format_file_size(file_size);
        let pb = start_progress_bar(
            &format!(
                "{}: computing SHA256 for {:?} ({})",
                label, path, file_size_str
            ),
            file_size,
        );
        let result = hasher::hash_file_sha256_with_progress(&path, Some(&pb));
        pb.finish_and_clear();
        result
    } else if is_hex_64(input) {
        Ok(input.to_string())
    } else {
        anyhow::bail!(
            "input '{}' is neither a valid file path nor a 64-character hex checksum",
            input
        )
    }
}

pub struct ChecksumEntry {
    pub checksum: String,
    pub file_path: Option<PathBuf>,
}

pub fn resolve_sha256_file_input(
    input: &str,
    other_checksum: &str,
    _label: &str,
) -> Result<(String, Vec<String>)> {
    let path = PathBuf::from(input);

    anyhow::ensure!(path.exists(), "SHA256 file '{}' does not exist", input);
    anyhow::ensure!(
        path.extension().and_then(|s| s.to_str()) == Some("sha256"),
        "'{}' is not a valid SHA256 file",
        input
    );

    let entries = parse_checksums_file_with_optional_paths(&path)?;
    anyhow::ensure!(
        !entries.is_empty(),
        "no valid checksums found in SHA256 file '{}'",
        input
    );

    let mut warnings = Vec::new();

    for entry in &entries {
        if entry.checksum == other_checksum {
            if entry.file_path.is_none() {
                warnings.push(format!(
                    "{} : missing filename",
                    warning_tag()
                ));
            } else if let Some(ref file_path) = entry.file_path
                && !file_path.exists() {
                    warnings.push(format!(
                        "{} : invalid file path",
                        warning_tag(),
                    ));
                }
            return Ok((entry.checksum.clone(), warnings));
        }
    }

    let first_entry = &entries[0];
    if first_entry.file_path.is_none() {
        warnings.push(format!(
            "{} : no matching checksum found, using first entry (no filename in SHA256 file)",
            warning_tag()
        ));
    }

    Ok((first_entry.checksum.clone(), warnings))
}

pub fn collect_all_files(dir: &Path, ignore_files: Option<&[&str]>) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    for entry in WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let file_path = entry.path();

        if let Some(ignore_list) = ignore_files
            && let Some(file_name) = file_path.file_name()
                && let Some(name_str) = file_name.to_str()
                    && ignore_list.contains(&name_str) {
                        continue;
                    }

        files.push(file_path.to_path_buf());
    }

    Ok(files)
}

pub fn write_checksums_to_file(
    root_dir: &Path,
    checksums: &[(PathBuf, String)],
    output_filename: &str,
) -> Result<PathBuf> {
    let output_path = root_dir.join(output_filename);
    let mut content = String::new();

    let mut sorted_checksums = checksums.to_vec();
    sorted_checksums.sort_by(|a, b| a.0.cmp(&b.0));

    for (file_path, checksum) in sorted_checksums {
        let relative_path = file_path
            .strip_prefix(root_dir)
            .unwrap_or(&file_path)
            .to_string_lossy();

        content.push_str(&format!("{}  {}\n", checksum, relative_path));
    }

    std::fs::write(&output_path, content)
        .with_context(|| format!("failed writing to {:?}", output_path))?;
    Ok(output_path)
}

pub fn parse_checksums_file_with_optional_paths(checksums_path: &Path) -> Result<Vec<ChecksumEntry>> {
    let content = std::fs::read_to_string(checksums_path)
        .with_context(|| format!("failed reading {:?}", checksums_path))?;
    let mut entries = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if line.len() >= 64 && is_hex_64(&line[..64]) {
            let checksum = line[..64].to_string();

            let rest = line[64..].trim_start();
            let file_path = if rest.is_empty() {
                None
            } else {
                Some(PathBuf::from(rest))
            };

            entries.push(ChecksumEntry { checksum, file_path });
        }
    }

    Ok(entries)
}