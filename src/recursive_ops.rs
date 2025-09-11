use crate::error::SharsError;
use crate::hasher::compute_sha_for_file;
use crate::read::read_sha256_file;
use crate::utils::{start_spinner, strip_prefix};
use colored::*;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use walkdir::WalkDir;

pub fn write_recursive(dir: PathBuf) -> Result<(), SharsError> {
    if !dir.is_dir() {
        return Err(SharsError::InvalidDirectory(
            "the 'wr' command requires a directory".to_string(),
        ));
    }

    let dir_name = dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("checksums");

    let checksums_file_name = format!("{}.sha256", dir_name);
    let output_file = dir.join(&checksums_file_name);

    let mut checksums_file = File::create(&output_file)?;

    let loading_message = if dir_name == "checksums" {
        "processing directory".to_string()
    } else {
        format!("processing directory '{}'", dir_name)
    };

    let files: Vec<_> = WalkDir::new(&dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.path().is_file()
                && entry.file_name().to_string_lossy().to_ascii_lowercase()
                    != checksums_file_name.to_ascii_lowercase()
        })
        .collect();

    let total_bytes: u64 = files
        .iter()
        .filter_map(|entry| entry.metadata().ok().map(|m| m.len()))
        .sum();

    let pb = start_spinner(&loading_message);
    pb.set_length(total_bytes);

    let processed_bytes = Arc::new(Mutex::new(0u64));
    let skipped_files = Arc::new(Mutex::new(Vec::new()));

    let results: Vec<_> = files
        .par_iter()
        .filter_map(|entry| {
            let path = entry.path();
            let relative_path = strip_prefix(path, &dir);
            let relative_path_str = relative_path.to_string_lossy().to_string();
            let normalized_path = normalize_path(&relative_path_str);
            let file_size = entry.metadata().ok().map(|m| m.len()).unwrap_or(0);

            match compute_sha_for_file(&path.to_path_buf(), &checksums_file_name, false) {
                Ok(hash) => {
                    let new_position = {
                        let mut processed = processed_bytes.lock().unwrap();
                        *processed += file_size;
                        *processed
                    };
                    pb.set_position(new_position);

                    Some((hash.to_lowercase(), normalized_path, relative_path_str))
                }
                Err(_) => {
                    if let Ok(mut skipped) = skipped_files.lock() {
                        skipped.push(relative_path_str);
                    }

                    let new_position = {
                        let mut processed = processed_bytes.lock().unwrap();
                        *processed += file_size;
                        *processed
                    };
                    pb.set_position(new_position);

                    None
                }
            }
        })
        .collect();

    pb.finish_and_clear();

    for (hash, _, original_path) in results {
        writeln!(checksums_file, "{} {}", hash, original_path)?;
    }

    println!(
        "{} file '{}' created and written to successfully",
        "Status:".truecolor(119, 193, 178),
        checksums_file_name.bold().white()
    );

    if let Ok(skipped) = skipped_files.lock() {
        if !skipped.is_empty() {
            println!(
                "{} skipped {} files due to checksum computation failures:",
                "Warning:".truecolor(173, 127, 172),
                skipped.len()
            );
            for file in skipped.iter() {
                println!("  FAILED: {}", file);
            }
        }
    }

    Ok(())
}

pub fn check_recursive(dir: PathBuf) -> Result<(), SharsError> {
    if !dir.is_dir() {
        return Err(SharsError::InvalidDirectory(
            "the 'cr' command requires a directory".to_string(),
        ));
    }

    let dir_name = dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("checksums");

    let checksums_file_name = format!("{}.sha256", dir_name);
    let checksums_path = dir.join(&checksums_file_name);

    if !checksums_path.exists() {
        return Err(SharsError::InvalidFile(format!(
            "file '{}' is missing",
            checksums_file_name
        )));
    }

    let sha256_content = read_sha256_file(&checksums_path, &checksums_file_name)?;

    let expected_files = parse_sha256_file(&sha256_content);

    let loading_message = if dir_name == "checksums" {
        "processing directory".to_string()
    } else {
        format!("processing directory '{}'", dir_name)
    };

    let files: Vec<_> = WalkDir::new(&dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.path().is_file()
                && entry.file_name().to_string_lossy().to_ascii_lowercase()
                    != checksums_file_name.to_ascii_lowercase()
        })
        .collect();

    let total_bytes: u64 = files
        .iter()
        .filter_map(|entry| entry.metadata().ok().map(|m| m.len()))
        .sum();

    let pb = start_spinner(&loading_message);
    pb.set_length(total_bytes);

    let processed_bytes = Arc::new(Mutex::new(0u64));
    let skipped_files = Arc::new(Mutex::new(Vec::new()));

    let mut actual_files_map = HashMap::new();

    let results: Vec<(FileStatus, String, String)> = files
        .par_iter()
        .filter_map(|entry| {
            let path = entry.path();
            let relative_path = strip_prefix(path, &dir);
            let relative_path_str = relative_path.to_string_lossy().to_string();
            let normalized_path = normalize_path(&relative_path_str);
            let file_size = entry.metadata().ok().map(|m| m.len()).unwrap_or(0);

            match compute_sha_for_file(&path.to_path_buf(), &checksums_file_name, false) {
                Ok(file_hash) => {
                    let new_position = {
                        let mut processed = processed_bytes.lock().unwrap();
                        *processed += file_size;
                        *processed
                    };
                    pb.set_position(new_position);

                    let file_hash = file_hash.to_lowercase();
                    let status = if let Some(expected_hash) = expected_files.get(&normalized_path) {
                        if &file_hash == expected_hash {
                            FileStatus::Ok
                        } else {
                            FileStatus::Mismatched
                        }
                    } else {
                        FileStatus::ExtraFile
                    };
                    Some((status, normalized_path, relative_path_str))
                }
                Err(_) => {
                    if let Ok(mut skipped) = skipped_files.lock() {
                        skipped.push(relative_path_str);
                    }

                    let new_position = {
                        let mut processed = processed_bytes.lock().unwrap();
                        *processed += file_size;
                        *processed
                    };
                    pb.set_position(new_position);

                    None
                }
            }
        })
        .collect();

    pb.finish_and_clear();

    let mut ok_files = Vec::new();
    let mut mismatched_files = Vec::new();
    let mut extra_files = Vec::new();
    let mut actual_file_paths = HashSet::with_capacity(results.len());

    for (status, normalized_path, relative_path) in results {
        actual_file_paths.insert(normalized_path.clone());
        actual_files_map.insert(normalized_path, relative_path.clone());

        match status {
            FileStatus::Ok => ok_files.push(relative_path),
            FileStatus::Mismatched => mismatched_files.push(relative_path),
            FileStatus::ExtraFile => extra_files.push(relative_path),
        }
    }

    let missing_files_from_checksum: Vec<_> = expected_files
        .keys()
        .filter(|path| !actual_file_paths.contains(*path))
        .cloned()
        .collect();

    let count_ok = ok_files.len();
    let count_mismatched = mismatched_files.len();
    let count_missing = missing_files_from_checksum.len();
    let total_checked = count_ok + count_mismatched;
    let problem_count = count_mismatched + count_missing;

    if count_mismatched == 0 && count_missing == 0 && extra_files.is_empty() {
        println!(
            "{} All checksums passed!",
            "Status:".truecolor(119, 193, 178)
        );
    } else {
        if !mismatched_files.is_empty() {
            println!("files with MISMATCHED hashes:");
            for file in &mismatched_files {
                println!("  MISMATCHED: {}", file);
            }
        }

        if !missing_files_from_checksum.is_empty() {
            println!("files MISSING from directory (listed in checksums file):");
            for file in &missing_files_from_checksum {
                println!("  MISSING: {}", file);
            }
        }

        if !extra_files.is_empty() {
            println!("EXTRA files in directory (not in checksums file):");
            for file in &extra_files {
                println!("  EXTRA: {}", file);
            }
        }

        if let Ok(skipped) = skipped_files.lock() {
            if !skipped.is_empty() {
                println!(
                    "{} skipped {} files due to checksum computation failures:",
                    "Warning:".truecolor(173, 127, 172),
                    skipped.len()
                );
                for file in skipped.iter() {
                    println!("  FAILED: {}", file);
                }
            }
        }

        let status_color = if count_ok > problem_count {
            "Status:".truecolor(119, 193, 178)
        } else {
            "Status:".truecolor(173, 127, 172)
        };

        println!(
            "{} {} out of {} checksums passed ({} mismatched, {} missing)",
            status_color,
            count_ok,
            total_checked + count_missing,
            count_mismatched,
            count_missing
        );
    }

    Ok(())
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum FileStatus {
    Ok,
    Mismatched,
    ExtraFile,
}

fn parse_sha256_file(content: &str) -> HashMap<String, String> {
    let mut result = HashMap::with_capacity(content.lines().count());

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((hash, filepath)) = line.split_once(' ') {
            let hash = hash.to_lowercase();
            let mut filepath = filepath.trim();

            if filepath.starts_with('*') {
                filepath = &filepath[1..];
            }

            let normalized_path = normalize_path(filepath);
            result.insert(normalized_path, hash);
        }
    }

    result
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/").to_ascii_lowercase()
}
