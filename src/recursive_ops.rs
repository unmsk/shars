use anyhow::{bail, Context, Result};
use rayon::prelude::*;
use std::path::PathBuf;

use crate::hasher;
use crate::util;

pub fn handle_wr_command(dir: &PathBuf) -> Result<()> {
    anyhow::ensure!(dir.exists(), "directory {:?} not found", dir);
    anyhow::ensure!(dir.is_dir(), "{:?} is not a directory", dir);

    let mut ignore_files = vec!["checksums.txt".to_string(), "checksums.sha256".to_string()];
    if let Some(name) = dir.file_name() {
        ignore_files.push(format!("{}.sha256", name.to_string_lossy()));
    }
    let ignore_refs: Vec<&str> = ignore_files.iter().map(|s| s.as_str()).collect();

    let files = util::collect_all_files(dir, Some(&ignore_refs))
        .with_context(|| format!("scanning directory {:?}", dir))?;

    if files.is_empty() {
        println!("no files found in directory");
        return Ok(());
    }

    let pb_progress = util::start_progress_bar_files(
        &format!(
            "computing checksums using {} threads...",
            rayon::current_num_threads()
        ),
        files.len() as u64,
    );

    let results: Vec<_> = files
        .par_iter()
        .map(|file_path| {
            let result = hasher::hash_file_sha256(file_path);
            pb_progress.inc(1);
            (file_path.clone(), result)
        })
        .collect();

    util::finish_progress_bar(&pb_progress, "");

    let mut checksums = Vec::new();
    let mut errors = Vec::new();

    for (file_path, result) in results {
        match result {
            Ok(checksum) => checksums.push((file_path, checksum)),
            Err(e) => errors.push((file_path, e)),
        }
    }

    if checksums.is_empty() {
        bail!("no files could be hashed successfully");
    }

    let succeeded_count = checksums.len();
    let failed_count = errors.len();

    if failed_count == 0 {
        println!("successfully hashed all {} files", succeeded_count);
    } else {
        println!(
            "status: {} succeeded, {} failed",
            succeeded_count, failed_count
        );
        for (file_path, e) in &errors {
            let relative_path = file_path.strip_prefix(dir).unwrap_or(file_path);
            let error_msg = e.to_string().to_lowercase();
            eprintln!(
                "{} : {} - {}",
                util::warning_tag(),
                relative_path.display(),
                error_msg
            );
        }
    }

    let output_filename = match dir.file_name() {
        Some(name) => format!("{}.sha256", name.to_string_lossy()),
        None => "checksums.sha256".to_string(),
    };

    util::write_checksums_to_file(dir, &checksums, &output_filename)
        .with_context(|| format!("failed writing checksums file to {:?}", dir))?;

    if failed_count > 1 {
        bail!("checksum verification failed for {} file(s)", failed_count);
    }

    Ok(())
}

enum VerificationResult {
    Success,
    ChecksumMismatch,
    FileNotFound,
    NoFilenameInChecksum,
    FilenameIncorrect { expected: PathBuf, found_checksum: bool },
    ChecksumError(String),
}

pub fn handle_cr_command(dir: &PathBuf) -> Result<()> {
    anyhow::ensure!(dir.exists(), "directory {:?} not found", dir);
    anyhow::ensure!(dir.is_dir(), "{:?} is not a directory", dir);

    let checksums_file = match dir.file_name() {
        Some(name) => {
            let dir_name_file = dir.join(format!("{}.sha256", name.to_string_lossy()));
            if dir_name_file.exists() {
                dir_name_file
            } else {
                dir.join("checksums.sha256")
            }
        }
        None => dir.join("checksums.sha256"),
    };

    anyhow::ensure!(
        checksums_file.exists(),
        "checksum file not found in {:?}",
        dir
    );

    let entries = util::parse_checksums_file_with_optional_paths(&checksums_file)
        .with_context(|| format!("failed reading checksums file {:?}", checksums_file))?;

    if entries.is_empty() {
        println!("no checksums found in file");
        return Ok(());
    }

    let pb_progress = util::start_progress_bar_files(
        &format!(
            "verifying checksums using {} threads...",
            rayon::current_num_threads()
        ),
        entries.len() as u64,
    );

    let verification_results: Vec<_> = entries
        .par_iter()
        .map(|entry| {
            let result = match &entry.file_path {
                None => {
                    (entry.checksum.clone(), None, VerificationResult::NoFilenameInChecksum)
                }
                Some(file_path) => {
                    let full_path = if file_path.is_relative() {
                        dir.join(file_path)
                    } else {
                        file_path.clone()
                    };

                    if !full_path.exists() {
                        let found = try_find_file_by_checksum(dir, &entry.checksum);
                        if let Some(_found_path) = found {
                            (
                                entry.checksum.clone(),
                                Some(file_path.clone()),
                                VerificationResult::FilenameIncorrect {
                                    expected: file_path.clone(),
                                    found_checksum: true,
                                },
                            )
                        } else {
                            (
                                entry.checksum.clone(),
                                Some(file_path.clone()),
                                VerificationResult::FileNotFound,
                            )
                        }
                    } else {
                        match crate::hasher::hash_file_sha256(&full_path) {
                            Ok(actual_checksum) => {
                                if actual_checksum == entry.checksum {
                                    (
                                        entry.checksum.clone(),
                                        Some(file_path.clone()),
                                        VerificationResult::Success,
                                    )
                                } else {
                                    (
                                        entry.checksum.clone(),
                                        Some(file_path.clone()),
                                        VerificationResult::ChecksumMismatch,
                                    )
                                }
                            }
                            Err(e) => (
                                entry.checksum.clone(),
                                Some(file_path.clone()),
                                VerificationResult::ChecksumError(e.to_string().to_lowercase()),
                            ),
                        }
                    }
                }
            };

            pb_progress.inc(1);
            result
        })
        .collect();

    util::finish_progress_bar(&pb_progress, "");

    let mut verified_count = 0;
    let mut failed_count = 0;
    let mut warning_count = 0;

    for (_checksum, _file_path, result) in &verification_results {
        match result {
            VerificationResult::Success => verified_count += 1,
            VerificationResult::NoFilenameInChecksum => warning_count += 1,
            VerificationResult::FilenameIncorrect { found_checksum: true, .. } => warning_count += 1,
            _ => failed_count += 1,
        }
    }

    if failed_count == 0 && warning_count == 0 {
        println!("all {} checksums verified successfully", verified_count);
    } else if failed_count == 0 {
        println!(
            "status: {} verified, {} warnings",
            verified_count, warning_count
        );
    } else {
        println!(
            "status: {} verified, {} failed, {} warnings",
            verified_count, failed_count, warning_count
        );
    }

    for (checksum, _file_path, result) in &verification_results {
        match result {
            VerificationResult::NoFilenameInChecksum => {
                println!(
                    "[ ok ] : checksum {} - no filename",
                    &checksum
                );
            }
            VerificationResult::FilenameIncorrect { expected, found_checksum: true } => {
                println!(
                    "[ ok ] : {} - invalid path",
                    expected.display()
                );
            }
            _ => {}
        }
    }

    let mut has_errors = false;
    for (_checksum, file_path, result) in &verification_results {
        match result {
            VerificationResult::FileNotFound => {
                if let Some(path) = file_path {
                    eprintln!(
                        "{} : {} - file not found",
                        util::warning_tag(),
                        path.display()
                    );
                }
            }
            VerificationResult::ChecksumMismatch => {
                if let Some(path) = file_path {
                    eprintln!(
                        "{} : {} - checksum mismatch",
                        util::warning_tag(),
                        path.display()
                    );
                }
            }
            VerificationResult::ChecksumError(err) => {
                if let Some(path) = file_path {
                    eprintln!(
                        "{} : {} - {}",
                        util::warning_tag(),
                        path.display(),
                        err
                    );
                    has_errors = true;
                }
            }
            _ => {}
        }
    }

    if has_errors && failed_count > 0 {
        bail!("checksum verification failed for {} file(s)", failed_count);
    }

    Ok(())
}

fn try_find_file_by_checksum(dir: &PathBuf, target_checksum: &str) -> Option<PathBuf> {
    use walkdir::WalkDir;

    for entry in WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let file_path = entry.path();

        if file_path.extension().and_then(|s| s.to_str()) == Some("sha256") {
            continue;
        }

        if let Ok(checksum) = hasher::hash_file_sha256(file_path) {
            if checksum == target_checksum {
                return Some(file_path.to_path_buf());
            }
        }
    }

    None
}