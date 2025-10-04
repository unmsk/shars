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
            "hashing complete: {} succeeded, {} failed",
            succeeded_count, failed_count
        );
        for (file_path, e) in &errors {
            let relative_path = file_path.strip_prefix(dir).unwrap_or(file_path);
            let error_msg = e.to_string().to_lowercase();
            eprintln!(
                "     {} : {} - {}",
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

    Ok(())
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

    let expected_checksums = util::parse_checksums_file(&checksums_file)
        .with_context(|| format!("failed reading checksums file {:?}", checksums_file))?;

    if expected_checksums.is_empty() {
        println!("no checksums found in file");
        return Ok(());
    }

    let pb_progress = util::start_progress_bar_files(
        &format!(
            "verifying checksums using {} threads...",
            rayon::current_num_threads()
        ),
        expected_checksums.len() as u64,
    );

    let verification_results: Vec<_> = expected_checksums
        .par_iter()
        .map(|(file_path, expected_checksum)| {
            let full_path = if file_path.is_relative() {
                dir.join(file_path)
            } else {
                file_path.clone()
            };

            let result = if !full_path.exists() {
                (file_path.clone(), false, "file not found".to_string())
            } else {
                match crate::hasher::hash_file_sha256(&full_path) {
                    Ok(actual_checksum) => {
                        if actual_checksum == *expected_checksum {
                            (file_path.clone(), true, "[ ok ]".to_string())
                        } else {
                            (file_path.clone(), false, util::warning_tag().to_string())
                        }
                    }
                    Err(e) => (
                        file_path.clone(),
                        false,
                        format!("checksum error: {}", e).to_lowercase(),
                    ),
                }
            };

            pb_progress.inc(1);
            result
        })
        .collect();

    util::finish_progress_bar(&pb_progress, "");

    let mut verified_count = 0;
    let mut failed_count = 0;

    for (_file_path, is_valid, _status) in &verification_results {
        if *is_valid {
            verified_count += 1;
        } else {
            failed_count += 1;
        }
    }

    if failed_count == 0 {
        println!("all {} checksums verified successfully", verified_count);
    } else {
        println!(
            "verification complete: {} verified, {} failed",
            verified_count, failed_count
        );
        for (file_path, is_valid, status) in &verification_results {
            if !*is_valid {
                eprintln!(
                    "     {} : {} - {}",
                    util::warning_tag(),
                    file_path.display(),
                    status
                );
            }
        }
    }

    Ok(())
}
