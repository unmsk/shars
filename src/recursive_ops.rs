use std::collections::HashMap;
use std::path::PathBuf;
use std::fs::File;
use std::io::Write;
use walkdir::WalkDir;
use rayon::prelude::*;
use colored::*;
use spinoff::{Spinner, spinners, Color, Streams};
use std::io;
use crate::{compute_sha_for_file, strip_prefix, read_sha256_file, clear_spinner_and_flush};

pub async fn write_recursive(dir: PathBuf) -> io::Result<()> {
    if !dir.is_dir() {
        eprintln!("{} the 'wr' command requires a directory", "Error:".truecolor(173, 127, 172));
        return Ok(());
    }

    let dir_name = dir.file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| {
            eprintln!("{} directory has no file name", "Error:".truecolor(173, 127, 172));
            io::Error::new(io::ErrorKind::InvalidInput, "Invalid directory name")
        })?;

    let checksums_file_name = format!("{}.sha256", dir_name);
    let output_file = dir.join(&checksums_file_name);
    let mut checksums_file = File::create(&output_file)?;

    let loading_message = format!("Computing checksums for directory '{}'", dir_name);
    let mut spinner = Spinner::new_with_stream(spinners::Line, loading_message, Color::White, Streams::Stdout);

    let files: Vec<_> = WalkDir::new(&dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.path().is_file() &&
                entry.file_name().to_string_lossy().to_ascii_lowercase() != checksums_file_name.to_ascii_lowercase()
        })
        .collect();

    let results: Vec<_> = files.par_iter()
        .map(|entry| {
            let path = entry.path();
            let result = compute_sha_for_file(&path.to_path_buf(), &checksums_file_name, false).to_lowercase();
            let relative_path = strip_prefix(path, &dir);
            (result, relative_path.to_string_lossy().into_owned())
        })
        .collect();

    for (hash, path) in results {
        writeln!(checksums_file, "{} {}", hash, path)?;
    }

    clear_spinner_and_flush(&mut spinner);
    println!("{} file '{}' created and written to successfully",
             "Status:".truecolor(119, 193, 178),
             checksums_file_name.bold().white());

    Ok(())
}

pub async fn check_recursive(dir: PathBuf) -> io::Result<()> {
    if !dir.is_dir() {
        eprintln!("{} the 'cr' command requires a directory", "Error:".truecolor(173, 127, 172));
        return Ok(());
    }

    let dir_name = dir.file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| {
            eprintln!("{} directory has no file name", "Error:".truecolor(173, 127, 172));
            io::Error::new(io::ErrorKind::InvalidInput, "Invalid directory name")
        })?;

    let checksums_file_name = format!("{}.sha256", dir_name);
    let checksums_path = dir.join(&checksums_file_name);

    if !checksums_path.exists() {
        eprintln!("{} file '{}' is missing", "Error:".truecolor(173, 127, 172), checksums_file_name);
        return Ok(());
    }

    let sha256_content = read_sha256_file(&checksums_path, dir_name)?;
    let text = sha256_content.to_lowercase();

    let expected_files = parse_sha256_file(&text);

    let loading_message = format!("Verifying checksums for directory '{}'", dir_name);
    let mut spinner = Spinner::new_with_stream(spinners::Line, loading_message, Color::White, Streams::Stdout);

    let files: Vec<_> = WalkDir::new(&dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.path().is_file() &&
                entry.file_name().to_string_lossy().to_ascii_lowercase() != checksums_file_name.to_ascii_lowercase()
        })
        .collect();

    let mut actual_files = HashMap::new();
    for entry in &files {
        let path = entry.path();
        let relative_path = strip_prefix(path, &dir);
        let relative_path_str = relative_path.to_string_lossy().to_string();
        let relative_path_lower = relative_path_str.to_ascii_lowercase();

        let normalized_path_lower = relative_path_lower.replace('\\', "/");

        let file_hash = compute_sha_for_file(&path.to_path_buf(), &checksums_file_name, false).to_lowercase();
        actual_files.insert(normalized_path_lower, (relative_path_str, file_hash));
    }

    let mut results = Vec::new();

    for (lower_path, (orig_path, actual_hash)) in &actual_files {
        if let Some(expected_hash) = expected_files.get(lower_path) {
            let matches = actual_hash == expected_hash;
            if matches {
                results.push((FileStatus::Ok, orig_path.clone()));
            } else {
                results.push((FileStatus::Mismatched, orig_path.clone()));
            }
        } else {
            results.push((FileStatus::ExtraFile, orig_path.clone()));
        }
    }

    let mut missing_files_from_checksum = Vec::new();
    for checksum_path in expected_files.keys() {
        if !actual_files.contains_key(checksum_path) {
            missing_files_from_checksum.push(checksum_path.clone());
        }
    }

    clear_spinner_and_flush(&mut spinner);

    let mut ok_files = Vec::new();
    let mut mismatched_files = Vec::new();
    let mut extra_files = Vec::new();

    for (status, filename) in results {
        match status {
            FileStatus::Ok => ok_files.push(filename),
            FileStatus::Mismatched => mismatched_files.push(filename),
            FileStatus::ExtraFile => extra_files.push(filename),
        }
    }

    let count_ok = ok_files.len();
    let count_mismatched = mismatched_files.len();
    let count_missing = missing_files_from_checksum.len();
    let total_checked = count_ok + count_mismatched;
    let problem_count = count_mismatched + count_missing;

    if count_mismatched == 0 && count_missing == 0 && extra_files.is_empty() {
        println!("{} All checksums passed!", "Status:".truecolor(119, 193, 178));
    } else {
        if !mismatched_files.is_empty() {
            println!("Files with MISMATCHED hashes:");
            for file in &mismatched_files {
                println!("  MISMATCHED: {}", file);
            }
        }

        if !missing_files_from_checksum.is_empty() {
            println!("Files MISSING from directory (listed in checksums file):");
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

        if count_ok > problem_count {
            println!("{} {} out of {} checksums passed ({} mismatched, {} missing)",
                     "Status:".truecolor(119, 193, 178), count_ok, total_checked + count_missing, count_mismatched, count_missing);
        } else {
            println!("{} {} out of {} checksums passed ({} mismatched, {} missing)",
                     "Status:".truecolor(173, 127, 172), count_ok, total_checked + count_missing, count_mismatched, count_missing);
        }
    }

    Ok(())
}

#[derive(PartialEq, Eq)]
enum FileStatus {
    Ok,
    Mismatched,
    ExtraFile,
}

fn parse_sha256_file(content: &str) -> HashMap<String, String> {
    let mut result = HashMap::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("#") {
            continue;
        }

        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        if parts.len() == 2 {
            let hash = parts[0].to_lowercase();
            let mut filepath = parts[1].trim();

            if filepath.starts_with('*') {
                filepath = &filepath[1..];
            }

            let normalized_path = filepath.replace('\\', "/");

            result.insert(normalized_path.to_ascii_lowercase(), hash);
        }
    }

    result
}
