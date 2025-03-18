use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::fs::File;
use std::io::Write;
use walkdir::WalkDir;
use rayon::prelude::*;
use colored::*;
use spinoff::{Spinner, spinners, Color, Streams};
use std::io;

use crate::hasher::compute_hash_helper;
use crate::read::{read_sha256_file};
use crate::utils::{strip_prefix, clear_spinner_and_flush};

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

    let mut checksums_file = match File::create(&output_file) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("{} could not create checksum file: {}", "Error:".truecolor(173, 127, 172), e);
            std::process::exit(3);
        },
    };


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
            let result = compute_hash_helper(&path.to_path_buf(), &checksums_file_name, false).to_lowercase();
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

    let dir_name = match dir.file_name().and_then(|n| n.to_str()) {
        Some(name) => name,
        None => {
            eprintln!("{} directory has no file name", "Error:".truecolor(173, 127, 172));
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid directory name"));
        }
    };

    let checksums_file_name = format!("{}.sha256", dir_name);
    let checksums_path = dir.join(&checksums_file_name);

    if !checksums_path.exists() {
        eprintln!("{} file '{}' is missing", "Error:".truecolor(173, 127, 172), checksums_file_name);
        return Ok(());
    }

    let sha256_content = match read_sha256_file(&checksums_path, dir_name) {
        Ok(content) => content,
        Err(_e) => std::process::exit(3)
    };

    let expected_files = parse_sha256_file(&sha256_content.to_lowercase());

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

    use rayon::prelude::*;
    let results: Vec<(FileStatus, String, String)> = files.par_iter()
        .map(|entry| {
            let path = entry.path();
            let relative_path = strip_prefix(path, &dir);
            let relative_path_str = relative_path.to_string_lossy().to_string();
            let relative_path_lower = relative_path_str.to_ascii_lowercase();
            let normalized_path_lower = relative_path_lower.replace('\\', "/");

            let file_hash = compute_hash_helper(&path.to_path_buf(), &checksums_file_name, false).to_lowercase();

            let status = if let Some(expected_hash) = expected_files.get(&normalized_path_lower) {
                if &file_hash == expected_hash {
                    FileStatus::Ok
                } else {
                    FileStatus::Mismatched
                }
            } else {
                FileStatus::ExtraFile
            };

            (status, normalized_path_lower, relative_path_str)
        })
        .collect();

    let mut ok_files = Vec::new();
    let mut mismatched_files = Vec::new();
    let mut extra_files = Vec::new();
    let mut actual_file_paths = HashSet::with_capacity(results.len());

    for (status, normalized_path, relative_path) in results {
        actual_file_paths.insert(normalized_path);
        match status {
            FileStatus::Ok => ok_files.push(relative_path),
            FileStatus::Mismatched => mismatched_files.push(relative_path),
            FileStatus::ExtraFile => extra_files.push(relative_path),
        }
    }

    let missing_files_from_checksum: Vec<_> = expected_files.keys()
        .filter(|path| !actual_file_paths.contains(*path))
        .cloned()
        .collect();

    clear_spinner_and_flush(&mut spinner);

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

        let status_color = if count_ok > problem_count {
            "Status:".truecolor(119, 193, 178)
        } else {
            "Status:".truecolor(173, 127, 172)
        };

        println!("{} {} out of {} checksums passed ({} mismatched, {} missing)",
                 status_color, count_ok, total_checked + count_missing, count_mismatched, count_missing);
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

            let normalized_path = filepath.replace('\\', "/");
            result.insert(normalized_path.to_ascii_lowercase(), hash);
        }
    }

    result
}
