use std::path::PathBuf;
use std::fs::File;
use std::io::Write;
use walkdir::WalkDir;
use rayon::prelude::*;
use colored::*;
use spinoff::{Spinner, spinners, Color, Streams};
use std::io;
use crate::{compute_sha_for_file, strip_prefix, read_sha256_file, find_matching_sha256_for_filename, clear_spinner_and_flush};

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
    
    let results: Vec<_> = files.par_iter()
        .map(|entry| {
            let path = entry.path();
            let file_hash = compute_sha_for_file(&path.to_path_buf(), &checksums_file_name, false).to_lowercase();
            let relative_path = strip_prefix(path, &dir);
            let matches = find_matching_sha256_for_filename(&text, &file_hash).is_some();
            (matches, relative_path.to_string_lossy().into_owned())
        })
        .collect();

    clear_spinner_and_flush(&mut spinner);

    let (good_files, bad_files): (Vec<_>, Vec<_>) = results.into_iter().partition(|&(matches, _)| matches);

    let count_good = good_files.len();
    let count_bad = bad_files.len();
    let total_count = count_good + count_bad;

    match (count_good, count_bad) {
        (_, 0) => println!("{} All checksums passed!", "Status:".truecolor(119, 193, 178)),
        (0, _) => println!("{} All checksums failed!", "Status:".truecolor(173, 127, 172)),
        _ => {
            println!("Files with mismatched hashes:");
            for (_, file) in bad_files {
                println!("{}", file);
            }

            if count_good > count_bad {
                println!("{} {} out of {} checksums passed!",
                         "Status:".truecolor(119, 193, 178), count_good, total_count);
            } else {
                println!("{} {} out of {} checksums passed!",
                         "Status:".truecolor(173, 127, 172), count_good, total_count);
            }
        }
    }

    Ok(())
}