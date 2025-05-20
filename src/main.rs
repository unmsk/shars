use colored::*;
use sha2::{Digest, Sha256};
use std::env::current_dir;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use clap::Parser;

mod recursive_ops;
mod hasher;
mod read;
mod utils;
mod error;
mod cli;

use hasher::compute_sha_for_file;
use recursive_ops::{check_recursive, write_recursive};
use utils::{is_file_sha, shorten_str, return_checksum, highlight_differences};
use error::SharsError;
use cli::{Cli, Commands};

fn main() {
    if let Err(e) = run(Cli::parse()) {
        match e {
            SharsError::IoError(e) => eprintln!("{} {}", "Error:".truecolor(173, 127, 172), e),
            SharsError::InvalidPath(msg) => eprintln!("{} {}", "Error:".truecolor(173, 127, 172), msg),
            SharsError::InvalidDirectory(msg) => eprintln!("{} {}", "Error:".truecolor(173, 127, 172), msg),
            SharsError::InvalidFile(msg) => eprintln!("{} {}", "Error:".truecolor(173, 127, 172), msg),
            SharsError::ChecksumError(msg) => eprintln!("{} {}", "Error:".truecolor(173, 127, 172), msg),
        }
    }
}

fn run(cli: Cli) -> Result<(), SharsError> {
    match cli.command {
        Commands::S { filename } => {
            if !filename.is_file() {
                return Err(SharsError::InvalidFile("the 's' command does not work with directories. use 'wr or 'cr' instead".to_string()));
            }
            let first_filename = filename.file_name().unwrap().to_string_lossy();
            let computed_hash = compute_sha_for_file(&filename, &first_filename, true)?;
            let shortened_first_filename = shorten_str(&first_filename, 18);
            println!("{} : '{}'", computed_hash.to_lowercase().bold().white(), shortened_first_filename);
        }

        Commands::T { text } => {
            let mut hasher = Sha256::new();
            hasher.update(text.as_bytes());
            let checksum = format!("{:x}", hasher.finalize());
            let shortened_input = shorten_str(&text, 18);
            println!("{} : '{}'", checksum.bold().white(), shortened_input);
        }

        Commands::W { filename } => {
            if !filename.is_file() {
                return Err(SharsError::InvalidFile("the 'w' command does not work with directories. use 'wr' or 'cr' instead".to_string()));
            }
            let first_filename = filename.file_name().unwrap().to_string_lossy();
            let computed_hash = compute_sha_for_file(&filename, &first_filename, true)?;
            let lower_computed_hash_and_filename = computed_hash.to_lowercase() + " " + &first_filename;
            let checksum_file_path = filename.with_extension("sha256");
            let checksum_file_name = checksum_file_path.file_name().unwrap().to_string_lossy();
            let mut checksum_file = File::create(&checksum_file_path)?;
            checksum_file.write_all(lower_computed_hash_and_filename.as_bytes())?;
            println!("{} file '{}' created and written to successfully", "Status:".truecolor(119, 193, 178), &checksum_file_name.bold().white());
        }

        Commands::C { input1, input2 } => {
            fn is_checksum(path: &Path) -> bool {
                let path_str = path.to_string_lossy();
                path_str.len() == 64 && path_str.chars().all(|c| c.is_ascii_hexdigit())
            }

            let is_checksum1 = is_checksum(&input1);
            let is_checksum2 = is_checksum(&input2);

            if (!is_checksum1 && input1.exists() && input1.is_dir()) ||
                (!is_checksum2 && input2.exists() && input2.is_dir()) {
                return Err(SharsError::InvalidDirectory("the 'c' command does not work with directories. Use 'wr' or 'cr' instead".to_string()));
            }

            match (is_checksum1, is_checksum2) {
                (true, true) => {
                    let checksum_1 = input1.to_string_lossy().to_lowercase();
                    let checksum_2 = input2.to_string_lossy().to_lowercase();
                    output_result(&checksum_1, &checksum_2, "USER-SHA-1", "USER-SHA-2");
                },
                (true, false) => {
                    let checksum_1 = input1.to_string_lossy().to_lowercase();
                    let second_filename = input2.file_name().unwrap().to_str().unwrap();
                    let shortened_second_filename = shorten_str(second_filename, 18);
                    if is_file_sha(&input2) {
                        let checksum_2 = return_checksum(&input2, &shortened_second_filename, &checksum_1)?;
                        println!("{} shars extracted checksum from file '{}'",
                                 "Warning:".truecolor(119, 193, 178), shortened_second_filename.bold().white());
                        output_result(&checksum_1, &checksum_2, "USER-SHA", &shortened_second_filename);
                    } else {
                        let checksum_2 = compute_sha_for_file(&input2, &shortened_second_filename, true)?;
                        output_result(&checksum_1, &checksum_2.to_lowercase(), "USER-SHA", &shortened_second_filename);
                    }
                },
                (false, true) => {
                    let checksum_2 = input2.to_string_lossy().to_lowercase();
                    let first_filename = input1.file_name().unwrap().to_str().unwrap();
                    let shortened_first_filename = shorten_str(first_filename, 18);
                    if is_file_sha(&input1) {
                        let checksum_1 = return_checksum(&input1, &shortened_first_filename, &checksum_2)?;
                        println!("{} shars extracted checksum from file '{}'",
                                 "Warning:".truecolor(119, 193, 178), shortened_first_filename.bold().white());
                        output_result(&checksum_1, &checksum_2, &shortened_first_filename, "USER-SHA");
                    } else {
                        let checksum_1 = compute_sha_for_file(&input1, &shortened_first_filename, true)?;
                        output_result(&checksum_1.to_lowercase(), &checksum_2, &shortened_first_filename, "USER-SHA");
                    }
                },
                (false, false) => {
                    let first_filename = input1.file_name().unwrap().to_str().unwrap();
                    let second_filename = input2.file_name().unwrap().to_str().unwrap();
                    let shortened_first_filename = shorten_str(first_filename, 18);
                    let shortened_second_filename = shorten_str(second_filename, 18);

                    let file_1_result = is_file_sha(&input1);
                    let file_2_result = is_file_sha(&input2);

                    let first_file_path = PathBuf::from(&input1);
                    let second_file_path = PathBuf::from(&input2);

                    match (file_1_result, file_2_result) {
                        (true, true) => {
                            let checksum_1 = compute_sha_for_file(&first_file_path, &shortened_first_filename, true)?;
                            let checksum_2 = compute_sha_for_file(&second_file_path, &shortened_second_filename, true)?;
                            output_result(&checksum_1.to_lowercase(), &checksum_2.to_lowercase(), &shortened_first_filename, &shortened_second_filename)
                        }

                        (true, false) => {
                            let checksum_2 = compute_sha_for_file(&second_file_path, &shortened_second_filename, true)?;
                            let checksum_1 = return_checksum(&first_file_path, &shortened_first_filename, &checksum_2.to_lowercase())?;
                            println!("{} shars extracted checksum from file '{}'", "Warning:".truecolor(119, 193, 178), shortened_first_filename.bold().white());
                            output_result(&checksum_1, &checksum_2.to_lowercase(), &shortened_first_filename, &shortened_second_filename);
                        }

                        (false, true) => {
                            let checksum_1 = compute_sha_for_file(&first_file_path, &shortened_first_filename, true)?;
                            let checksum_2 = return_checksum(&second_file_path, &shortened_second_filename, &checksum_1.to_lowercase())?;
                            println!("{} shars extracted checksum from file '{}'", "Warning:".truecolor(119, 193, 178), shortened_second_filename.bold().white());
                            output_result(&checksum_1.to_lowercase(), &checksum_2, &shortened_first_filename, &shortened_second_filename)
                        }

                        (false, false) => {
                            let checksum_1 = compute_sha_for_file(&first_file_path, &shortened_first_filename, true)?;
                            let checksum_2 = compute_sha_for_file(&second_file_path, &shortened_second_filename, true)?;
                            output_result(&checksum_1.to_lowercase(), &checksum_2.to_lowercase(), &shortened_first_filename, &shortened_second_filename)
                        }
                    }
                }
            }
        }
        
        Commands::WR { directory } => {
            let dir = if directory == PathBuf::from(".") {
                current_dir()?
            } else {
                directory
            };

            tokio::runtime::Runtime::new()?
                .block_on(async {
                    write_recursive(dir).await?;
                    Ok::<(), SharsError>(())
                })?;
        },

        Commands::CR { directory } => {
            let dir = if directory == PathBuf::from(".") {
                current_dir()?
            } else {
                directory
            };

            tokio::runtime::Runtime::new()?
                .block_on(async {
                    check_recursive(dir).await?;
                    Ok::<(), SharsError>(())
                })?;
        },
    }

    Ok(())
}

fn output_result(checksum_1: &str, checksum_2: &str, padded_filename_1: &str, padded_filename_2: &str) {
    let lower_checksum_1 = &checksum_1.to_lowercase();
    let lower_checksum_2 = &checksum_2.to_lowercase();
    let squiggles = highlight_differences(lower_checksum_1, lower_checksum_2);
    println!("{} : '{}'", lower_checksum_1, padded_filename_1.trim());
    if squiggles.contains('~') {
        println!("{}", squiggles)
    }
    println!("{} : '{}'", lower_checksum_2, padded_filename_2.trim());
    if lower_checksum_1 == lower_checksum_2 {
        println!("{} {}", "Status:".truecolor(119, 193, 178), "[ ok ]".bold());
    } else {
        println!("{} {}", "Status:".truecolor(173, 127, 172), "[ !! ]".bold());
    }
}