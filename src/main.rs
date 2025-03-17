use std::io::{self, BufRead, BufReader, Read, Write};
use std::fs;
use std::env::current_dir;
use std::fs::File;
use sha2::{Sha256, Digest};
use colored::*;
use spinoff::Spinner;
use std::path::{PathBuf};
use std::path::Path;
use regex_lite::Regex;
use encoding_rs::UTF_16LE;
use clap::{Parser, Subcommand, crate_authors, crate_version, crate_name, crate_description};
mod recursive_ops;
mod hasher;

use hasher::{compute_sha_for_file, compute_hash_helper};
use recursive_ops::{write_recursive, check_recursive};

#[derive(Parser)]

#[command(
    name = crate_name!(),
    version = crate_version!(),
    about = crate_description!(),
    long_about = None,
    author = crate_authors!()
)]
#[command(help_template = "\
{name} {version}
Author: {author}

{about}

\x1b[4mUsage:\x1b[0m {usage}

{all-args}
")]

struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Creates a checksum of a given file")]
    S {
        #[arg(value_parser = parse_path)]
        filename: PathBuf,
    },

    #[command(about = "Creates a checksum of a given text string")]
    T {
        text: String,
    },

    #[command(about = "Compares two inputs (files or checksums)")]
    C {
        #[arg(help = "File or checksum")]
        #[arg(value_parser = parse_path)]
        input1: PathBuf,
        #[arg(help = "File or checksum")]
        #[arg(value_parser = parse_path)]
        input2: PathBuf,
    },

    #[command(about = "Writes a file's checksum to a SHA file")]
    W {
        #[arg(value_parser = parse_path)]
        filename: PathBuf,
    },

    #[command(about = "Creates a SHA file containing the checksums of all files in a directory")]
    WR {
        #[arg(default_value = ".")]
        #[arg(value_parser = parse_path)]
        directory: PathBuf,
    },

    #[command(about = "Verifies all files in a directory against a SHA file")]
    CR {
        #[arg(default_value = ".")]
        #[arg(value_parser = parse_path)]
        directory: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::S { filename } => {
            if !filename.is_file() {
                eprintln!("{} the 's' command does not work with directories. use 'wr or 'cr' instead",
                    "Error:".truecolor(173, 127, 172));
                return;
            }
            let first_filename = filename.file_name().unwrap().to_string_lossy();
            let computed_hash = compute_hash_helper(&filename, &first_filename, true);
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
                eprintln!("{} the 'w' command does not work with directories. use 'wr' or 'cr' instead",
                    "Error:".truecolor(173, 127, 172));
                return;
            }
            let first_filename = filename.file_name().unwrap().to_string_lossy();
            let computed_hash = compute_hash_helper(&filename, &first_filename, true).to_lowercase();
            let lower_computed_hash_and_filename = computed_hash + " " + &first_filename;
            let checksum_file_name = format!("{}.sha256", &first_filename);
            let sha256_file_name_raw = format!("{}.sha256", filename.to_str().unwrap());
            
            let mut checksum_file = match File::create(sha256_file_name_raw) {
                Ok(file) => file,
                Err(e) => {
                    eprintln!("{} failed to create file '{}': {}", "Error:".truecolor(173, 127, 172), checksum_file_name, e);
                    return;
                }
            };
            if let Err(e) = checksum_file.write_all(lower_computed_hash_and_filename.as_bytes()) {
                eprintln!("{} failed to write to file '{}': {}", "Error:".truecolor(173, 127, 172), checksum_file_name, e);
                return;
            }
            println!("{} file '{}' created and written to successfully", "Status:".truecolor(119, 193, 178), checksum_file_name.bold().white());
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
                eprintln!("{} the 'c' command does not work with directories. Use 'wr' or 'cr' instead",
                          "Error:".truecolor(173, 127, 172));
                return;
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
                        let checksum_2 = return_checksum(&input2, &shortened_second_filename, &checksum_1);
                        println!("{} shars extracted checksum from file '{}'",
                                 "Warning:".truecolor(119, 193, 178), shortened_second_filename.bold().white());
                        output_result(&checksum_1, &checksum_2, "USER-SHA", &shortened_second_filename);
                    } else {
                        let checksum_2 = compute_hash_helper(&input2, &shortened_second_filename, true);
                        output_result(&checksum_1, &checksum_2, "USER-SHA", &shortened_second_filename);
                    }
                },
                (false, true) => {
                    let checksum_2 = input2.to_string_lossy().to_lowercase();
                    let first_filename = input1.file_name().unwrap().to_str().unwrap();
                    let shortened_first_filename = shorten_str(first_filename, 18);
                    if is_file_sha(&input1) {
                        let checksum_1 = return_checksum(&input1, &shortened_first_filename, &checksum_2);
                        println!("{} shars extracted checksum from file '{}'",
                                 "Warning:".truecolor(119, 193, 178), shortened_first_filename.bold().white());
                        output_result(&checksum_1, &checksum_2, &shortened_first_filename, "USER-SHA");
                    } else {
                        let checksum_1 = compute_hash_helper(&input1, &shortened_first_filename, true);
                        output_result(&checksum_1, &checksum_2, &shortened_first_filename, "USER-SHA");
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
                            let checksum_1 = match compute_sha_for_file(&first_file_path, first_filename, true) {
                                Ok(checksum_1) => checksum_1,
                                Err(e) => {
                                    eprintln!("Failed to compute hash: {}", e);
                                    std::process::exit(1);
                                }
                            };
                            let checksum_2 = return_checksum(&second_file_path, &shortened_second_filename, &checksum_1);
                            println!("{} shars extracted checksum from file '{}'", "Warning:".truecolor(119, 193, 178), shortened_second_filename.bold().white());
                            output_result(&checksum_1, &checksum_2, &shortened_first_filename, &shortened_second_filename)
                        }

                        (true, false) => {
                            let checksum_2 = compute_hash_helper(&second_file_path, second_filename, true);
                            let checksum_1 = return_checksum(&first_file_path, &shortened_first_filename, &checksum_2);
                            println!("{} shars extracted checksum from file '{}'", "Warning:".truecolor(119, 193, 178), shortened_first_filename.bold().white());
                            output_result(&checksum_1, &checksum_2, &shortened_first_filename, &shortened_second_filename);
                        }

                        (false, true) => {
                            let checksum_1 = compute_hash_helper(&first_file_path, first_filename, true).to_lowercase();
                            let checksum_2 = return_checksum(&second_file_path, &shortened_second_filename, &checksum_1);
                            println!("{} shars extracted checksum from file '{}'", "Warning:".truecolor(119, 193, 178), shortened_second_filename.bold().white());
                            output_result(&checksum_1, &checksum_2, &shortened_first_filename, &shortened_second_filename)
                        }

                        (false, false) => {
                            let checksum_1 = compute_hash_helper(&first_file_path, first_filename, true).to_lowercase();
                            let checksum_2 = compute_hash_helper(&second_file_path, second_filename, true).to_lowercase();
                            output_result(&checksum_1, &checksum_2, &shortened_first_filename, &shortened_second_filename)
                        }
                    }
                }
            }
        }
        
        Commands::WR { directory } => {
            let dir = if directory == PathBuf::from(".") {
                current_dir().unwrap()
            } else {
                directory
            };

            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async {
                    write_recursive(dir).await.unwrap();
                });
        },

        Commands::CR { directory } => {
            let dir = if directory == PathBuf::from(".") {
                current_dir().unwrap()
            } else {
                directory
            };

            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async {
                    check_recursive(dir).await.unwrap();
                });
        },
    }
}

fn read_sha256_file(file_path: &PathBuf, filename: &str) -> io::Result<String> {
    let file_metadata = match fs::metadata(file_path) {
        Ok(metadata) => metadata,
        Err(e) => {
            eprintln!(
                "{} failed to open the file '{}'",
                "Error:".truecolor(173, 127, 172),
                &filename.bold().white()
            );
            return Err(e);
        }
    };

    if file_metadata.len() > 5 * 1024 * 1024 {  // 5 MB
        return Ok(Default::default());
    }

    let mut file = File::open(file_path)?;
    let mut raw_content = Vec::new();
    file.read_to_end(&mut raw_content).map_err(|e| {
        eprintln!(
            "{} failed to read '{}' file content: {}",
            "Error:".truecolor(173, 127, 172), filename.bold().white(), e
        );
        e
    })?;

    if raw_content.is_empty() {
        eprintln!(
            "{} file '{}' is empty",
            "Error:".truecolor(173, 127, 172), filename
        );
        return Ok(Default::default());
    }

    if let Ok(utf8_content) = std::str::from_utf8(&raw_content) {
        return Ok(utf8_content.to_string());
    }

    let (utf16_decoded, _, had_errors) = UTF_16LE.decode(&raw_content);
    if had_errors {
        eprintln!(
            "{} failed to decode file '{}'",
            "Error:".truecolor(173, 127, 172), filename
        );
        return Ok(Default::default());
    }

    Ok(utf16_decoded.to_string())
}

fn is_file_sha(filepath: &PathBuf) -> bool {
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

fn return_checksum(file_path: &PathBuf, shortened_filename: &str, checksum_1: &str) -> String {
    let content = match read_sha256_file(file_path, shortened_filename) {
        Ok(content) => content.to_string(),
        Err(_) => return String::new()
    };

    let re = match Regex::new(&format!(
        r"\b{}[0-9a-fA-F]{{{}}}\b",
        regex_lite::escape(checksum_1),
        64 - checksum_1.len()
    )) {
        Ok(re) => re,
        Err(_) => return String::new()
    };

    if let Some(mat) = re.find(&content) {
        return mat.as_str().trim().to_string();
    }

    let re_any = Regex::new(r"\b[0-9a-fA-F]{64}\b").unwrap();
    if let Some(mat) = re_any.find(&content) {
        return mat.as_str().trim().to_string();
    }

    String::new()
}

fn highlight_differences(a: &str, b: &str) -> String {
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

fn clear_spinner_and_flush(spinner: &mut Spinner) {
    spinner.clear();
    io::stdout().flush().unwrap();
}

fn strip_prefix<'a>(full_path: &'a Path, base_path: &Path) -> &'a Path {
    full_path.strip_prefix(base_path).unwrap_or(full_path)
}

fn shorten_str(file_name: &str, max_len: usize) -> String {
    if file_name.len() > max_len {
        let start = &file_name[..9];
        let end = &file_name[file_name.len() - 9..];
        format!("{}...{}", start, end)
    } else {
        file_name.to_string()
    }
}

fn parse_path(s: &str) -> Result<PathBuf, String> {
    let clean_str = s.trim_matches('"').trim_matches('\'');
    if clean_str.len() == 64 && clean_str.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(PathBuf::from(clean_str));
    }
    let path_buf = PathBuf::from(clean_str);
    if !path_buf.exists() {
        return Err(format!("{} no file found in '{}'", "error:".truecolor(173, 127, 172), clean_str));
    }

    Ok(path_buf)
}

 fn output_result(checksum_1: &str, checksum_2: &str, padded_filename_1: &str, padded_filename_2: &str) {
     let lower_checksum_1 = &checksum_1.to_lowercase();
     let lower_checksum_2 = &checksum_2.to_lowercase();
     let squiggles = highlight_differences(lower_checksum_1, lower_checksum_2);
     println!("{} : '{}'", lower_checksum_1.white(), padded_filename_1.trim());
     if squiggles.contains('~') {
         println!("{}", squiggles.bold())
     }
     println!("{} : '{}'", lower_checksum_2.white(), padded_filename_2.trim());
     if lower_checksum_1 == lower_checksum_2 {
         println!("{} {}", "Status:".truecolor(119, 193, 178), "[ OK ]".bold());
     } else {
         println!("{} {}", "Status:".truecolor(173, 127, 172), "[ !! ]".bold());
     }
 }