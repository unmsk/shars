use clap::{Parser, Subcommand, crate_name, crate_version, crate_description, crate_authors};
use std::path::PathBuf;

mod hasher;
mod util;
mod recursive_ops;
mod compare;

#[derive(Parser, Debug)]
#[command(
    name = crate_name!(),
    version = crate_version!(),
    about = crate_description!(),
    long_about = None,
    author = crate_authors!()
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(about = "creates a checksum of a given file")]
    S {
        file: PathBuf,
    },

    #[command(about = "compares two inputs (files or checksums)")]
    C {
        #[arg(help = "file or checksum")]
        input1: String,
        #[arg(help = "file or checksum")]
        input2: String,
    },

    T {
        text: String,
    },

    WR {
        #[arg(help = "creates a SHA file containing the checksums of all files in a directory")]
        dir: Option<PathBuf>,
    },

    CR {
        #[arg(help = "verifies all files in a directory against a SHA file")]
        dir: Option<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {

        Commands::S { file } => {
            if !file.exists() {
                eprintln!("{} file {:?} not found", util::error_tag(), file);
                return;
            }

            let file_size = match std::fs::metadata(&file) {
                Ok(metadata) => metadata.len(),
                Err(e) => {
                    eprintln!("{} failed retrieving file size: {}", util::error_tag(), e);
                    return;
                }
            };

            let file_size_str = util::format_file_size(file_size);
            let pb = util::start_progress_bar(&format!("computing SHA-256 for {:?} ({})", file, file_size_str), file_size);
            match crate::hasher::hash_file_sha256_with_progress(&file, Some(&pb)) {
                Ok(hash) => {
                    util::finish_progress_bar(&pb, &format!("{} : {}", file.file_name().and_then(|s| s.to_str()).unwrap_or("<invalid or missing name>"), hash));
                }
                Err(e) => {
                    util::finish_progress_bar(&pb, &format!("{} failed to hash file {:?}: {}", util::error_tag(), file, e));
                }
            }
        }

        Commands::C { input1, input2 } => {
            compare::handle_c_command(&input1, &input2);
        }

        Commands::T { text } => {
            let hash = crate::hasher::hash_text_sha256(&text);
            println!("SHA-256: {}", hash);
        }

        Commands::WR { dir } => {
            let target_dir = match dir {
                Some(d) => d,
                None => match std::env::current_dir() {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("{} failed retrieving current directory: {}", util::error_tag(), e);
                        return;
                    }
                }
            };
            recursive_ops::handle_wr_command(&target_dir);
        }

        Commands::CR { dir } => {
            let target_dir = match dir {
                Some(d) => d,
                None => match std::env::current_dir() {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("{} failed retrieving current directory: {}", util::error_tag(), e);
                        return;
                    }
                }
            };
            recursive_ops::handle_cr_command(&target_dir);
        }
    }
}
