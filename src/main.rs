use anyhow::{Context, Result};
use clap::{Parser, Subcommand, crate_authors, crate_description, crate_name, crate_version};
use colored::*;
use std::path::PathBuf;
use std::process;

mod compare;
mod hasher;
mod recursive_ops;
mod util;

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
    #[command(about = "computes file checksum")]
    S { file: PathBuf },

    #[command(about = "computes string checksum")]
    T { text: String },

    #[command(about = "compares two inputs (files or checksums)")]
    C {
        #[arg(help = "file or checksum")]
        input1: String,
        #[arg(help = "file or checksum")]
        input2: String,
    },

    #[command(about = "computes checksums for a directory tree and writes them to a .sha file")]
    WR {
        dir: Option<PathBuf>,
        #[arg(short = 'F', long, help = "show per-file details")]
        verbose: bool,
    },

    #[command(about = "compares checksums from a .sha file against a directory tree")]
    CR {
        dir: Option<PathBuf>,
        #[arg(short = 'F', long, help = "show per-file details")]
        verbose: bool,
    },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{} {:#}", "error:".red().bold(), e);
        process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::S { file } => handle_single_file(file),
        Commands::C { input1, input2 } => compare::handle_c_command(&input1, &input2),
        Commands::T { text } => handle_text(text),
        Commands::WR { dir, verbose } => {
            let target_dir = resolve_directory(dir)?;
            recursive_ops::handle_wr_command(&target_dir, verbose)
        }
        Commands::CR { dir, verbose } => {
            let target_dir = resolve_directory(dir)?;
            recursive_ops::handle_cr_command(&target_dir, verbose)
        }
    }
}

fn handle_single_file(file: PathBuf) -> Result<()> {
    anyhow::ensure!(file.exists(), "file {:?} not found", file);

    let file_size = std::fs::metadata(&file)
        .with_context(|| format!("failed retrieving file size for {:?}", file))?
        .len();

    let file_size_str = util::format_file_size(file_size);
    let pb = util::start_progress_bar(
        &format!("computing SHA-256 for {:?} ({})", file, file_size_str),
        file_size,
    );

    let hash = hasher::hash_file_sha256_with_progress(&file, Some(&pb))
        .with_context(|| format!("failed to hash file {:?}", file))?;

    let filename = file
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("<invalid>");
    util::finish_progress_bar(&pb, &format!("{} : {}", hash, filename));
    Ok(())
}

fn handle_text(text: String) -> Result<()> {
    let hash = hasher::hash_text_sha256(&text);
    println!("SHA-256: {}", hash);
    Ok(())
}

fn resolve_directory(dir: Option<PathBuf>) -> Result<PathBuf> {
    match dir {
        Some(d) => Ok(d),
        None => std::env::current_dir().context("failed retrieving current directory"),
    }
}
