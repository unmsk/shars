use anyhow::{Context, Result};
use clap::Parser;
use colored::*;
use sha2::{Digest, Sha256};
use std::env::current_dir;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

mod cli;
mod comparison;
mod hasher;
mod read;
mod recursive_ops;
mod utils;

use cli::{Cli, Commands};
use comparison::ComparisonHandler;
use hasher::compute_sha_for_file;
use recursive_ops::{check_recursive, write_recursive};
use utils::shorten_str;

fn main() {
    if let Err(e) = run(Cli::parse()) {
        let error_color = "Error:".truecolor(173, 127, 172);
        eprintln!("{} {}", error_color, e);
        
        let mut source = e.source();
        while let Some(err) = source {
            eprintln!("  Caused by: {}", err);
            source = err.source();
        }
        
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::S { filename } => handle_single_file_checksum(filename),
        Commands::T { text } => handle_text_checksum(text),
        Commands::W { filename } => handle_write_checksum(filename),
        Commands::C { input1, input2 } => {
            let handler = ComparisonHandler::new(input1, input2);
            handler.compare()
        }
        Commands::WR { directory } => handle_write_recursive(directory),
        Commands::CR { directory } => handle_check_recursive(directory),
    }
}

fn handle_single_file_checksum(filename: PathBuf) -> Result<()> {
    if !filename.is_file() {
        anyhow::bail!("the 's' command does not work with directories. use 'wr' or 'cr' instead");
    }

    let file_name = filename.file_name()
        .context("Failed to get filename")?
        .to_string_lossy();
    
    let computed_hash = compute_sha_for_file(&filename, &file_name, true)
        .with_context(|| format!("Failed to compute hash for '{}'", file_name))?;
    
    let shortened_name = shorten_str(&file_name, 18);

    println!(
        "{} : '{}'",
        computed_hash.to_lowercase().bold().white(),
        shortened_name
    );

    Ok(())
}

fn handle_text_checksum(text: String) -> Result<()> {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    let checksum = format!("{:x}", hasher.finalize());
    let shortened_input = shorten_str(&text, 18);

    println!("{} : '{}'", checksum.bold().white(), shortened_input);
    Ok(())
}

fn handle_write_checksum(filename: PathBuf) -> Result<()> {
    if !filename.is_file() {
        anyhow::bail!("the 'w' command does not work with directories. use 'wr' or 'cr' instead");
    }

    let file_name = filename.file_name()
        .context("Failed to get filename")?
        .to_string_lossy();
    
    let computed_hash = compute_sha_for_file(&filename, &file_name, true)
        .with_context(|| format!("Failed to compute hash for '{}'", file_name))?;
    
    let checksum_content = format!("{} {}", computed_hash.to_lowercase(), file_name);
    let checksum_file_path = filename.with_extension("sha256");
    let checksum_file_name = checksum_file_path.file_name()
        .context("Failed to get checksum filename")?
        .to_string_lossy();

    let mut checksum_file = File::create(&checksum_file_path)
        .with_context(|| format!("Failed to create checksum file '{}'", checksum_file_name))?;
    
    checksum_file.write_all(checksum_content.as_bytes())
        .with_context(|| format!("Failed to write to checksum file '{}'", checksum_file_name))?;

    println!(
        "{} file '{}' created and written to successfully",
        "Status:".truecolor(119, 193, 178),
        checksum_file_name.bold().white()
    );

    Ok(())
}

fn handle_write_recursive(directory: PathBuf) -> Result<()> {
    let dir = resolve_directory(directory)?;
    write_recursive(dir)
}

fn handle_check_recursive(directory: PathBuf) -> Result<()> {
    let dir = resolve_directory(directory)?;
    check_recursive(dir)
}

fn resolve_directory(directory: PathBuf) -> Result<PathBuf> {
    if directory == PathBuf::from(".") {
        current_dir().context("Failed to get current directory")
    } else {
        Ok(directory)
    }
}