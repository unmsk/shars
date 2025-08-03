use colored::*;
use sha2::{Digest, Sha256};
use std::env::current_dir;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use clap::Parser;

mod recursive_ops;
mod hasher;
mod read;
mod utils;
mod error;
mod cli;
mod comparison;

use hasher::compute_sha_for_file;
use recursive_ops::{check_recursive, write_recursive};
use utils::shorten_str;
use error::SharsError;
use cli::{Cli, Commands};
use comparison::ComparisonHandler;

fn main() {
    if let Err(e) = run(Cli::parse()) {
        let error_color = "Error:".truecolor(173, 127, 172);
        eprintln!("{} {}", error_color, e);
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), SharsError> {
    match cli.command {
        Commands::S { filename } => handle_single_file_checksum(filename),
        Commands::T { text } => handle_text_checksum(text),
        Commands::W { filename } => handle_write_checksum(filename),
        Commands::C { input1, input2 } => {
            let handler = ComparisonHandler::new(input1, input2);
            handler.compare()
        },
        Commands::WR { directory } => handle_write_recursive(directory),
        Commands::CR { directory } => handle_check_recursive(directory),
    }
}

fn handle_single_file_checksum(filename: PathBuf) -> Result<(), SharsError> {
    if !filename.is_file() {
        return Err(SharsError::InvalidFile(
            "the 's' command does not work with directories. use 'wr' or 'cr' instead".to_string()
        ));
    }
    
    let file_name = filename.file_name().unwrap().to_string_lossy();
    let computed_hash = compute_sha_for_file(&filename, &file_name, true)?;
    let shortened_name = shorten_str(&file_name, 18);
    
    println!("{} : '{}'", 
        computed_hash.to_lowercase().bold().white(), 
        shortened_name
    );
    
    Ok(())
}

fn handle_text_checksum(text: String) -> Result<(), SharsError> {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    let checksum = format!("{:x}", hasher.finalize());
    let shortened_input = shorten_str(&text, 18);
    
    println!("{} : '{}'", checksum.bold().white(), shortened_input);
    Ok(())
}

fn handle_write_checksum(filename: PathBuf) -> Result<(), SharsError> {
    if !filename.is_file() {
        return Err(SharsError::InvalidFile(
            "the 'w' command does not work with directories. use 'wr' or 'cr' instead".to_string()
        ));
    }
    
    let file_name = filename.file_name().unwrap().to_string_lossy();
    let computed_hash = compute_sha_for_file(&filename, &file_name, true)?;
    let checksum_content = format!("{} {}", computed_hash.to_lowercase(), file_name);
    let checksum_file_path = filename.with_extension("sha256");
    let checksum_file_name = checksum_file_path.file_name().unwrap().to_string_lossy();
    
    let mut checksum_file = File::create(&checksum_file_path)?;
    checksum_file.write_all(checksum_content.as_bytes())?;
    
    println!("{} file '{}' created and written to successfully", 
        "Status:".truecolor(119, 193, 178), 
        checksum_file_name.bold().white()
    );
    
    Ok(())
}

fn handle_write_recursive(directory: PathBuf) -> Result<(), SharsError> {
    let dir = resolve_directory(directory)?;
    
    tokio::runtime::Runtime::new()?
        .block_on(async {
            write_recursive(dir).await
        })
}

fn handle_check_recursive(directory: PathBuf) -> Result<(), SharsError> {
    let dir = resolve_directory(directory)?;
    
    tokio::runtime::Runtime::new()?
        .block_on(async {
            check_recursive(dir).await
        })
}

fn resolve_directory(directory: PathBuf) -> Result<PathBuf, SharsError> {
    if directory == PathBuf::from(".") {
        current_dir().map_err(SharsError::IoError)
    } else {
        Ok(directory)
    }
}