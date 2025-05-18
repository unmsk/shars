use clap::{Parser, crate_authors, crate_description, crate_name, crate_version, Subcommand};
use std::path::PathBuf;
use crate::utils::parse_path;

#[derive(Parser)]
#[command(
    name = crate_name!(),
    version = crate_version!(),
    about = crate_description!(),
    long_about = None,
    author = crate_authors!()
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
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