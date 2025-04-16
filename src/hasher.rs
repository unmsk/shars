use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use colored::Colorize;
use indicatif::ProgressBar;
use sha2::{Digest, Sha256};

use crate::utils::{start_spinner};

pub fn compute_sha_for_file(filepath: &PathBuf, filename: &str, not_recursive: bool) -> Result<String, Box<dyn std::error::Error>> {
    let mut spinner_opt: Option<ProgressBar> = if not_recursive {
        let loading_message = format!("Loading file '{}'", filename);
        Some(start_spinner(&loading_message))
    } else {
        None
    };

    let mut handle_error = |e: std::io::Error, error_message: &str| -> Box<dyn std::error::Error> {
        if let Some(spinner) = spinner_opt.take() {
            spinner.finish_and_clear();
        }
        if not_recursive {
            eprintln!(
                "{} {} '{}': {}",
                "Error:".truecolor(173, 127, 172),
                error_message,
                filename.bold().white(),
                e
            );
        }
        Box::new(e)
    };

    let file = match File::open(filepath) {
        Ok(file) => file,
        Err(e) => return Err(handle_error(e, "failed to open the file")),
    };

    let mut reader = BufReader::new(&file);
    let mut hasher = Sha256::new();
    let mut buffer = [0; 65536];

    loop {
        let bytes_read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(bytes_read) => bytes_read,
            Err(e) => return Err(handle_error(e, "failed to read the file")),
        };
        hasher.update(&buffer[..bytes_read]);
    }

    if let Some(spinner) = spinner_opt {
        spinner.finish_and_clear();
    }

    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}
