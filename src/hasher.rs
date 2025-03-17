use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use colored::Colorize;
use sha2::{Digest, Sha256};
use spinoff::{spinners, Color, Spinner, Streams};
use crate::clear_spinner_and_flush;

pub fn compute_sha_for_file(filepath: &PathBuf, filename: &str, spinner_switch: bool) -> Result<String, Box<dyn std::error::Error>> {
    let mut spinner_opt = if spinner_switch {
        let loading_message = format!("Loading file '{}'", filename);
        Some(Spinner::new_with_stream(spinners::Line, loading_message, Color::White, Streams::Stdout))
    } else {
        None
    };

    let mut handle_error = |e: std::io::Error, error_message: &str| -> Box<dyn std::error::Error> {
        if let Some(mut spinner) = spinner_opt.take() {
            clear_spinner_and_flush(&mut spinner);
        }
        eprintln!("{} {} '{}': {}",
                  "Error:".truecolor(173, 127, 172),
                  error_message,
                  filename.bold().white(),
                  e);
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

    if let Some(mut spinner) = spinner_opt {
        clear_spinner_and_flush(&mut spinner);
    }

    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

pub fn compute_hash_helper(filepath: &PathBuf, filename: &str, spinner_switch: bool) -> String {
    
    match compute_sha_for_file(filepath, filename, spinner_switch) {
        Ok(computed_hash) => computed_hash,
        Err(_e) => {
            std::process::exit(1);
        }
    }
}