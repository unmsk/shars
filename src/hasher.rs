use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use indicatif::ProgressBar;
use sha2::{Digest, Sha256};

use crate::utils::{start_spinner};
use crate::error::SharsError;

pub fn compute_sha_for_file(filepath: &PathBuf, filename: &str, not_recursive: bool) -> Result<String, SharsError> {
    let spinner_opt: Option<ProgressBar> = if not_recursive {
        let loading_message = format!("Loading file '{}'", filename);
        Some(start_spinner(&loading_message))
    } else {
        None
    };

    let file = File::open(filepath)?;

    let mut reader = BufReader::new(&file);
    let mut hasher = Sha256::new();
    let mut buffer = [0; 65536];

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    if let Some(spinner) = spinner_opt {
        spinner.finish_and_clear();
    }

    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}
