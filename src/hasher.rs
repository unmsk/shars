use indicatif::ProgressBar;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;

use crate::error::SharsError;
use crate::utils::start_spinner;

pub fn compute_sha_for_file(
    filepath: &PathBuf,
    filename: &str,
    not_recursive: bool,
) -> Result<String, SharsError> {
    let file = File::open(filepath)?;
    let file_size = file.metadata()?.len();

    let pb_opt: Option<ProgressBar> = if not_recursive {
        let loading_message = format!("processing file '{}'", filename);
        let pb = start_spinner(&loading_message);
        pb.set_length(file_size);
        Some(pb)
    } else {
        None
    };

    let mut reader = BufReader::new(&file);
    let mut hasher = Sha256::new();
    let mut buffer = [0; 65536];
    let mut total_bytes_read = 0;

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
        total_bytes_read += bytes_read as u64;
        if let Some(pb) = &pb_opt {
            pb.set_position(total_bytes_read);
        }
    }

    if let Some(pb) = pb_opt {
        pb.finish_and_clear();
    }

    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}
