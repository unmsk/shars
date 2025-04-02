use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use colored::Colorize;
use encoding_rs::UTF_16LE;

pub fn read_sha256_file(file_path: &PathBuf, filename: &str) -> Result<String, Box<dyn std::error::Error>> {
    let format_error = |e: &dyn std::fmt::Display, message: &str| {
        eprintln!(
            "{} {} '{}': {}",
            "Error:".truecolor(173, 127, 172),
            message,
            filename.bold().white(),
            e
        );
    };

    #[derive(Debug)]
    enum FileContentError {
        Empty,
        TooLarge,
        DecodingFailed,
    }

    impl std::fmt::Display for FileContentError {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            match self {
                Self::Empty => write!(f, "file is empty"),
                Self::TooLarge => write!(f, "file exceeds maximum size (5MB)"),
                Self::DecodingFailed => write!(f, "failed to decode file content"),
            }
        }
    }

    impl std::error::Error for FileContentError {}

    let file_metadata = match fs::metadata(file_path) {
        Ok(metadata) => metadata,
        Err(e) => {
            format_error(&e, "failed to access metadata for");
            return Err(Box::new(e));
        }
    };

    if file_metadata.len() > 5 * 1024 * 1024 {  // 5 MB
        let error = FileContentError::TooLarge;
        format_error(&error, "cannot process");
        return Err(Box::new(error));
    }

    let mut file = match File::open(file_path) {
        Ok(file) => file,
        Err(e) => {
            format_error(&e, "failed to open");
            return Err(Box::new(e));
        }
    };

    let mut raw_content = Vec::new();
    match file.read_to_end(&mut raw_content) {
        Ok(_) => {},
        Err(e) => {
            format_error(&e, "failed to read content from");
            return Err(Box::new(e));
        }
    }

    if raw_content.is_empty() {
        let error = FileContentError::Empty;
        format_error(&error, "cannot process");
        return Err(Box::new(error));
    }

    if let Ok(utf8_content) = std::str::from_utf8(&raw_content) {
        return Ok(utf8_content.to_string());
    }

    let (utf16_decoded, _, had_errors) = UTF_16LE.decode(&raw_content);
    if had_errors {
        let error = FileContentError::DecodingFailed;
        format_error(&error, "failed to decode");
        return Err(Box::new(error));
    }

    Ok(utf16_decoded.to_string())
}