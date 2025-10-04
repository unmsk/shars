use std::path::PathBuf;

use crate::util;
use crate::util::Shorten;

pub fn handle_c_command(input1: &str, input2: &str) {
    let path1 = PathBuf::from(input1);
    let path2 = PathBuf::from(input2);

    let is_hash1 = util::is_hex_64(input1);
    let is_hash2 = util::is_hex_64(input2);

    let (checksum1, checksum2, match_message) = if path1.extension().and_then(|s| s.to_str()) == Some("sha256") {
        let other_checksum = match util::resolve_to_checksum_with_progress_bar(input2, "Input 2") {
            Ok(checksum) => checksum,
            Err(e) => {
                eprintln!("{} failed processing input ('{}'): {}", util::error_tag(), input2, e);
                return;
            }
        };

        let sha256_checksum = match util::resolve_sha256_file_input(input1, &other_checksum, "Input 1") {
            Ok(checksum) => checksum,
            Err(e) => {
                eprintln!("{} failed processing SHA256 file ('{}'): {}", util::error_tag(), input1, e);
                return;
            }
        };

        let match_msg = if sha256_checksum == other_checksum {
            format!("[ ok ] : hash found in {}", input1)
        } else {
            format!("{} : matching hash not found in {}, using first checksum from file", util::warning_tag(), input1)
        };

        (sha256_checksum, other_checksum, match_msg)
    } else if path2.extension().and_then(|s| s.to_str()) == Some("sha256") {
        let other_checksum = match util::resolve_to_checksum_with_progress_bar(input1, "Input 1") {
            Ok(checksum) => checksum,
            Err(e) => {
                eprintln!("{} failed processing input ('{}'): {}", util::error_tag(), input1, e);
                return;
            }
        };

        let sha256_checksum = match util::resolve_sha256_file_input(input2, &other_checksum, "Input 2") {
            Ok(checksum) => checksum,
            Err(e) => {
                eprintln!("{} failed processing SHA256 file ('{}'): {}", util::error_tag(), input2, e);
                return;
            }
        };

        let match_msg = if sha256_checksum == other_checksum {
            format!("[ ok ] : hash found in {}", input2)
        } else {
            format!("{} : matching hash not found in {}, using first checksum from file", util::warning_tag(), input2)
        };

        (other_checksum, sha256_checksum, match_msg)
    } else {
        let checksum1 = match util::resolve_to_checksum_with_progress_bar(input1, "Input 1") {
            Ok(checksum) => checksum,
            Err(e) => {
                eprintln!("{} failed processing input ('{}'): {}", util::error_tag(), input1, e);
                return;
            }
        };

        let checksum2 = match util::resolve_to_checksum_with_progress_bar(input2, "Input 2") {
            Ok(checksum) => checksum,
            Err(e) => {
                eprintln!("{} failed processing input ('{}'): {}", util::error_tag(), input2, e);
                return;
            }
        };

        let match_msg = if checksum1 == checksum2 {
            "[ ok ] : checksums match".to_string()
        } else {
            format!("{} : checksums differ", util::warning_tag())
        };

        (checksum1, checksum2, match_msg)
    };

    let display1 = if is_hash1 {
        "USER-HASH-1".to_string()
    } else {
        path1.file_name()
            .map(|s| s.to_string_lossy().shorten())
            .unwrap_or_else(|| "<invalid>".to_string())
    };

    let display2 = if is_hash2 {
        "USER-HASH-2".to_string()
    } else {
        path2.file_name()
            .map(|s| s.to_string_lossy().shorten())
            .unwrap_or_else(|| "<invalid>".to_string())
    };

    let max_width = display1.len().max(display2.len());

    if checksum1 == checksum2 {
        println!("{}", match_message);
    } else {
        println!(
            "{}\n     {:width$} : {}\n     {:width$} : {}",
            match_message,
            display1,
            checksum1,
            display2,
            checksum2,
            width = max_width
        );
    }

}