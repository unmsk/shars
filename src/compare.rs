use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::util;
use crate::util::warning_tag;

pub fn handle_c_command(input1: &str, input2: &str) -> Result<()> {
    let path1 = PathBuf::from(input1);
    let path2 = PathBuf::from(input2);


    let (_checksum1, _checksum2, match_message) =
        if path1.extension().and_then(|s| s.to_str()) == Some("sha256") {
            let other_checksum = util::resolve_to_checksum_with_progress_bar(input2, "Input 2")
                .with_context(|| format!("failed processing input ('{}')", input2))?;

            let (sha256_checksum, _) =
                util::resolve_sha256_file_input(input1, &other_checksum, "Input 1")
                    .with_context(|| format!("failed processing SHA256 file ('{}')", input1))?;

            let match_msg = if sha256_checksum == other_checksum {
                format!("[ ok ] : hash found in {}", input1)
            } else {
                format!("{} : no matching checksum found in {}", warning_tag(), input1)
            };

            (sha256_checksum, other_checksum, match_msg)

        } else if path2.extension().and_then(|s| s.to_str()) == Some("sha256") {
            let other_checksum = util::resolve_to_checksum_with_progress_bar(input1, "Input 1")
                .with_context(|| format!("failed processing input ('{}')", input1))?;

            let (sha256_checksum, _) =
                util::resolve_sha256_file_input(input2, &other_checksum, "Input 2")
                    .with_context(|| format!("failed processing SHA256 file ('{}')", input2))?;

            let match_msg = if sha256_checksum == other_checksum {
                format!("[ ok ] : hash found in {}", input2)
            } else {
                format!("{} : no matching checksum found in {}", warning_tag(), input2)
            };

            (other_checksum, sha256_checksum, match_msg)
        } else {
            let checksum1 = util::resolve_to_checksum_with_progress_bar(input1, "Input 1")
                .with_context(|| format!("failed processing input ('{}')", input1))?;

            let checksum2 = util::resolve_to_checksum_with_progress_bar(input2, "Input 2")
                .with_context(|| format!("failed processing input ('{}')", input2))?;

            let match_msg = if checksum1 == checksum2 {
                "[ ok ] : checksums match".to_string()
            } else {
                format!("{} : checksum mismatch", warning_tag())
            };

            (checksum1, checksum2, match_msg)
        };

    println!("{}", match_message);

    Ok(())
}
