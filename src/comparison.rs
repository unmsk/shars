use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use crate::hasher::compute_sha_for_file;
use crate::utils::{is_file_sha, shorten_str, return_checksum, highlight_differences};
use colored::*;

pub struct ComparisonHandler {
    input1: PathBuf,
    input2: PathBuf,
}

#[derive(Debug)]
enum InputType {
    Checksum(String),
    File(PathBuf),
}

impl ComparisonHandler {
    pub fn new(input1: PathBuf, input2: PathBuf) -> Self {
        Self { input1, input2 }
    }

    pub fn compare(self) -> Result<()> {
        self.validate_inputs()?;
        
        let input1_type = self.classify_input(&self.input1);
        let input2_type = self.classify_input(&self.input2);
        
        match (input1_type, input2_type) {
            (InputType::Checksum(c1), InputType::Checksum(c2)) => {
                self.compare_checksums(&c1, &c2, "USER-SHA-1", "USER-SHA-2");
                Ok(())
            },
            (InputType::Checksum(checksum), InputType::File(file)) => {
                self.compare_checksum_with_file(&checksum, &file, "USER-SHA", true)
            },
            (InputType::File(file), InputType::Checksum(checksum)) => {
                self.compare_checksum_with_file(&checksum, &file, "USER-SHA", false)
            },
            (InputType::File(file1), InputType::File(file2)) => {
                self.compare_files(&file1, &file2)
            },
        }
    }

    fn validate_inputs(&self) -> Result<()> {
        for input in [&self.input1, &self.input2] {
            if !self.is_checksum(input) && input.exists() && input.is_dir() {
                bail!("the 'c' command does not work with directories. Use 'wr' or 'cr' instead");
            }
        }
        Ok(())
    }

    fn classify_input(&self, path: &Path) -> InputType {
        if self.is_checksum(path) {
            InputType::Checksum(path.to_string_lossy().to_lowercase())
        } else {
            InputType::File(path.to_path_buf())
        }
    }

    fn is_checksum(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        path_str.len() == 64 && path_str.chars().all(|c| c.is_ascii_hexdigit())
    }

    fn compare_checksums(&self, checksum1: &str, checksum2: &str, label1: &str, label2: &str) {
        self.output_result(checksum1, checksum2, label1, label2);
    }

    fn compare_checksum_with_file(&self, checksum: &str, file: &PathBuf, checksum_label: &str, checksum_first: bool) -> Result<()> {
        let filename = file.file_name()
            .and_then(|n| n.to_str())
            .context("Failed to get filename")?;
        let shortened_filename = shorten_str(filename, 18);
        
        let file_checksum = if is_file_sha(file) {
            let extracted = return_checksum(file, &shortened_filename, checksum)
                .with_context(|| format!("Failed to extract checksum from file '{}'", shortened_filename))?;
            println!("{} shars extracted checksum from file '{}'",
                     "Warning:".truecolor(119, 193, 178), 
                     shortened_filename.bold().white());
            extracted
        } else {
            compute_sha_for_file(file, &shortened_filename, true)
                .with_context(|| format!("Failed to compute checksum for file '{}'", shortened_filename))?
                .to_lowercase()
        };

        if checksum_first {
            self.output_result(checksum, &file_checksum, checksum_label, &shortened_filename);
        } else {
            self.output_result(&file_checksum, checksum, &shortened_filename, checksum_label);
        }
        
        Ok(())
    }

    fn compare_files(&self, file1: &PathBuf, file2: &PathBuf) -> Result<()> {
        let filename1 = file1.file_name()
            .and_then(|n| n.to_str())
            .context("Failed to get first filename")?;
        let filename2 = file2.file_name()
            .and_then(|n| n.to_str())
            .context("Failed to get second filename")?;
        let shortened_filename1 = shorten_str(filename1, 18);
        let shortened_filename2 = shorten_str(filename2, 18);

        let (checksum1, checksum2) = self.compute_file_checksums(
            file1, &shortened_filename1,
            file2, &shortened_filename2
        )?;

        self.output_result(&checksum1, &checksum2, &shortened_filename1, &shortened_filename2);
        Ok(())
    }

    fn compute_file_checksums(
        &self, 
        file1: &PathBuf, 
        filename1: &str,
        file2: &PathBuf, 
        filename2: &str
    ) -> Result<(String, String)> {
        let is_sha1 = is_file_sha(file1);
        let is_sha2 = is_file_sha(file2);

        match (is_sha1, is_sha2) {
            (false, false) => {
                // both are regular files
                let checksum1 = compute_sha_for_file(file1, filename1, true)
                    .with_context(|| format!("Failed to compute checksum for '{}'", filename1))?
                    .to_lowercase();
                let checksum2 = compute_sha_for_file(file2, filename2, true)
                    .with_context(|| format!("Failed to compute checksum for '{}'", filename2))?
                    .to_lowercase();
                Ok((checksum1, checksum2))
            },
            (true, false) => {
                // file1 is SHA file, file2 is regular file
                let checksum2 = compute_sha_for_file(file2, filename2, true)
                    .with_context(|| format!("Failed to compute checksum for '{}'", filename2))?
                    .to_lowercase();
                let checksum1 = return_checksum(file1, filename1, &checksum2)
                    .with_context(|| format!("Failed to extract checksum from '{}'", filename1))?;
                println!("{} shars extracted checksum from file '{}'", 
                    "Warning:".truecolor(119, 193, 178), 
                    filename1.bold().white());
                Ok((checksum1, checksum2))
            },
            (false, true) => {
                // file1 is regular file, file2 is SHA file
                let checksum1 = compute_sha_for_file(file1, filename1, true)
                    .with_context(|| format!("Failed to compute checksum for '{}'", filename1))?
                    .to_lowercase();
                let checksum2 = return_checksum(file2, filename2, &checksum1)
                    .with_context(|| format!("Failed to extract checksum from '{}'", filename2))?;
                println!("{} shars extracted checksum from file '{}'", 
                    "Warning:".truecolor(119, 193, 178), 
                    filename2.bold().white());
                Ok((checksum1, checksum2))
            },
            (true, true) => {
                // both are SHA files - compute their checksums
                let checksum1 = compute_sha_for_file(file1, filename1, true)
                    .with_context(|| format!("Failed to compute checksum for '{}'", filename1))?
                    .to_lowercase();
                let checksum2 = compute_sha_for_file(file2, filename2, true)
                    .with_context(|| format!("Failed to compute checksum for '{}'", filename2))?
                    .to_lowercase();
                Ok((checksum1, checksum2))
            }
        }
    }

    fn output_result(&self, checksum1: &str, checksum2: &str, label1: &str, label2: &str) {
        let lower_checksum1 = checksum1.to_lowercase();
        let lower_checksum2 = checksum2.to_lowercase();
        let squiggles = highlight_differences(&lower_checksum1, &lower_checksum2);
        
        println!("{} : '{}'", lower_checksum1, label1.trim());
        if squiggles.contains('~') {
            println!("{}", squiggles);
        }
        println!("{} : '{}'", lower_checksum2, label2.trim());
        
        if lower_checksum1 == lower_checksum2 {
            println!("{} {}", "Status:".truecolor(119, 193, 178), "[ ok ]".bold());
        } else {
            println!("{} {}", "Status:".truecolor(173, 127, 172), "[ !! ]".bold());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_is_checksum_valid() {
        let handler = ComparisonHandler::new(PathBuf::new(), PathBuf::new());
        
        let valid_checksum = Path::new("a1b2c3d4e5f67890123456789012345678901234567890123456789012345678");
        assert!(handler.is_checksum(valid_checksum));
        
        let too_short = Path::new("a1b2c3d4e5f6");
        assert!(!handler.is_checksum(too_short));
        
        let invalid_chars = Path::new("g1b2c3d4e5f67890123456789012345678901234567890123456789012345678");
        assert!(!handler.is_checksum(invalid_chars));
        
        let too_long = Path::new("a1b2c3d4e5f6789012345678901234567890ffff5678901234567890123456785");
        assert!(!handler.is_checksum(too_long));
    }

    #[test]
    fn test_classify_input_checksum() {
        let handler = ComparisonHandler::new(PathBuf::new(), PathBuf::new());
        let checksum_path = Path::new("a1b2c3d4e5f67890123456789012345678901234567890123456789012345678");
        
        match handler.classify_input(checksum_path) {
            InputType::Checksum(checksum) => {
                assert_eq!(checksum, "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678");
            }
            InputType::File(_) => panic!("Expected Checksum, got File"),
        }
    }

    #[test]
    fn test_classify_input_file() {
        let handler = ComparisonHandler::new(PathBuf::new(), PathBuf::new());
        let file_path = Path::new("some_file.txt");
        
        match handler.classify_input(file_path) {
            InputType::File(path) => {
                assert_eq!(path, PathBuf::from("some_file.txt"));
            }
            InputType::Checksum(_) => panic!("Expected File, got Checksum"),
        }
    }

    #[test]
    fn test_validate_inputs_with_directory() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempdir()?;
        let handler = ComparisonHandler::new(dir.path().to_path_buf(), PathBuf::from("some_file.txt"));
        
        let result = handler.validate_inputs();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not work with directories"));
        
        Ok(())
    }

    #[test]
    fn test_validate_inputs_with_checksums() {
        let checksum1 = PathBuf::from("a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890");
        let checksum2 = PathBuf::from("b1a2d3c4f5e6789012345678901234567890123456789012345678901234567890");
        let handler = ComparisonHandler::new(checksum1, checksum2);
        
        let result = handler.validate_inputs();
        assert!(result.is_ok());
    }

    #[test]
    fn test_compare_checksums_identical() {
        let checksum = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678";
        let handler = ComparisonHandler::new(PathBuf::new(), PathBuf::new());
        
        handler.compare_checksums(checksum, checksum, "TEST1", "TEST2");
    }

    #[test]
    fn test_compare_checksums_different() {
        let checksum1 = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678";
        let checksum2 = "b1a2d3c4f5e67890123456789012345678901234567890123456789012345678";
        let handler = ComparisonHandler::new(PathBuf::new(), PathBuf::new());
        
        handler.compare_checksums(checksum1, checksum2, "TEST1", "TEST2");
    }

    #[test]
    fn test_compare_actual_files() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempdir()?;
        
        let file1_path = dir.path().join("file1.txt");
        let file2_path = dir.path().join("file2.txt");
        
        let content = "Hello, world!";
        fs::write(&file1_path, content)?;
        fs::write(&file2_path, content)?;
        
        let handler = ComparisonHandler::new(file1_path, file2_path);
        let result = handler.compare();
        
        assert!(result.is_ok());
        
        Ok(())
    }

    #[test]
    fn test_compare_different_files() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempdir()?;
        
        let file1_path = dir.path().join("file1.txt");
        let file2_path = dir.path().join("file2.txt");
        
        fs::write(&file1_path, "Hello, world!")?;
        fs::write(&file2_path, "Goodbye, world!")?;
        
        let handler = ComparisonHandler::new(file1_path, file2_path);
        let result = handler.compare();
        
        assert!(result.is_ok());
        
        Ok(())
    }
}