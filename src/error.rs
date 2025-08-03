use std::fmt;

#[derive(Debug)]
pub enum SharsError {
    IoError(std::io::Error),
    InvalidPath(String),
    InvalidDirectory(String),
    InvalidFile(String),
    ChecksumError(String),
    RegexError(String),
}

impl fmt::Display for SharsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SharsError::IoError(e) => write!(f, "IO error: {}", e),
            SharsError::InvalidPath(msg) => write!(f, "Invalid path: {}", msg),
            SharsError::InvalidDirectory(msg) => write!(f, "Invalid directory: {}", msg),
            SharsError::InvalidFile(msg) => write!(f, "Invalid file: {}", msg),
            SharsError::ChecksumError(msg) => write!(f, "Checksum error: {}", msg),
            SharsError::RegexError(msg) => write!(f, "Regex error: {}", msg),
        }
    }
}

impl std::error::Error for SharsError {}

impl From<std::io::Error> for SharsError {
    fn from(err: std::io::Error) -> Self {
        SharsError::IoError(err)
    }
}

impl From<regex_lite::Error> for SharsError {
    fn from(err: regex_lite::Error) -> Self {
        SharsError::RegexError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn test_error_display() {
        let io_error = SharsError::IoError(io::Error::new(io::ErrorKind::NotFound, "file not found"));
        assert!(io_error.to_string().contains("IO error"));
        
        let invalid_path = SharsError::InvalidPath("test path".to_string());
        assert_eq!(invalid_path.to_string(), "Invalid path: test path");
        
        let invalid_dir = SharsError::InvalidDirectory("test dir".to_string());
        assert_eq!(invalid_dir.to_string(), "Invalid directory: test dir");
        
        let invalid_file = SharsError::InvalidFile("test file".to_string());
        assert_eq!(invalid_file.to_string(), "Invalid file: test file");
        
        let checksum_error = SharsError::ChecksumError("checksum issue".to_string());
        assert_eq!(checksum_error.to_string(), "Checksum error: checksum issue");
        
        let regex_error = SharsError::RegexError("regex issue".to_string());
        assert_eq!(regex_error.to_string(), "Regex error: regex issue");
    }

    #[test]
    fn test_from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");
        let shars_err: SharsError = io_err.into();
        
        match shars_err {
            SharsError::IoError(_) => {},
            _ => panic!("Expected IoError variant"),
        }
    }

    #[test]
    fn test_error_trait() {
        let error = SharsError::ChecksumError("test".to_string());
        
        let _: &dyn std::error::Error = &error;
    }
}