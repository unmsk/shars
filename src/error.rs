use std::fmt;

#[derive(Debug)]
pub enum SharsError {
    IoError(std::io::Error),
    InvalidPath(String),
    InvalidDirectory(String),
    InvalidFile(String),
    ChecksumError(String),
}

impl fmt::Display for SharsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SharsError::IoError(e) => write!(f, "{}", e),
            SharsError::InvalidPath(msg) => write!(f, "{}", msg),
            SharsError::InvalidDirectory(msg) => write!(f, "{}", msg),
            SharsError::InvalidFile(msg) => write!(f, "{}", msg),
            SharsError::ChecksumError(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for SharsError {}

impl From<std::io::Error> for SharsError {
    fn from(err: std::io::Error) -> Self {
        SharsError::IoError(err)
    }
} 