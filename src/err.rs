use std::io;

use forensic_rs::prelude::ForensicError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignToolError {
    #[error("I/O error")]
    Io(#[from] io::Error),

    #[error("SignTool exited with code {exit_code}: {stderr}")]
    SignToolError { exit_code: i32, stderr: String },

    #[error("{0}")]
    Other(String),
}


impl From<String> for SignToolError {
    fn from(err: String) -> Self {
        SignToolError::Other(err)
    }
}

impl From<ForensicError> for SignToolError {
    fn from(err: ForensicError) -> Self {
        SignToolError::Other(format!("{:?}",err))
    }
}