use std::io;

use thiserror::Error;

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("resolution failed: {0}")]
    Resolve(String),

    #[error("protocol error: {0}")]
    Protocol(String),
}
