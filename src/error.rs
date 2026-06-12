//! Error types shared across the crate.

use thiserror::Error;

/// Render an anyhow error with its cause chain on one log-friendly line.
pub fn format_chain(error: &anyhow::Error) -> String {
    error
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
}

/// Errors produced while parsing a forward spec from the CLI or config.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SpecError {
    #[error("empty forward spec")]
    Empty,

    #[error("invalid port {0:?}: {1}")]
    InvalidPort(String, String),

    #[error("missing port in {0:?}")]
    MissingPort(String),

    #[error("malformed namespace selector {0:?}: {1}")]
    BadNamespace(String, String),

    #[error("malformed forward spec {0:?}: {1}")]
    Malformed(String, String),
}
