use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StatkeelError {
    #[error("I/O error: {message}")]
    Io { message: String, fix_hint: String },

    #[error("Source error: {message}")]
    Source { message: String, fix_hint: String },

    #[error("Database error: {message}")]
    Database {
        message: String,
        fix_hint: String,
        retryable: bool,
    },

    #[error("SQL parse error: {message}")]
    SqlParse { message: String, fix_hint: String },

    #[error("Unsafe SQL rejected: {message}")]
    UnsafeSql { message: String, fix_hint: String },

    #[error("Rules config error: {message}")]
    Rules { message: String, fix_hint: String },

    #[error("Configuration error: {message}")]
    Config { message: String, fix_hint: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorEnvelope {
    pub ok: bool,
    pub code: &'static str,
    pub message: String,
    pub fix_hint: String,
    pub retryable: bool,
}

impl StatkeelError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Io { .. } => "E_IO",
            Self::Source { .. } => "E_SOURCE",
            Self::Database { .. } => "E_DB",
            Self::SqlParse { .. } => "E_SQL_PARSE",
            Self::UnsafeSql { .. } => "E_UNSAFE_SQL",
            Self::Rules { .. } => "E_RULES",
            Self::Config { .. } => "E_CONFIG",
        }
    }

    pub fn fix_hint(&self) -> &str {
        match self {
            Self::Io { fix_hint, .. }
            | Self::Source { fix_hint, .. }
            | Self::Database { fix_hint, .. }
            | Self::SqlParse { fix_hint, .. }
            | Self::UnsafeSql { fix_hint, .. }
            | Self::Rules { fix_hint, .. }
            | Self::Config { fix_hint, .. } => fix_hint,
        }
    }

    pub fn retryable(&self) -> bool {
        match self {
            Self::Database { retryable, .. } => *retryable,
            _ => false,
        }
    }

    pub fn to_envelope(&self) -> ErrorEnvelope {
        ErrorEnvelope {
            ok: false,
            code: self.code(),
            message: self.to_string(),
            fix_hint: self.fix_hint().to_string(),
            retryable: self.retryable(),
        }
    }

    pub fn io(err: impl std::fmt::Display, path: &str) -> Self {
        Self::Io {
            message: format!("{path}: {err}"),
            fix_hint: format!("Verify that `{path}` exists and is readable/writable."),
        }
    }

    pub fn source(message: impl Into<String>, fix_hint: impl Into<String>) -> Self {
        Self::Source {
            message: message.into(),
            fix_hint: fix_hint.into(),
        }
    }

    pub fn db(message: impl Into<String>, fix_hint: impl Into<String>, retryable: bool) -> Self {
        Self::Database {
            message: message.into(),
            fix_hint: fix_hint.into(),
            retryable,
        }
    }

    pub fn config(message: impl Into<String>, fix_hint: impl Into<String>) -> Self {
        Self::Config {
            message: message.into(),
            fix_hint: fix_hint.into(),
        }
    }
}

pub type Result<T> = std::result::Result<T, StatkeelError>;
