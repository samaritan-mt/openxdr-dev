use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("unsupported platform")]
    UnsupportedPlatform,
    #[error("other error: {0}")]
    Other(String),
}
