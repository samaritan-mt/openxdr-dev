use thiserror::Error;

/**
 * Error enumeration for the agent module.
 * Io - Represents IO errors
 * Yaml - Represents YAML parsing errors
 * UnsupportedPlatform - Indicates that the current platform is not supported
 * Other - Represents other types of errors with a message
 */

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
