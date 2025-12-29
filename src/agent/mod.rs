pub use crate::agent::engine::{Engine, Event};
use crate::agent::rule::RuleSet;
pub mod config;
pub mod engine;
mod errors;
pub(crate) mod rule;
pub mod user;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

pub use config::Config;
pub use errors::Error;

/**
 * An agent that processes audit events and generates alerts based on rules.
 */

pub struct Agent {
    config: Config,
    rules: Option<RuleSet>,
}

/**
 * Implementation of the Agent.
 *
 */

impl Agent {
    pub async fn new(config: Config) -> Result<Self, Error> {
        Ok(Self {
            config,
            rules: None,
        })
    }
    /**
     * Runs the agent to process audit events from stdin and output alerts to stdout.
     * Returns an Error if any IO or parsing error occurs.
     */
    pub async fn run(&mut self) -> Result<(), Error> {
        let rules = crate::agent::rule::load_rules(&self.config.rules_path)?;

        let stdin = BufReader::new(tokio::io::stdin());
        let mut lines = stdin.lines();
        let mut stdout = tokio::io::stdout();

        while let Some(line) = lines.next_line().await? {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let event: Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(err) => {
                    tracing::warn!(%err, "failed to parse audit event");
                    continue;
                }
            };

            let rule_id = match event.get("rule_id").and_then(|v| v.as_str()) {
                Some(id) => id,
                None => continue,
            };

            let rule = match rules.rules.iter().find(|r| r.id == rule_id) {
                Some(r) => r,
                None => continue,
            };

            let alert = serde_json::json!({
                "rule": {
                    "id": rule.id,
                    "description": rule.description,
                    "severity": rule.severity,
                },
                "event": event,
            });

            match serde_json::to_vec(&alert) {
                Ok(bytes) => {
                    stdout.write_all(&bytes).await?;
                    stdout.write_all(b"\n").await?;
                }
                Err(err) => {
                    tracing::warn!(%err, "failed to serialize alert");
                }
            }
        }

        Ok(())
    }

    pub fn get_config(&self) -> &Config {
        &self.config
    }

    pub fn get_rules(&self) -> Option<&RuleSet> {
        self.rules.as_ref()
    }
}
