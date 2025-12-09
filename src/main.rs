mod agent;
use std::fs;
use std::io;
use std::io::BufRead;


use serde::de::value::Error;

use crate::agent::config::global_to_string;

fn main() -> Result<(), Error> {
    let agent_config = agent::config::Config::load_default().expect("Failed to load agent config");
    println!("Agent Configuration:");
    println!("{}", global_to_string(&agent_config));
    Ok(())
}
