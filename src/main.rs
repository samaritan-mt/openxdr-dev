mod agent;

use crate::agent::Agent;

#[tokio::main]
async fn main() -> Result<(), agent::Error> {
    tracing_subscriber::fmt::init();

    let config = agent::Config::load_default()?;
    let mut agent = Agent::new(config).await?;

    // Print out agent-detected environment in a user-friendly format
    let runtime_config = agent.get_config();
    println!("== Agent environment ==");
    println!("  OS type        : {}", runtime_config.os_type_string());
    println!("  Architecture   : {}", runtime_config.arch_type_string());
    println!("  Agent version  : {}", runtime_config.agent_version_string());
    println!("  Distribution   : {}", runtime_config.os_distribution_string());
    println!("  Kernel version : {}", runtime_config.os_kernel_version_string());
    println!("  OS release     : {}", runtime_config.os_release_string());
    println!();
    
    agent.run().await
}
