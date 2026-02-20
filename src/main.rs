mod agent;
use agent::config::global_to_string;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let agent_config = agent::config::Config::load_default().expect("Failed to load agent config");
    println!("{}", global_to_string(&agent_config));

    let app = agent::app::App::new(agent_config);
    app.run().await?;

    Ok(())
}
