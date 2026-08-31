mod cli;
mod config;
mod invite;
mod node;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Command, SeedCommand};
use config::State;

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let dir = cli.state_dir();
    match cli.command {
        Command::Seed { command } => match command {
            SeedCommand::Init { force } => {
                let state = State::new_seed();
                state.save_new(&dir, force)?;
                let peer = State::load_secret(&dir)?.public().to_string();
                cli::print_result(
                    cli.json,
                    "initialized",
                    serde_json::json!({
                        "type": "initialized", "state_dir": dir, "peer": peer, "topic": state.topic
                    }),
                );
            }
            SeedCommand::Join { token, force } => {
                let invite: invite::Invite = token.parse()?;
                invite.ensure_room_for_new_seed()?;
                let state = State::from_invite(config::Role::Seed, token, &invite);
                state.save_new(&dir, force)?;
                let peer = State::load_secret(&dir)?.public().to_string();
                cli::print_result(
                    cli.json,
                    "seed joined",
                    serde_json::json!({
                        "type":"seed_joined", "state_dir":dir, "peer":peer,
                        "topic":state.topic, "known_seeds":invite.seeds.len()
                    }),
                );
            }
            SeedCommand::Run => node::run_seed_daemon(&dir, cli.json).await?,
            SeedCommand::Invite => {
                let state = State::load(&dir)?;
                state.ensure_role(config::Role::Seed)?;
                let token = state
                    .invite
                    .context("seed has not run yet; run `meshmsg seed run` first")?;
                if cli.json {
                    println!("{}", serde_json::json!({"type":"invite", "token":token}));
                } else {
                    println!("{token}");
                }
            }
        },
        Command::Join { token, force } => {
            let invite: invite::Invite = token.parse()?;
            let state = State::from_invite(config::Role::Member, token, &invite);
            state.save_new(&dir, force)?;
            let peer = State::load_secret(&dir)?.public().to_string();
            cli::print_result(
                cli.json,
                "joined",
                serde_json::json!({
                    "type":"joined", "state_dir":dir, "peer":peer, "topic":state.topic
                }),
            );
        }
        Command::Daemon => node::run_daemon(&dir, cli.json).await?,
        Command::Stop => node::stop(&dir, cli.json).await?,
        Command::Send { message } => node::send_once(&dir, &message, cli.json).await?,
        Command::Listen => node::listen(&dir, cli.json).await?,
        Command::Chat => node::chat(&dir, cli.json).await?,
        Command::Status => node::status(&dir, cli.json).await?,
        Command::Doctor => node::doctor(&dir, cli.json).await?,
    }
    Ok(())
}

use anyhow::Context;
