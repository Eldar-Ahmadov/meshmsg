mod attachment;
mod bench_tui;
mod cli;
mod config;
mod invite;
mod ipc;
mod node;
mod web;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Command};
use config::State;
use invite::Invite;

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let is_bench_tui = matches!(&cli.command, Command::BenchTui);
    anyhow::ensure!(
        !(is_bench_tui && cli.json),
        "--json cannot be used with bench-tui; use bench-send or bench-receive for NDJSON"
    );
    if !is_bench_tui {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_writer(std::io::stderr)
            .init();
    }

    let dir = cli.state_dir();
    match cli.command {
        Command::Init { force } => {
            let state = State::new_topic();
            let peer = state.save_new(&dir, force)?;
            cli::print_result(
                cli.json,
                "initialized",
                serde_json::json!({
                    "type":"initialized", "state_dir":dir, "peer":peer,
                    "topic":state.topic, "advertises_self":true, "has_invite":false,
                    "bootstrap_peer_count":0, "self_advertised":false
                }),
            );
        }
        Command::Join {
            input,
            advertise_self,
            force,
        } => {
            let token = input.into_token()?;
            let invite: Invite = token.parse()?;
            let (state, peer, bootstrap_peer_count) =
                save_joined_state(&dir, token, &invite, advertise_self, force)?;
            cli::print_result(
                cli.json,
                "joined",
                serde_json::json!({
                    "type":"joined", "state_dir":dir, "peer":peer, "topic":state.topic,
                    "advertises_self":advertise_self, "has_invite":true,
                    "bootstrap_peer_count":bootstrap_peer_count, "self_advertised":false
                }),
            );
        }
        Command::Daemon => node::run_daemon(&dir, cli.json).await?,
        Command::Web { listen, origin } => web::run(&dir, listen, origin).await?,
        Command::Invite => {
            let (state, secret) = State::load_for_doctor(&dir)?;
            state.validate()?;
            let token = state
                .invite
                .context("invite is not available yet; run `meshmsg daemon` first")?;
            let invite: Invite = token.parse()?;
            let self_advertised = invite
                .bootstrap_peers
                .iter()
                .any(|peer| peer.id == secret.public());
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "type":"invite", "token":token,
                        "advertises_self":state.advertise_self, "has_invite":true,
                        "bootstrap_peer_count":invite.bootstrap_peers.len(),
                        "self_advertised":self_advertised
                    })
                );
            } else {
                println!("{token}");
            }
        }
        Command::Stop => node::stop(&dir, cli.json).await?,
        Command::Send { input } => {
            let message = input.into_message()?;
            node::send_once(&dir, &message, cli.json).await?
        }
        Command::Share { path } => node::share(&dir, &path, cli.json).await?,
        Command::Offers => node::offers(&dir, cli.json).await?,
        Command::Download { input, output } => {
            let offer = input.into_offer()?;
            node::download(&dir, &offer, &output, cli.json).await?
        }
        Command::Listen => node::listen(&dir, cli.json).await?,
        Command::BenchSend { args } => {
            node::bench_send(
                &dir,
                args.run_id,
                args.rate,
                args.duration_secs,
                args.payload_bytes,
                cli.json,
            )
            .await?
        }
        Command::BenchReceive { args } => {
            node::bench_receive(
                &dir,
                args.run_id,
                args.duration_secs,
                args.expected,
                cli.json,
            )
            .await?
        }
        Command::BenchTui => bench_tui::run(&dir).await?,
        Command::Chat => node::chat(&dir, cli.json).await?,
        Command::Status => node::status(&dir, cli.json).await?,
        Command::Doctor => node::doctor(&dir, cli.json).await?,
    }
    Ok(())
}

fn save_joined_state(
    dir: &std::path::Path,
    token: String,
    invite: &Invite,
    advertise_self: bool,
    force: bool,
) -> Result<(State, String, usize)> {
    // A newly generated identity cannot already be in this invite. Check before
    // save_new creates an identity generation or replaces committed state.
    if advertise_self {
        invite.ensure_room_for_new_bootstrap_peer()?;
    }
    let bootstrap_peer_count = invite.bootstrap_peers.len();
    let state = State::from_invite(token, invite, advertise_self);
    let peer = state.save_new(dir, force)?;
    Ok((state, peer, bootstrap_peer_count))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invite::MAX_BOOTSTRAP_PEERS;
    use iroh::{EndpointAddr, SecretKey};
    use iroh_gossip::proto::TopicId;

    #[test]
    fn advertising_join_preflights_capacity_before_replacing_state() {
        let dir = std::env::temp_dir().join(format!(
            "meshmsg-join-preflight-test-{}",
            rand::random::<u64>()
        ));
        State::new_topic().save_new(&dir, false).unwrap();
        let config_before = std::fs::read(dir.join("config.json")).unwrap();
        let files_before = std::fs::read_dir(&dir).unwrap().count();
        let invite = Invite {
            topic: TopicId::from_bytes([9; 32]),
            bootstrap_peers: (0..MAX_BOOTSTRAP_PEERS)
                .map(|_| EndpointAddr::new(SecretKey::generate().public()))
                .collect(),
        };

        let error = save_joined_state(&dir, invite.to_string(), &invite, true, true).unwrap_err();

        assert!(error.to_string().contains("maximum"));
        assert_eq!(
            std::fs::read(dir.join("config.json")).unwrap(),
            config_before
        );
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), files_before);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
