mod alias;
mod attachment;
mod bench_tui;
mod cli;
mod config;
mod contracts;
mod direct;
mod direct_replay;
mod invite;
mod ipc;
mod message;
mod node;
mod peers;
mod web;

use alias::AliasConfig;
use anyhow::{Context, Result};
use clap::Parser;
use cli::{AliasCommand, Cli, Command, OffersCommand};
use config::State;
use invite::Invite;

fn json_mode_requested(arguments: impl IntoIterator<Item = std::ffi::OsString>) -> bool {
    arguments
        .into_iter()
        .skip(1)
        .take_while(|argument| argument != "--")
        .any(|argument| argument == "--json")
}

fn authoritative_contract_failure(error: &anyhow::Error) -> Option<contracts::ErrorEnvelopeV1> {
    error
        .downcast_ref::<contracts::ContractFailure>()
        .map(|failure| failure.0.clone())
}

#[tokio::main]
async fn main() {
    let json = json_mode_requested(std::env::args_os());
    if let Err(error) = run().await {
        if json {
            // JSON failures use stdout, the same documented stream as JSON
            // successes/NDJSON events. Internal causes and local paths remain on
            // the human-only diagnostic path.
            let authoritative = authoritative_contract_failure(&error);
            let envelope = authoritative.unwrap_or_else(|| {
                let diagnostic = format!("{error:#}");
                let (code, retryable, outcome) = if diagnostic.contains("connect to local daemon") {
                    ("daemon_offline", true, "not_started")
                } else if diagnostic.contains("timed out")
                    || diagnostic.contains("outcome may be unknown")
                {
                    ("command_timeout", true, "unknown")
                } else {
                    ("command_failed", false, "not_started")
                };
                let mut envelope = contracts::ErrorEnvelopeV1::new(
                    code,
                    "Command failed. Run without --json for a local diagnostic.",
                    outcome,
                    retryable,
                );
                envelope.request_id = Some(contracts::new_request_id());
                envelope
            });
            println!("{}", envelope.into_value());
        } else {
            eprintln!("error: {error:#}");
        }
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            print!("{error}");
            return Ok(());
        }
        Err(error) => return Err(anyhow::anyhow!(error.to_string())),
    };
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
        Command::Init { force, no_alias } => {
            let mut alias = AliasConfig::prepare(!no_alias)?;
            let state = State::new_topic();
            let peer = state.save_new_with_alias(&dir, force, &mut alias)?;
            cli::print_result(
                cli.json,
                "initialized",
                serde_json::json!({
                    "type":"initialized", "state_dir":dir, "peer":peer,
                    "topic":state.topic, "advertises_self":true, "has_invite":false,
                    "bootstrap_peer_count":0, "self_advertised":false,
                    "alias":alias.effective(), "alias_enabled":alias.enabled()
                }),
            );
        }
        Command::Join {
            input,
            advertise_self,
            force,
            no_alias,
        } => {
            let token = input.into_token()?;
            let invite: Invite = token.parse()?;
            let mut alias = AliasConfig::prepare(!no_alias)?;
            let (state, peer, bootstrap_peer_count) =
                save_joined_state(&dir, token, &invite, advertise_self, force, &mut alias)?;
            cli::print_result(
                cli.json,
                "joined",
                serde_json::json!({
                    "type":"joined", "state_dir":dir, "peer":peer, "topic":state.topic,
                    "advertises_self":advertise_self, "has_invite":true,
                    "bootstrap_peer_count":bootstrap_peer_count, "self_advertised":false,
                    "alias":alias.effective(), "alias_enabled":alias.enabled()
                }),
            );
        }
        Command::Alias { command } => {
            let config = match command {
                AliasCommand::Show => {
                    let (state, secret) = State::load_for_doctor(&dir)?;
                    state.validate_for_identity(secret.public())?;
                    AliasConfig::load_for_identity(&dir, secret.public())?
                }
                AliasCommand::Set { alias } => AliasConfig::set(&dir, &alias)?,
                AliasCommand::Clear => AliasConfig::clear(&dir)?,
                AliasCommand::ResetHostname => AliasConfig::reset_hostname(&dir)?,
            };
            let value = serde_json::json!({
                "type":"alias", "enabled":config.enabled(),
                "hostname":config.hostname(), "custom":config.custom(),
                "alias":config.effective()
            });
            if cli.json {
                cli::print_result(true, "", value);
            } else if let Some(alias) = config.effective() {
                println!("{alias}");
            } else {
                println!("alias disabled");
            }
        }
        Command::Daemon {
            max_attachment_bytes,
            max_attachment_storage_bytes,
            min_attachment_free_bytes,
            attachment_retention_secs,
        } => {
            node::run_daemon(
                &dir,
                cli.json,
                max_attachment_bytes,
                max_attachment_storage_bytes,
                min_attachment_free_bytes,
                attachment_retention_secs,
            )
            .await?
        }
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
                cli::print_result(
                    true,
                    "",
                    serde_json::json!({
                        "type":"invite", "token":token,
                        "advertises_self":state.advertise_self, "has_invite":true,
                        "bootstrap_peer_count":invite.bootstrap_peers.len(),
                        "self_advertised":self_advertised
                    }),
                );
            } else {
                println!("{token}");
            }
        }
        Command::Stop => node::stop(&dir, cli.json).await?,
        Command::Send {
            operation_id,
            to,
            input,
        } => {
            // Allocate or preserve the retry identity before local body
            // validation, but do not contact the daemon or admit its cache.
            let operation_id = operation_id.unwrap_or_else(ipc::new_operation_id);
            let private = to.is_some();
            let maximum = if private {
                message::MAX_PRIVATE_BODY_BYTES
            } else {
                message::MAX_BROADCAST_BODY_BYTES
            };
            let message = input
                .into_message(maximum)
                .and_then(|body| {
                    if private {
                        message::validate_private_body(&body)?;
                    } else {
                        message::validate_broadcast_body(&body)?;
                    }
                    Ok(body)
                })
                .map_err(|error| message::invalid_local_message(&operation_id, error))?;
            node::send_once(&dir, Some(operation_id), to.as_deref(), &message, cli.json).await?
        }
        Command::Share { operation_id, path } => {
            node::share(&dir, operation_id, &path, cli.json).await?
        }
        #[cfg(debug_assertions)]
        Command::TestSignAttachmentFixture {
            operation_id,
            name,
            size,
            kind,
        } => {
            anyhow::ensure!(
                std::env::var_os("MESHMSG_TEST_FIXTURE_SIGNER").as_deref()
                    == Some(std::ffi::OsStr::new("1")),
                "test fixture signer is disabled"
            );
            println!(
                "{}",
                node::signed_attachment_fixture(&dir, &operation_id, &kind, &name, size)?
            );
        }
        Command::Offers { command } => match command {
            None => node::offers(&dir, cli.json).await?,
            Some(OffersCommand::Remove {
                offer_id,
                direction,
                provider,
            }) => {
                node::offers_remove(
                    &dir,
                    &offer_id,
                    direction.map(|value| value.as_str()),
                    provider.as_deref(),
                    cli.json,
                )
                .await?
            }
            Some(OffersCommand::Prune {
                older_than_secs,
                direction,
                dry_run,
                max_delete,
            }) => {
                node::offers_prune(
                    &dir,
                    older_than_secs,
                    direction.map(|value| value.as_str()),
                    dry_run,
                    max_delete,
                    cli.json,
                )
                .await?
            }
        },
        Command::Peers => node::peers(&dir, cli.json).await?,
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
    alias: &mut AliasConfig,
) -> Result<(State, String, usize)> {
    // A newly generated identity cannot already be in this invite. Check before
    // save_new creates an identity generation or replaces committed state.
    if advertise_self {
        invite.ensure_room_for_new_bootstrap_peer()?;
    }
    let bootstrap_peer_count = invite.bootstrap_peers.len();
    let state = State::from_invite(token, invite, advertise_self);
    let peer = state.save_new_with_alias(dir, force, alias)?;
    Ok((state, peer, bootstrap_peer_count))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contextual_contract_failure_remains_authoritative() {
        let mut expected =
            contracts::ErrorEnvelopeV1::new("daemon_disconnected", "", "partial", true);
        expected.request_id = Some("11111111111111111111111111111111".into());
        let error = anyhow::anyhow!("private transport diagnostic")
            .context(contracts::ContractFailure(expected.clone()));
        assert_eq!(authoritative_contract_failure(&error), Some(expected));
    }

    #[test]
    fn json_error_mode_ignores_literals_after_positional_terminator() {
        let args = |values: &[&str]| {
            values
                .iter()
                .map(std::ffi::OsString::from)
                .collect::<Vec<_>>()
        };
        assert!(json_mode_requested(args(&[
            "meshmsg", "send", "--json", "hello"
        ])));
        assert!(json_mode_requested(args(&["meshmsg", "--json", "status"])));
        assert!(!json_mode_requested(args(&[
            "meshmsg", "send", "--", "--json"
        ])));
        assert!(!json_mode_requested(args(&[
            "meshmsg", "send", "--", "text", "--json"
        ])));
    }
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

        let mut alias = AliasConfig::prepare(false).unwrap();
        let error = save_joined_state(&dir, invite.to_string(), &invite, true, true, &mut alias)
            .unwrap_err();

        assert!(error.to_string().contains("maximum"));
        assert_eq!(
            std::fs::read(dir.join("config.json")).unwrap(),
            config_before
        );
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), files_before);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
