use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "meshmsg",
    version,
    about = "Peer-to-peer messaging over Iroh Gossip"
)]
pub struct Cli {
    /// State directory (defaults to $XDG_DATA_HOME/meshmsg)
    #[arg(long, global = true, env = "MESHMSG_STATE_DIR")]
    pub state_dir: Option<PathBuf>,
    /// Emit JSON; streaming commands emit NDJSON
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Initialize, run, or invite peers to a seed node
    Seed {
        #[command(subcommand)]
        command: SeedCommand,
    },
    /// Save configuration from an invite token
    Join {
        token: String,
        /// Replace existing state and identity
        #[arg(long)]
        force: bool,
    },
    /// Broadcast one message and exit
    Send { message: String },
    /// Stream incoming messages
    Listen,
    /// Send lines from stdin while receiving messages
    Chat,
    /// Show local configuration and connectivity
    Status,
    /// Validate local state
    Doctor,
}

#[derive(Subcommand, Debug)]
pub enum SeedCommand {
    /// Generate a persistent identity and topic
    Init {
        #[arg(long)]
        force: bool,
    },
    /// Join an existing seed set while retaining a seed role
    Join {
        token: String,
        /// Replace existing state and identity
        #[arg(long)]
        force: bool,
    },
    /// Run the persistent bootstrap node
    Run,
    /// Print the current invite token
    Invite,
}

impl Cli {
    pub fn state_dir(&self) -> PathBuf {
        self.state_dir.clone().unwrap_or_else(|| {
            dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("meshmsg")
        })
    }
}

pub fn print_result(json: bool, human: &str, value: serde_json::Value) {
    if json {
        println!("{value}");
    } else {
        println!("{human}");
    }
}
