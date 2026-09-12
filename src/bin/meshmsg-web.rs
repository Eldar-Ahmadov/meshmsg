use anyhow::Result;
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf, process::ExitCode};

/// Optional loopback HTTP bridge for a running meshmsg daemon.
#[derive(Debug, Parser)]
#[command(name = "meshmsg-web", version)]
struct Cli {
    /// State directory (defaults to $XDG_DATA_HOME/meshmsg)
    #[arg(long, env = "MESHMSG_STATE_DIR")]
    state_dir: Option<PathBuf>,
    /// Loopback HTTP listener; expose only through Tailscale Serve, never Funnel
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: SocketAddr,
    /// Exact public HTTPS origin, e.g. https://host.tailnet-name.ts.net (no trailing slash)
    #[arg(long)]
    origin: Option<String>,
}

impl Cli {
    fn state_dir(&self) -> PathBuf {
        self.state_dir.clone().unwrap_or_else(|| {
            dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("meshmsg")
        })
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    meshmsg::web::run(&cli.state_dir(), cli.listen, cli.origin).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_loopback_and_accepts_an_explicit_https_origin() {
        let cli = Cli::try_parse_from(["meshmsg-web"]).unwrap();
        assert_eq!(cli.listen.to_string(), "127.0.0.1:8787");
        assert!(cli.origin.is_none());
        assert!(Cli::try_parse_from([
            "meshmsg-web",
            "--listen",
            "127.0.0.1:9898",
            "--origin",
            "https://node.example.ts.net",
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["meshmsg-web", "--listen", "not-an-address"]).is_err());
    }
}
