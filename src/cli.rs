use anyhow::{bail, Context, Result};
use clap::{ArgGroup, Args, Parser, Subcommand};
use std::{
    fs,
    io::{self, Read},
    path::PathBuf,
};

// The message body cannot fit its signed envelope if it alone exceeds the wire limit.
const MAX_MESSAGE_INPUT_BYTES: usize = 4096;
// Invites are normally a few KiB even at the seed limit; leave ample compatibility headroom.
const MAX_INVITE_INPUT_BYTES: usize = 1024 * 1024;

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

#[derive(Args, Debug)]
#[command(group(
    ArgGroup::new("invite_source")
        .required(true)
        .multiple(false)
        .args(["token", "token_file", "token_stdin"])
))]
pub struct InviteInput {
    /// Invite token (visible in shell history and process listings; prefer a file or stdin)
    pub token: Option<String>,
    /// Read the invite token from this UTF-8 file
    #[arg(long, value_name = "PATH")]
    pub token_file: Option<PathBuf>,
    /// Read the invite token from stdin through EOF
    #[arg(long)]
    pub token_stdin: bool,
}

#[derive(Args, Debug)]
#[command(group(
    ArgGroup::new("message_source")
        .required(true)
        .multiple(false)
        .args(["message", "message_file", "message_stdin"])
))]
pub struct MessageInput {
    /// Message body (visible in shell history and process listings; prefer a file or stdin)
    pub message: Option<String>,
    /// Read the exact message body from this UTF-8 file
    #[arg(long, value_name = "PATH")]
    pub message_file: Option<PathBuf>,
    /// Read the exact message body from stdin through EOF
    #[arg(long)]
    pub message_stdin: bool,
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
        #[command(flatten)]
        input: InviteInput,
        /// Replace existing state and identity
        #[arg(long)]
        force: bool,
    },
    /// Run the local network daemon in the foreground
    Daemon,
    /// Ask the local daemon to shut down
    Stop,
    /// Queue one message for broadcast (not a delivery acknowledgement)
    Send {
        #[command(flatten)]
        input: MessageInput,
    },
    /// Stream incoming messages
    Listen,
    /// Send lines from stdin while receiving messages
    Chat,
    /// Show live daemon configuration and connectivity
    Status,
    /// Validate local state, including the expected public identity
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
        #[command(flatten)]
        input: InviteInput,
        /// Replace existing state and identity
        #[arg(long)]
        force: bool,
    },
    /// Run the persistent bootstrap node
    Run,
    /// Print the current invite token
    Invite,
}

impl InviteInput {
    pub fn into_token(self) -> Result<String> {
        let mut token = match (self.token, self.token_file, self.token_stdin) {
            (Some(token), None, false) => token,
            (None, Some(path), false) => read_file(&path, "invite token", MAX_INVITE_INPUT_BYTES)?,
            (None, None, true) => read_stdin("invite token", MAX_INVITE_INPUT_BYTES)?,
            _ => bail!("exactly one invite token input source is required"),
        };
        if token.ends_with('\n') {
            token.pop();
            if token.ends_with('\r') {
                token.pop();
            }
        }
        anyhow::ensure!(!token.is_empty(), "invite token input is empty");
        Ok(token)
    }
}

impl MessageInput {
    pub fn into_message(self) -> Result<String> {
        match (self.message, self.message_file, self.message_stdin) {
            (Some(message), None, false) => Ok(message),
            (None, Some(path), false) => read_file(&path, "message body", MAX_MESSAGE_INPUT_BYTES),
            (None, None, true) => read_stdin("message body", MAX_MESSAGE_INPUT_BYTES),
            _ => bail!("exactly one message input source is required"),
        }
    }
}

fn read_file(path: &std::path::Path, description: &str, limit: usize) -> Result<String> {
    let source = format!("{description} from {}", path.display());
    let file = fs::File::open(path).with_context(|| format!("read {source}"))?;
    read_utf8(file, &source, limit)
}

fn read_stdin(description: &str, limit: usize) -> Result<String> {
    read_utf8(
        io::stdin().lock(),
        &format!("{description} from stdin"),
        limit,
    )
}

fn read_utf8(reader: impl Read, source: &str, limit: usize) -> Result<String> {
    let mut bytes = Vec::with_capacity(limit.min(8192));
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {source}"))?;
    anyhow::ensure!(
        bytes.len() <= limit,
        "{source} exceeds the {limit}-byte input limit"
    );
    String::from_utf8(bytes).with_context(|| format!("decode {source} as UTF-8"))
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    fn parse(arguments: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("meshmsg").chain(arguments.iter().copied()))
    }

    #[test]
    fn legacy_and_new_input_forms_parse() {
        assert!(parse(&["join", "token"]).is_ok());
        assert!(parse(&["join", "--token-file", "invite.txt"]).is_ok());
        assert!(parse(&["join", "--token-stdin"]).is_ok());
        assert!(parse(&["seed", "join", "token"]).is_ok());
        assert!(parse(&["seed", "join", "--token-file", "invite.txt"]).is_ok());
        assert!(parse(&["seed", "join", "--token-stdin"]).is_ok());
        assert!(parse(&["send", "message"]).is_ok());
        assert!(parse(&["send", "--message-file", "message.txt"]).is_ok());
        assert!(parse(&["send", "--message-stdin"]).is_ok());
    }

    #[test]
    fn input_source_is_required_and_sources_conflict() {
        for arguments in [vec!["join"], vec!["seed", "join"], vec!["send"]] {
            assert_eq!(
                parse(&arguments).unwrap_err().kind(),
                ErrorKind::MissingRequiredArgument
            );
        }
        for arguments in [
            vec!["join", "token", "--token-file", "invite.txt"],
            vec!["join", "token", "--token-stdin"],
            vec!["join", "--token-file", "invite.txt", "--token-stdin"],
            vec!["send", "message", "--message-file", "message.txt"],
            vec!["send", "message", "--message-stdin"],
            vec!["send", "--message-file", "message.txt", "--message-stdin"],
        ] {
            assert_eq!(
                parse(&arguments).unwrap_err().kind(),
                ErrorKind::ArgumentConflict
            );
        }
    }

    #[test]
    fn repeated_source_flags_are_rejected() {
        assert!(parse(&["join", "--token-stdin", "--token-stdin"]).is_err());
        assert!(parse(&["send", "--message-file", "one", "--message-file", "two"]).is_err());
    }

    #[test]
    fn invite_normalizes_one_line_ending_only() {
        for (input, expected) in [("token\n", "token"), ("token\r\n", "token")] {
            let value = InviteInput {
                token: Some(input.into()),
                token_file: None,
                token_stdin: false,
            }
            .into_token()
            .unwrap();
            assert_eq!(value, expected);
        }
        for value in [" token ", "token\n\n", "token\r"] {
            let resolved = InviteInput {
                token: Some(value.into()),
                token_file: None,
                token_stdin: false,
            }
            .into_token()
            .unwrap();
            let expected = value.strip_suffix('\n').unwrap_or(value);
            assert_eq!(resolved, expected);
        }
        assert!(InviteInput {
            token: Some("\n".into()),
            token_file: None,
            token_stdin: false,
        }
        .into_token()
        .unwrap_err()
        .to_string()
        .contains("empty"));
    }

    #[test]
    fn file_read_errors_identify_source_without_contents() {
        let path = std::env::temp_dir().join(format!(
            "meshmsg-missing-sensitive-token-{}",
            rand::random::<u64>()
        ));
        let error = InviteInput {
            token: None,
            token_file: Some(path.clone()),
            token_stdin: false,
        }
        .into_token()
        .unwrap_err();
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains(&path.display().to_string()));
        assert!(!diagnostic.contains("actual-invite-contents"));
    }

    #[test]
    fn bounded_reader_rejects_limit_plus_one_without_consuming_the_remainder() {
        let mut reader = io::Cursor::new(b"123456tail".as_slice());
        let error = read_utf8(&mut reader, "test input", 5).unwrap_err();

        assert!(error.to_string().contains("5-byte input limit"));
        assert_eq!(reader.position(), 6);
    }

    #[test]
    fn message_file_preserves_text_exactly_and_rejects_invalid_utf8() {
        let dir = std::env::temp_dir().join(format!("meshmsg-cli-test-{}", rand::random::<u64>()));
        fs::create_dir(&dir).unwrap();
        for (name, bytes) in [
            ("multiline", " one\r\n二\n\0".as_bytes()),
            ("empty", b"".as_slice()),
        ] {
            let path = dir.join(name);
            fs::write(&path, bytes).unwrap();
            let message = MessageInput {
                message: None,
                message_file: Some(path),
                message_stdin: false,
            }
            .into_message()
            .unwrap();
            assert_eq!(message.as_bytes(), bytes);
        }
        let oversized_path = dir.join("oversized");
        fs::write(&oversized_path, vec![b'x'; MAX_MESSAGE_INPUT_BYTES + 1]).unwrap();
        let error = MessageInput {
            message: None,
            message_file: Some(oversized_path),
            message_stdin: false,
        }
        .into_message()
        .unwrap_err();
        assert!(error.to_string().contains("4096-byte input limit"));

        let path = dir.join("invalid");
        fs::write(&path, [0xff]).unwrap();
        let error = MessageInput {
            message: None,
            message_file: Some(path),
            message_stdin: false,
        }
        .into_message()
        .unwrap_err();
        assert!(error.to_string().contains("UTF-8"));
        fs::remove_dir_all(dir).unwrap();
    }
}
