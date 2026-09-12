use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    meshmsg::entry(std::env::args_os().collect()).await
}
