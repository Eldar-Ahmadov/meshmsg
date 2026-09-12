use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    meshmsg::bench_tui_entry(std::env::args_os().collect()).await
}
