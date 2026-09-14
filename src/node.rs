mod bootstrap;
mod commands;
mod common;
mod operation_cache;
mod runtime;
mod supervisor;

pub(crate) use commands::{
    request_operation_id, CommandPolicy, CommandTimeouts, DaemonCommand, ExecutableRequest,
};
pub(crate) use common::{
    DEFAULT_ATTACHMENT_RETENTION_SECS, DEFAULT_MAX_ATTACHMENT_STORAGE_BYTES,
    DEFAULT_MIN_FREE_SPACE_BYTES,
};

use anyhow::Result;
use std::path::Path;

pub async fn run_daemon(
    dir: &Path,
    max_attachment_bytes: u64,
    max_attachment_storage_bytes: u64,
    min_attachment_free_bytes: u64,
    attachment_retention_secs: u64,
) -> Result<()> {
    runtime::run_daemon(
        dir,
        max_attachment_bytes,
        max_attachment_storage_bytes,
        min_attachment_free_bytes,
        attachment_retention_secs,
    )
    .await
}
