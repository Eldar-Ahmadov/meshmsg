//! Shared node constants and wall-clock helpers.

use anyhow::Result;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(super) const BLOB_GC_INTERVAL: Duration = Duration::from_secs(60 * 60);
pub(super) const OPERATION_CACHE_CAPACITY: usize = 1_024;
pub(super) const OPERATION_CACHE_TTL: Duration = Duration::from_secs(10 * 60);

pub(crate) const DEFAULT_MAX_ATTACHMENT_STORAGE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub(crate) const DEFAULT_MIN_FREE_SPACE_BYTES: u64 = 1024 * 1024 * 1024;
pub(crate) const DEFAULT_ATTACHMENT_RETENTION_SECS: u64 = 0;

pub(super) fn unix_timestamp_ms() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64)
}

pub(super) fn unix_timestamp_ms_saturating(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}
