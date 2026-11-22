//! Shared node constants.

use std::time::Duration;

pub(super) const BLOB_GC_INTERVAL: Duration = Duration::from_secs(60 * 60);
pub(super) const OPERATION_CACHE_CAPACITY: usize = 1_024;
pub(super) const OPERATION_CACHE_TTL: Duration = Duration::from_secs(10 * 60);

pub(crate) const DEFAULT_MAX_ATTACHMENT_STORAGE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub(crate) const DEFAULT_MIN_FREE_SPACE_BYTES: u64 = 1024 * 1024 * 1024;
pub(crate) const DEFAULT_ATTACHMENT_RETENTION_SECS: u64 = 0;
