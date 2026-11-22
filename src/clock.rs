//! Wall-clock time as Unix milliseconds.

use anyhow::Result;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn unix_timestamp_ms() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64)
}

pub(crate) fn unix_timestamp_ms_saturating(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}
