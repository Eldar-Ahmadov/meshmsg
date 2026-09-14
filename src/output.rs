use anyhow::Result;

pub(crate) fn status(json: bool, frame: &meshmsg_protocol::ResponseFrame) -> Result<()> {
    let value = match &frame.response {
        meshmsg_protocol::Response::Status(value) => value,
        _ => unreachable!("checked response family"),
    };
    if json {
        println!("{}", serde_json::to_string(frame)?);
    } else {
        println!(
            "daemon: running\npeer: {}\ntopic: {}\nalias: {}\nalias enabled: {}\nadvertised aliases: {}\nadvertises self: {}\nhas invite: {}\nbootstrap peers: {}\nself advertised: {}\nendpoint online: {}\ntopic joined: {}\nneighbors: {}\nattachment storage: {} / {} bytes ({} unique blobs, {} / {} pins)\nattachment filesystem available: {} bytes (minimum {})\nattachment storage pressure: {}\nattachment retention: {} seconds",
            value.peer,
            value.topic,
            value.alias.as_ref().map(|alias| alias.as_str()).unwrap_or("(disabled)"),
            value.alias_enabled,
            value.advertised_aliases,
            value.advertises_self,
            value.has_invite,
            value.bootstrap_peer_count,
            value.self_advertised,
            value.endpoint_online,
            value.topic_joined,
            value.neighbors,
            value.attachment_storage.tagged_bytes,
            value.attachment_storage.quota_bytes,
            value.attachment_storage.tagged_blobs,
            value.attachment_storage.tags,
            value.attachment_storage.tag_capacity,
            value.attachment_storage.available_bytes,
            value.attachment_storage.min_free_bytes,
            value.attachment_storage.pressure,
            value.attachment_retention_secs
        );
    }
    Ok(())
}

pub(crate) fn doctor(json: bool, value: &serde_json::Value) {
    if json {
        println!("{value}");
    } else {
        println!("ok: state, identity, topic, and invite are valid");
    }
}

fn terminal_safe(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| {
            if character.is_control() {
                character.escape_default().collect::<Vec<_>>()
            } else {
                vec![character]
            }
        })
        .collect()
}

fn attachment_kind_name(kind: meshmsg_protocol::AttachmentKind) -> &'static str {
    match kind {
        meshmsg_protocol::AttachmentKind::File => "file",
        meshmsg_protocol::AttachmentKind::DirectoryTarV1 => "directory_tar_v1",
    }
}

fn print_peer_snapshot(value: &meshmsg_protocol::PeerSnapshot) {
    println!(
        "self: {}{} ({})",
        value.self_peer.public_key,
        value
            .self_peer
            .alias
            .as_ref()
            .map(|alias| format!(" ({})", alias.as_str()))
            .unwrap_or_default(),
        if value.self_peer.online {
            "online"
        } else {
            "offline"
        }
    );
    for peer in &value.peers {
        println!(
            "peer: {}{} ({})",
            peer.public_key,
            peer.alias
                .as_ref()
                .map(|alias| format!(" ({})", alias.as_str()))
                .unwrap_or_default(),
            if peer.online { "online" } else { "offline" }
        );
    }
}

fn print_peer_transition(action: &str, value: &meshmsg_protocol::PeerTransition) {
    println!(
        "{action}: {}{}",
        value.peer.public_key,
        value
            .peer
            .alias
            .as_ref()
            .map(|alias| format!(" ({})", alias.as_str()))
            .unwrap_or_default()
    );
}

fn offer_listing_warnings(truncated: bool, item_errors: usize) -> Vec<String> {
    let mut warnings = Vec::new();
    if truncated {
        warnings
            .push("WARNING: attachment listing truncated; more pinned blobs may exist".to_owned());
    }
    if item_errors != 0 {
        warnings.push(format!(
            "WARNING: {item_errors} attachment tag(s) could not be read"
        ));
    }
    warnings
}

fn print_offers(value: &meshmsg_protocol::OffersList) {
    if value.blobs.is_empty() {
        println!("no pinned attachment blobs");
    } else {
        for blob in &value.blobs {
            println!(
                "{}  {}  {}  {}  {}  {}  {}  {} bytes  {}",
                blob.direction,
                terminal_safe(blob.name.as_str()),
                attachment_kind_name(blob.kind),
                blob.offer_id,
                blob.provider
                    .as_ref()
                    .map(ToString::to_string)
                    .as_deref()
                    .unwrap_or("-"),
                terminal_safe(&blob.format),
                terminal_safe(&blob.status),
                blob.size
                    .map(|size| size.to_string())
                    .as_deref()
                    .unwrap_or("?"),
                blob.hash
            );
        }
    }
    for warning in offer_listing_warnings(value.truncated, value.item_errors) {
        println!("{warning}");
    }
}

fn print_offer_removed(value: &meshmsg_protocol::OfferRemoved) {
    println!(
        "removed {} attachment pin(s); {} quota bytes released",
        value.removed_tags, value.released_bytes
    );
}

fn print_offers_pruned(value: &meshmsg_protocol::OffersPruned) {
    println!(
        "{} {} attachment pin(s); {} quota bytes released{}",
        if value.dry_run {
            "would remove"
        } else {
            "removed"
        },
        if value.dry_run {
            value.selected_tags
        } else {
            value.removed_tags
        },
        value.released_bytes,
        if value.limited {
            " (more eligible pins remain)"
        } else {
            ""
        }
    );
}

fn print_protocol_error(error: &meshmsg_protocol::ProtocolError) {
    println!(
        "error: {} ({})",
        error.message(),
        error.retry_advice().message()
    );
}

pub(crate) fn response(json: bool, frame: &meshmsg_protocol::ResponseFrame) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string(frame)?);
        return Ok(());
    }
    match &frame.response {
        meshmsg_protocol::Response::Status(_) => println!("daemon running"),
        meshmsg_protocol::Response::Queued(value) => println!(
            "queued locally (delivery not acknowledged): {}",
            terminal_safe(value.body.as_ref())
        ),
        meshmsg_protocol::Response::PrivateAccepted(value) if value.duplicate_accepted => println!(
            "private message was previously accepted by {} (not redelivered; not durable or read)",
            value.to
        ),
        meshmsg_protocol::Response::PrivateAccepted(value) => println!(
            "private message accepted by {} (acceptance only; not durable or read)",
            value.to
        ),
        meshmsg_protocol::Response::PeersSnapshot(value) => print_peer_snapshot(value),
        meshmsg_protocol::Response::Offers(value) => print_offers(value),
        meshmsg_protocol::Response::AttachmentShared(value) => println!(
            "shared {} ({} bytes)\noffer: {}\ndelivery acknowledged: no",
            terminal_safe(value.name.as_str()),
            value.size,
            value.offer.as_str()
        ),
        meshmsg_protocol::Response::OfferRemoved(value) => print_offer_removed(value),
        meshmsg_protocol::Response::OffersPruned(value) => print_offers_pruned(value),
        meshmsg_protocol::Response::DownloadComplete(value) => println!(
            "downloaded {} bytes to {}",
            value.size,
            value.output.display()
        ),
        meshmsg_protocol::Response::Stopping {} => println!("daemon stopping"),
        meshmsg_protocol::Response::Error(error) => print_protocol_error(error),
    }
    Ok(())
}

pub(crate) fn event(json: bool, frame: &meshmsg_protocol::EventFrame) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string(frame)?);
        return Ok(());
    }
    match &frame.event {
        meshmsg_protocol::Event::Connected(value) => println!("connected as {}", value.peer),
        meshmsg_protocol::Event::Message(value) => {
            println!("{}: {}", value.from, terminal_safe(value.body.as_ref()))
        }
        meshmsg_protocol::Event::PrivateMessage(value) => println!(
            "private from {}: {}",
            value.from,
            terminal_safe(value.body.as_ref())
        ),
        meshmsg_protocol::Event::Queued(value) => println!(
            "queued locally (delivery not acknowledged): {}",
            terminal_safe(value.body.as_ref())
        ),
        meshmsg_protocol::Event::AttachmentOffer(value) => println!(
            "{} shared {} ({} bytes)\ndownload with: meshmsg download '{}' --output PATH",
            value.from,
            terminal_safe(value.name.as_str()),
            value.size,
            value.offer.as_str()
        ),
        meshmsg_protocol::Event::AttachmentShared(value) => println!(
            "shared {} ({} bytes)\noffer: {}\ndelivery acknowledged: no",
            terminal_safe(value.name.as_str()),
            value.size,
            value.offer.as_str()
        ),
        meshmsg_protocol::Event::PeersSnapshot(value) => print_peer_snapshot(value),
        meshmsg_protocol::Event::PeerDiscovered(value) => {
            print_peer_transition("peer discovered", value)
        }
        meshmsg_protocol::Event::PeerUpdated(value) => print_peer_transition("peer updated", value),
        meshmsg_protocol::Event::PeerExpired(value) => print_peer_transition("peer expired", value),
        meshmsg_protocol::Event::DownloadStarted { .. } => println!("attachment download started"),
        meshmsg_protocol::Event::DownloadProgress {
            received_bytes,
            total_bytes,
            ..
        } => {
            println!("attachment download: {received_bytes} / {total_bytes} bytes")
        }
        meshmsg_protocol::Event::DownloadComplete(value) => println!(
            "downloaded {} bytes to {}",
            value.size,
            value.output.display()
        ),
        meshmsg_protocol::Event::Lagged { message, .. } => {
            println!("warning: {}", terminal_safe(message))
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_output_escapes_control_sequences() {
        let escaped = terminal_safe("hello\n\u{1b}]0;owned\u{7}");
        assert_eq!(escaped, "hello\\n\\u{1b}]0;owned\\u{7}");
        assert!(!escaped.chars().any(char::is_control));
    }

    #[test]
    fn human_offer_warnings_announce_truncation_and_item_errors() {
        assert_eq!(
            offer_listing_warnings(true, 2),
            vec![
                "WARNING: attachment listing truncated; more pinned blobs may exist",
                "WARNING: 2 attachment tag(s) could not be read",
            ]
        );
    }
}
