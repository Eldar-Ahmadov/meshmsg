use std::{collections::BTreeMap, fs, path::PathBuf};

fn repository_file(path: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(root.join(path)).expect("read repository documentation")
}

fn contract_facts(document: &str) -> BTreeMap<&str, u64> {
    document
        .lines()
        .filter_map(|line| {
            let columns = line.split('|').map(str::trim).collect::<Vec<_>>();
            let name = columns.get(3)?.strip_prefix('`')?.strip_suffix('`')?;
            let value = columns
                .get(2)?
                .split_whitespace()
                .next()?
                .replace(',', "")
                .parse()
                .expect("checked contract limit must begin with an integer");
            Some((name, value))
        })
        .collect()
}

fn json_examples(document: &str) -> Vec<serde_json::Value> {
    // Git may check documentation out with CRLF on Windows. Normalize only the
    // parser input; JSON examples still pass through strict serde_json parsing.
    let normalized = document.replace("\r\n", "\n");
    let mut examples = Vec::new();
    let mut remainder = normalized.as_str();
    while let Some((_, after_open)) = remainder.split_once("```json\n") {
        let (json, after_close) = after_open
            .split_once("\n```")
            .expect("JSON documentation fence must be closed");
        examples.push(serde_json::from_str(json).expect("JSON documentation example must parse"));
        remainder = after_close;
    }
    examples
}

#[test]
fn json_examples_accept_crlf_fenced_blocks() {
    let document =
        "before\r\n```json\r\n{\"protocol_version\":4,\"type\":\"stopping\"}\r\n```\r\nafter\r\n";
    assert_eq!(
        json_examples(document),
        vec![serde_json::json!({
            "protocol_version": 4,
            "type": "stopping"
        })]
    );
}

#[test]
fn authoritative_contract_facts_match_protocol_constants() {
    let document = repository_file("docs/contracts.md");
    let facts = contract_facts(&document);
    let expected = [
        (
            "protocol_version",
            meshmsg_protocol::PROTOCOL_VERSION as u64,
        ),
        (
            "signed_broadcast_envelope_version",
            meshmsg_protocol::SIGNED_BROADCAST_ENVELOPE_VERSION as u64,
        ),
        (
            "max_signed_broadcast_envelope_bytes",
            meshmsg_protocol::MAX_SIGNED_BROADCAST_ENVELOPE_BYTES as u64,
        ),
        (
            "max_broadcast_body_bytes",
            meshmsg_protocol::MAX_BROADCAST_BODY_BYTES as u64,
        ),
        (
            "max_signed_attachment_token_bytes",
            meshmsg_protocol::MAX_SIGNED_ATTACHMENT_TOKEN_BYTES as u64,
        ),
        (
            "max_ipc_path_bytes",
            meshmsg_protocol::MAX_IPC_PATH_BYTES as u64,
        ),
        ("max_peers", meshmsg_protocol::MAX_PEERS as u64),
        ("max_offers", meshmsg_protocol::MAX_OFFERS as u64),
        ("max_offer_scan", meshmsg_protocol::MAX_OFFER_SCAN as u64),
        (
            "max_lifecycle_items",
            meshmsg_protocol::MAX_LIFECYCLE_ITEMS as u64,
        ),
        (
            "max_request_frame_bytes",
            meshmsg_protocol::framing::MAX_REQUEST_FRAME_BYTES as u64,
        ),
        (
            "max_event_frame_bytes",
            meshmsg_protocol::framing::MAX_EVENT_FRAME_BYTES as u64,
        ),
    ];

    assert_eq!(
        facts.len(),
        expected.len(),
        "unexpected contract fact added or omitted"
    );
    for (name, value) in expected {
        assert_eq!(
            facts.get(name),
            Some(&value),
            "contract fact {name} drifted"
        );
    }
}

#[test]
fn authoritative_json_examples_are_v4_and_lifecycle_shapes_are_distinct() {
    let document = repository_file("docs/contracts.md");
    let examples = json_examples(&document);
    assert!(
        !examples.is_empty(),
        "authoritative contract needs JSON examples"
    );

    for example in &examples {
        assert_eq!(
            example
                .get("protocol_version")
                .and_then(serde_json::Value::as_u64),
            Some(meshmsg_protocol::PROTOCOL_VERSION as u64),
            "contract JSON example has the wrong protocol version"
        );
    }

    let keys_for = |kind: &str| {
        let value = examples
            .iter()
            .find(|value| value.get("type").and_then(serde_json::Value::as_str) == Some(kind))
            .unwrap_or_else(|| panic!("missing {kind} contract example"));
        serde_json::from_value::<meshmsg_protocol::ResponseFrame>(value.clone()).unwrap_or_else(
            |error| panic!("{kind} example is not a valid response frame: {error}"),
        );
        value
            .as_object()
            .expect("frame example must be an object")
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
    };

    assert_eq!(
        keys_for("offer_removed"),
        [
            "direction",
            "limited",
            "maximum",
            "offer_id",
            "operation_id",
            "protocol_version",
            "provider",
            "released_bytes",
            "removed_tags",
            "request_id",
            "selected_tags",
            "type",
        ]
    );
    assert_eq!(
        keys_for("offers_pruned"),
        [
            "cutoff_ms",
            "direction",
            "dry_run",
            "limited",
            "maximum",
            "older_than_secs",
            "operation_id",
            "protocol_version",
            "released_bytes",
            "removed_tags",
            "request_id",
            "selected_tags",
            "type",
        ]
    );
}
