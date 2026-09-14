#!/usr/bin/env python3
"""Validate the terminal local-input error in a meshmsg chat NDJSON stream."""

import json
import pathlib
import re
import sys

HEX_ID = re.compile(r"[0-9a-f]{32}").fullmatch
BASE_KEYS = {"protocol_version", "request_id", "type"}
EVENT_FIELDS = {
    "connected": {"peer", "endpoint_online", "topic_joined", "alias"},
    "message": {"from", "message_id", "timestamp_ms", "body"},
    "private_message": {
        "private", "from", "message_id", "timestamp_ms", "body",
        "acceptance_acknowledged", "durable", "read",
    },
    "queued": {
        "operation_id", "from", "message_id", "timestamp_ms", "body",
        "delivery_acknowledged",
    },
    "attachment_offer": {
        "from", "message_id", "timestamp_ms", "offer_id", "kind", "name",
        "size", "ticket", "offer",
    },
    "attachment_shared": {
        "operation_id", "from", "message_id", "timestamp_ms", "offer_id",
        "source_digest", "kind", "name", "size", "ticket", "offer",
        "delivery_acknowledged",
    },
    "peers_snapshot": {
        "generated_at_ms", "directory_epoch", "directory_revision", "self", "peers",
    },
    "peer_discovered": {"directory_epoch", "directory_revision", "peer"},
    "peer_updated": {"directory_epoch", "directory_revision", "peer"},
    "peer_expired": {"directory_epoch", "directory_revision", "peer"},
    "download_started": {"operation_id", "output"},
    "download_progress": {"operation_id", "received_bytes", "total_bytes", "output"},
    "download_complete": {
        "operation_id", "token_digest", "offer_id", "kind", "name", "size", "from",
        "output", "mode", "installed", "pinned", "destination_synced",
        "cleanup_complete", "warnings",
    },
    "lagged": {"source", "dropped", "message"},
}
ERROR_KEYS = {
    "protocol_version",
    "request_id",
    "type",
    "code",
    "operation_id",
    "outcome",
}


def canonical_id(value):
    return isinstance(value, str) and HEX_ID(value) is not None


def reject_constant(value):
    raise ValueError(f"non-JSON numeric constant: {value}")


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON field: {key}")
        value[key] = item
    return value


def decode_line(line, number):
    if not line:
        raise AssertionError(f"line {number}: empty NDJSON frame")
    try:
        value = json.loads(
            line,
            parse_constant=reject_constant,
            object_pairs_hook=unique_object,
        )
    except (json.JSONDecodeError, ValueError) as error:
        raise AssertionError(f"line {number}: invalid JSON frame: {error}") from error
    if not isinstance(value, dict):
        raise AssertionError(f"line {number}: frame is not an object")
    if value.get("protocol_version") != 4:
        raise AssertionError(f"line {number}: frame is not protocol v4")
    if not canonical_id(value.get("request_id")):
        raise AssertionError(f"line {number}: request_id is not canonical")
    if not isinstance(value.get("type"), str):
        raise AssertionError(f"line {number}: frame type is missing")
    return value


def validate(text):
    lines = text.splitlines()
    if not lines:
        raise AssertionError("chat produced no NDJSON frames")
    frames = [decode_line(line, number) for number, line in enumerate(lines, 1)]

    errors = [(index, frame) for index, frame in enumerate(frames) if frame["type"] == "error"]
    if len(errors) != 1:
        raise AssertionError(f"expected exactly one terminal error, found {len(errors)}")
    error_index, error = errors[0]
    if error_index != len(frames) - 1:
        raise AssertionError("chat emitted output after its terminal error")

    for number, frame in enumerate(frames[:-1], 1):
        fields = EVENT_FIELDS.get(frame["type"])
        if fields is None:
            raise AssertionError(f"line {number}: non-event frame preceded terminal error")
        if set(frame) != BASE_KEYS | fields:
            raise AssertionError(f"line {number}: event does not have its canonical fields")

    if set(error) != ERROR_KEYS:
        raise AssertionError("terminal error does not have the canonical protocol-v4 fields")
    if error["code"] != "invalid_message" or error["outcome"] != "not_started":
        raise AssertionError("terminal error has the wrong code or outcome")
    if not canonical_id(error["operation_id"]):
        raise AssertionError("terminal error operation_id is not canonical")


def self_test():
    request_id = "1" * 32
    operation_id = "2" * 32
    connected = {
        "protocol_version": 4,
        "request_id": request_id,
        "type": "connected",
        "peer": "a" * 64,
        "endpoint_online": True,
        "topic_joined": True,
        "alias": None,
    }
    snapshot = {
        "protocol_version": 4,
        "request_id": request_id,
        "type": "peers_snapshot",
        "generated_at_ms": 1,
        "directory_epoch": "4" * 32,
        "directory_revision": 0,
        "self": {"public_key": "a" * 64, "alias": None, "online": True},
        "peers": [],
    }
    terminal = {
        "protocol_version": 4,
        "request_id": "3" * 32,
        "type": "error",
        "code": "invalid_message",
        "operation_id": operation_id,
        "outcome": "not_started",
    }

    encode = lambda values: "".join(json.dumps(value) + "\n" for value in values)
    validate(encode([terminal]))
    validate(encode([connected, snapshot, terminal]))

    invalid = [
        encode([terminal, connected]),
        encode([terminal, terminal]),
        encode([connected]),
        encode([{**terminal, "protocol_version": 3}]),
        encode([{**terminal, "code": "command_failed"}]),
        encode([{**terminal, "operation_id": "A" * 32}]),
        json.dumps(terminal) + "\n\n" + json.dumps(terminal) + "\n",
        '{"protocol_version":4,"protocol_version":4}\n',
        "not-json\n",
        "",
    ]
    for fixture in invalid:
        try:
            validate(fixture)
        except AssertionError:
            continue
        raise AssertionError(f"validator accepted invalid fixture: {fixture!r}")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        print("PASS: chat NDJSON validator rejects race-sensitive and malformed streams")
        return
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} FILE | --self-test")
    validate(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
