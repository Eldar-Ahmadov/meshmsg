#!/usr/bin/env python3
"""Real peer-directory snapshot/lifecycle checks. Requires working Iroh networking."""
import json
import pathlib
import subprocess
import sys
import tempfile
import time

BIN = str(pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "target/debug/meshmsg").resolve())
LEASE_MS = 150_000
REMOTE_KEYS = {"public_key", "alias", "online", "last_seen_ms", "expires_at_ms"}
SELF_KEYS = {"public_key", "alias", "online"}
EVENT_KEYS = {"type", "schema_version", "peer"}
FORBIDDEN_KEYS = {
    "endpoint", "endpoints", "address", "addresses", "addrs", "relay", "socket",
    "local_endpoint", "invite", "token", "ticket", "offer", "path", "record",
    "signature", "capabilities", "ipc_capabilities", "body",
}


def main():
    with tempfile.TemporaryDirectory(prefix="meshmsg-peer-directory-") as root_name:
        root = pathlib.Path(root_name)
        processes = {}
        logs = []

        def command(node, *args, timeout=20, check=True):
            result = subprocess.run(
                [BIN, "--state-dir", str(root / node), "--json", *args],
                text=True, capture_output=True, timeout=timeout, check=False,
            )
            if check and result.returncode:
                raise AssertionError(
                    f"{node} {' '.join(args)} failed ({result.returncode}): {result.stderr}"
                )
            return result

        def cli(node, *args, timeout=20):
            result = command(node, *args, timeout=timeout)
            return json.loads(result.stdout)

        def start_daemon(node):
            path = root / f"{node}.daemon.log"
            log = path.open("w+")
            logs.append(log)
            process = subprocess.Popen(
                [BIN, "--state-dir", str(root / node), "--json", "daemon"],
                stdout=log, stderr=log,
            )
            processes[node] = process
            wait_for(
                lambda: process.poll() is None and cli(node, "status")["running"] is True,
                f"{node} daemon startup", 90,
            )

        def stop_daemon(node):
            process = processes.pop(node)
            cli(node, "stop")
            assert process.wait(timeout=15) == 0, f"{node} daemon did not stop cleanly"

        listener_log = None
        listener = None

        def events():
            if listener_log is None:
                return []
            values = []
            for line in listener_log.read_text().splitlines():
                try:
                    values.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
            return values

        def peer_events(kind=None, public_key=None):
            result = [value for value in events() if value.get("type", "").startswith("peer_")]
            if kind is not None:
                result = [value for value in result if value.get("type") == kind]
            if public_key is not None:
                result = [
                    value for value in result
                    if isinstance(value.get("peer"), dict)
                    and value["peer"].get("public_key") == public_key
                ]
            return result

        def wait_for(predicate, description, seconds=60):
            deadline = time.monotonic() + seconds
            last_error = None
            while time.monotonic() < deadline:
                try:
                    if predicate():
                        return
                except (AssertionError, json.JSONDecodeError, OSError, subprocess.SubprocessError) as error:
                    last_error = error
                time.sleep(.2)
            detail = f": {last_error}" if last_error else ""
            raise AssertionError(f"timeout waiting for {description}{detail}")

        def assert_no_private_fields(value):
            if isinstance(value, dict):
                overlap = FORBIDDEN_KEYS.intersection(value)
                assert not overlap, f"peer API leaked private fields: {sorted(overlap)}"
                for child in value.values():
                    assert_no_private_fields(child)
            elif isinstance(value, list):
                for child in value:
                    assert_no_private_fields(child)

        def validate_remote(entry, generated_at_ms, expected_alias):
            assert set(entry) == REMOTE_KEYS, entry
            assert entry["public_key"]
            assert entry["alias"] == expected_alias
            assert isinstance(entry["online"], bool)
            assert isinstance(entry["last_seen_ms"], int)
            assert isinstance(entry["expires_at_ms"], int)
            assert 0 <= entry["expires_at_ms"] - entry["last_seen_ms"] <= LEASE_MS
            if entry["online"]:
                assert entry["last_seen_ms"] <= generated_at_ms <= entry["expires_at_ms"]
            assert_no_private_fields(entry)

        def validate_snapshot(value, self_peer, self_alias, remotes):
            assert set(value) == {"type", "schema_version", "generated_at_ms", "self", "peers"}, value
            assert value["type"] == "peers_snapshot"
            assert value["schema_version"] == 1
            assert isinstance(value["generated_at_ms"], int)
            self_entry = value["self"]
            assert set(self_entry) == SELF_KEYS
            assert self_entry["public_key"] == self_peer
            assert self_entry["alias"] == self_alias
            assert isinstance(self_entry["online"], bool)
            entries = value["peers"]
            keys = [entry["public_key"] for entry in entries]
            assert keys == sorted(keys)
            assert len(set(keys)) == len(entries)
            assert self_peer not in keys
            assert set(keys) == set(remotes)
            for entry in entries:
                validate_remote(entry, value["generated_at_ms"], remotes[entry["public_key"]])
                assert entry["online"] is True
            assert_no_private_fields(value)
            return {entry["public_key"]: entry for entry in entries}

        def validate_event(value, kind, alias):
            assert set(value) == EVENT_KEYS, value
            assert value["type"] == kind and value["schema_version"] == 1
            peer = value["peer"]
            validate_remote(peer, int(time.time() * 1000), alias)
            if kind == "peer_expired":
                assert peer["online"] is False
            else:
                assert peer["online"] is True
            assert_no_private_fields(value)

        try:
            cli("one", "init", "--no-default-alias")
            cli("one", "alias", "set", "alpha")
            start_daemon("one")
            one_status = cli("one", "status")
            one_peer = one_status["peer"]
            assert "peer_directory_v1" in one_status["ipc_capabilities"]

            listener_path = root / "one.listen.log"
            listener_log = listener_path
            listener_handle = listener_path.open("w+")
            logs.append(listener_handle)
            listener = subprocess.Popen(
                [BIN, "--state-dir", str(root / "one"), "--json", "listen"],
                stdout=listener_handle, stderr=listener_handle,
            )
            wait_for(lambda: len(events()) >= 2, "listener handshake")
            assert [value.get("type") for value in events()[:2]] == ["connected", "peers_snapshot"]

            invite = cli("one", "invite")["token"]
            cli("two", "join", "--no-default-alias", invite)
            cli("two", "alias", "set", "beta")
            two_peer = cli("two", "doctor")["peer"]
            cli("three", "join", "--no-default-alias", invite)
            three_peer = cli("three", "doctor")["peer"]
            start_daemon("two")
            start_daemon("three")

            wait_for(
                lambda: len(peer_events("peer_discovered", two_peer)) == 1
                and len(peer_events("peer_discovered", three_peer)) == 1,
                "both discovery events", 60,
            )
            snapshot = cli("one", "peers")
            initial = validate_snapshot(
                snapshot, one_peer, "alpha", {two_peer: "beta", three_peer: None},
            )
            current_status = cli("one", "status")
            assert snapshot["self"]["online"] is (
                current_status["endpoint_online"] and current_status["topic_joined"]
            )
            validate_event(peer_events("peer_discovered", two_peer)[0], "peer_discovered", "beta")
            validate_event(peer_events("peer_discovered", three_peer)[0], "peer_discovered", None)
            assert not peer_events(public_key=one_peer), "gossip loopback emitted a self lifecycle event"

            # At least one scheduled presence refresh must advance freshness without
            # generating another discovery/update event for an unchanged peer.
            first_seen = initial[two_peer]["last_seen_ms"]
            refreshed = {}

            def freshness_advanced():
                nonlocal refreshed
                value = cli("one", "peers")
                refreshed = validate_snapshot(
                    value, one_peer, "alpha", {two_peer: "beta", three_peer: None},
                )
                return refreshed[two_peer]["last_seen_ms"] > first_seen

            wait_for(freshness_advanced, "silent presence refresh", 50)
            assert len(peer_events("peer_discovered", two_peer)) == 1
            assert not peer_events("peer_updated", two_peer)
            assert not peer_events("peer_expired", two_peer)

            # Restarting the same identity with a new signed alias before expiry is
            # an update, not another discovery. No endpoint details may accompany it.
            stop_daemon("two")
            cli("two", "alias", "set", "beta-renamed")
            start_daemon("two")
            wait_for(
                lambda: any(v["peer"].get("alias") == "beta-renamed" for v in peer_events("peer_updated", two_peer)),
                "alias update event", 60,
            )
            updated_events = [
                value for value in peer_events("peer_updated", two_peer)
                if value["peer"]["alias"] == "beta-renamed"
            ]
            assert len(updated_events) == 1
            validate_event(updated_events[0], "peer_updated", "beta-renamed")
            assert len(peer_events("peer_discovered", two_peer)) == 1
            validate_snapshot(
                cli("one", "peers"), one_peer, "alpha",
                {two_peer: "beta-renamed", three_peer: None},
            )

            # The daemon owns lease expiry. It emits one authoritative transition,
            # removes the peer from snapshots, and treats a later lease as discovery.
            stop_daemon("two")
            wait_for(lambda: len(peer_events("peer_expired", two_peer)) == 1, "peer expiry", 180)
            expired_events = peer_events("peer_expired", two_peer)
            assert len(expired_events) == 1
            validate_event(expired_events[0], "peer_expired", "beta-renamed")
            validate_snapshot(cli("one", "peers"), one_peer, "alpha", {three_peer: None})
            time.sleep(16)  # one additional cleanup interval must not repeat expiry
            assert len(peer_events("peer_expired", two_peer)) == 1

            start_daemon("two")
            wait_for(
                lambda: len(peer_events("peer_discovered", two_peer)) == 2,
                "rediscovery after expiry", 60,
            )
            validate_event(peer_events("peer_discovered", two_peer)[-1], "peer_discovered", "beta-renamed")
            validate_snapshot(
                cli("one", "peers"), one_peer, "alpha",
                {two_peer: "beta-renamed", three_peer: None},
            )

            print(
                "PASS: deterministic versioned peer snapshot, explicit self/online semantics, "
                "bounded local freshness, silent refresh, update/single-expiry/rediscovery lifecycle, "
                "and sanitized endpoint-free fields"
            )
        finally:
            if listener is not None and listener.poll() is None:
                listener.terminate()
                try:
                    listener.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    listener.kill()
                    listener.wait()
            for node, process in list(processes.items()):
                try:
                    command(node, "stop", timeout=5, check=False)
                except subprocess.SubprocessError:
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            for log in logs:
                log.close()


if __name__ == "__main__":
    main()
