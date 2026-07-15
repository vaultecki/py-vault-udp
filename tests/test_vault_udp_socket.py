import os
import socket
import time

import pytest

import vault_ip
import vault_udp_socket as vus


def _free_udp_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


@pytest.fixture(autouse=True)
def fixed_mtu(monkeypatch):
    """Keep MTU deterministic and independent of the host's real network interfaces."""
    monkeypatch.setattr(vault_ip, "get_min_mtu", lambda: 1500)


@pytest.fixture
def make_socket():
    created = []

    def _make(**kwargs):
        kwargs.setdefault("recv_port", _free_udp_port())
        sock = vus.UDPSocketClass(**kwargs)
        created.append(sock)
        return sock

    yield _make

    for sock in created:
        sock.stop(timeout=1.0)


def _wait_until(predicate, timeout=5.0, interval=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


# --- RateLimiter ---

def test_rate_limiter_allows_requests_under_limit():
    limiter = vus.RateLimiter(max_per_second=3)
    addr = ("1.2.3.4", 1000)

    assert limiter.allow_request(addr) is True
    assert limiter.allow_request(addr) is True
    assert limiter.allow_request(addr) is True


def test_rate_limiter_blocks_requests_over_limit():
    limiter = vus.RateLimiter(max_per_second=2)
    addr = ("1.2.3.4", 1000)

    assert limiter.allow_request(addr) is True
    assert limiter.allow_request(addr) is True
    assert limiter.allow_request(addr) is False


def test_rate_limiter_tracks_peers_independently():
    limiter = vus.RateLimiter(max_per_second=1)
    addr_a = ("1.2.3.4", 1000)
    addr_b = ("5.6.7.8", 2000)

    assert limiter.allow_request(addr_a) is True
    assert limiter.allow_request(addr_b) is True
    assert limiter.allow_request(addr_a) is False
    assert limiter.allow_request(addr_b) is False


def test_rate_limiter_cleanup_removes_inactive_peers():
    limiter = vus.RateLimiter(max_per_second=5)
    addr = ("1.2.3.4", 1000)
    limiter.allow_request(addr)
    limiter._requests[addr] = [time.time() - 120]  # simulate old activity

    limiter.cleanup_old_entries()

    assert addr not in limiter._requests


# --- _validate_port ---

def test_validate_port_accepts_value_within_range():
    assert vus.UDPSocketClass._validate_port(12345) == 12345


def test_validate_port_clamps_below_minimum():
    assert vus.UDPSocketClass._validate_port(1) == vus.MIN_PORT


def test_validate_port_clamps_above_maximum():
    assert vus.UDPSocketClass._validate_port(999999) == vus.MAX_PORT


def test_validate_port_accepts_numeric_string():
    assert vus.UDPSocketClass._validate_port("12345") == 12345


def test_validate_port_rejects_non_numeric_value():
    with pytest.raises(vus.InvalidPortError):
        vus.UDPSocketClass._validate_port("not-a-port")


# --- _generate_padding ---

def test_generate_padding_returns_requested_length():
    padding = vus.UDPSocketClass._generate_padding(32)
    assert isinstance(padding, bytes)
    assert len(padding) == 32


def test_generate_padding_returns_empty_for_non_positive_length():
    assert vus.UDPSocketClass._generate_padding(0) == b""
    assert vus.UDPSocketClass._generate_padding(-5) == b""


# --- UDPSocketClass integration behavior ---

def test_add_peer_and_remove_peer(make_socket):
    sock = make_socket()
    peer_addr = ("127.0.0.1", _free_udp_port())

    sock.add_peer(peer_addr)
    assert sock.has_peer(peer_addr) is True
    assert peer_addr in sock.get_peers()

    sock.remove_peer(peer_addr)
    assert sock.has_peer(peer_addr) is False


def test_add_peer_ignores_malformed_address(make_socket):
    sock = make_socket()
    sock.add_peer(("only-ip",))
    assert sock.get_peers() == []


def test_add_peer_with_preseeded_key_stores_it_immediately(make_socket):
    sock = make_socket()
    peer_addr = ("127.0.0.1", _free_udp_port())
    fake_key = "some-base64-key"

    sock.add_peer((peer_addr[0], peer_addr[1], fake_key))

    assert sock.has_peer(peer_addr) is True
    assert sock.get_peer_key(peer_addr) == fake_key


def test_add_peer_with_preseeded_key_sends_first_announcement_encrypted(make_socket, caplog):
    """A key learned out-of-band should let even the very first
    announcement go out encrypted, skipping the plaintext bootstrap."""
    sock_a = make_socket()
    sock_b = make_socket()
    addr_b = ("127.0.0.1", sock_b.recv_port)

    with caplog.at_level("DEBUG", logger="vault_udp_encryption"):
        sock_a.add_peer((addr_b[0], addr_b[1], sock_b.own_public_key))

    assert not any(
        "sending unencrypted" in record.message for record in caplog.records
    ), "first announcement should have been encrypted since the peer's key was pre-seeded"


def test_own_public_key_matches_full_key(make_socket):
    sock = make_socket()
    assert sock.own_public_key == sock._encryption.enc_public_key
    assert sock.own_public_key  # non-empty
    # get_stats() only exposes a truncated version for display purposes.
    assert len(sock.own_public_key) > len(sock.get_stats()["enc_public_key"])


def test_get_peer_key_returns_none_when_unknown(make_socket):
    sock = make_socket()
    assert sock.get_peer_key(("127.0.0.1", _free_udp_port())) is None


def test_get_all_peer_keys_reflects_known_peers(make_socket):
    sock = make_socket()
    addr_1 = ("127.0.0.1", _free_udp_port())
    addr_2 = ("127.0.0.1", _free_udp_port())

    sock.add_peer((addr_1[0], addr_1[1], "key-one"))
    sock.add_peer((addr_2[0], addr_2[1], "key-two"))

    all_keys = sock.get_all_peer_keys()

    assert all_keys == {addr_1: "key-one", addr_2: "key-two"}
    # Must be a snapshot, not a live view.
    all_keys[addr_1] = "tampered"
    assert sock.get_peer_key(addr_1) == "key-one"


def test_get_peers_by_ip_filters_correctly(make_socket):
    sock = make_socket()
    sock.add_peer(("127.0.0.1", _free_udp_port()))
    sock.add_peer(("127.0.0.1", _free_udp_port()))
    sock.add_peer(("10.0.0.5", _free_udp_port()))

    matches = sock.get_peers_by_ip("127.0.0.1")

    assert len(matches) == 2
    assert all(addr[0] == "127.0.0.1" for addr in matches)


def test_get_stats_reports_expected_fields(make_socket):
    sock = make_socket()
    sock.add_peer(("127.0.0.1", _free_udp_port()))

    stats = sock.get_stats()

    assert stats["protocol_version"] == vus.PROTOCOL_VERSION
    assert stats["peer_count"] == 1
    assert stats["unique_ips"] == 1
    assert "encryption_stats" in stats
    assert stats["enc_public_key"] is not None


def test_send_data_raises_when_message_too_large(make_socket):
    sock = make_socket()
    # Random bytes are incompressible, so this reliably exceeds the MTU
    # even after zstd compression.
    huge_message = os.urandom(1_000_000)

    with pytest.raises(vus.MessageTooLargeError):
        sock.send_data(huge_message)


def test_send_data_rejects_non_str_non_bytes_payload(make_socket):
    sock = make_socket()
    with pytest.raises(TypeError):
        sock.send_data(12345)


def test_two_sockets_exchange_keys_and_deliver_message(make_socket):
    sock_a = make_socket()
    sock_b = make_socket()

    assert _wait_until(
        lambda: sock_a._read_socket is not None and sock_b._read_socket is not None
    ), "read sockets did not finish binding in time"

    received = []
    sock_b.udp_recv_data.connect(lambda data, addr: received.append(data))

    addr_a = ("127.0.0.1", sock_a.recv_port)
    addr_b = ("127.0.0.1", sock_b.recv_port)

    sock_a.add_peer(addr_b)

    assert _wait_until(
        lambda: sock_a._encryption.peer_keys_exist(addr_b)
        and sock_b._encryption.peer_keys_exist(addr_a)
    ), "mutual key exchange did not complete in time"

    sock_a.send_data("hello world")

    assert _wait_until(lambda: len(received) > 0), "message was not received in time"
    assert received == ["hello world"]


def test_update_recv_port_reannounces_to_known_peers(make_socket):
    sock_a = make_socket()
    sock_b = make_socket()

    assert _wait_until(
        lambda: sock_a._read_socket is not None and sock_b._read_socket is not None
    ), "read sockets did not finish binding in time"

    received = []
    sock_a.udp_recv_data.connect(lambda data, addr: received.append(data))

    addr_b = ("127.0.0.1", sock_b.recv_port)
    sock_a.add_peer(addr_b)

    assert _wait_until(
        lambda: sock_a._encryption.peer_keys_exist(addr_b)
        and sock_b._encryption.peer_keys_exist(("127.0.0.1", sock_a.recv_port))
    ), "initial key exchange did not complete in time"

    new_addr_a = ("127.0.0.1", _free_udp_port())
    sock_a.update_recv_port(new_addr_a[1])

    assert _wait_until(
        lambda: sock_b._encryption.peer_keys_exist(new_addr_a)
    ), "peer was not re-announced to after the port change"

    sock_b.send_data("hello after port change", new_addr_a)

    assert _wait_until(lambda: len(received) > 0), "message was not received on the new port"
    assert received == ["hello after port change"]


def test_lifetime_constructor_param_is_used(make_socket):
    sock = make_socket(lifetime=15)
    assert sock.lifetime == 15
    assert sock.get_stats()["encryption_stats"]["key_lifetime_seconds"] == 15


def test_update_lifetime_propagates_to_encryption_manager(make_socket):
    sock = make_socket(lifetime=60)
    sock.update_lifetime(15)
    assert sock.lifetime == 15
    assert sock.get_stats()["encryption_stats"]["key_lifetime_seconds"] == 15


def test_key_change_for_known_peer_logs_warning(make_socket, caplog):
    sock = make_socket()
    addr = ("127.0.0.1", _free_udp_port())
    sock._encryption.update_peer_keys(addr, "old-key")

    with caplog.at_level("WARNING", logger="vault_udp_socket"):
        sock._handle_key_exchange({"enc_key": "new-key"}, addr)

    assert sock.get_peer_key(addr) == "new-key"
    assert any("changed since last seen" in record.message for record in caplog.records)


def test_same_key_reannounced_does_not_log_warning(make_socket, caplog):
    sock = make_socket()
    addr = ("127.0.0.1", _free_udp_port())
    sock._encryption.update_peer_keys(addr, "same-key")

    with caplog.at_level("WARNING", logger="vault_udp_socket"):
        sock._handle_key_exchange({"enc_key": "same-key"}, addr)

    assert not any("changed since last seen" in record.message for record in caplog.records)


def test_stop_returns_promptly_even_with_a_long_lifetime(make_socket):
    """stop() must not have to wait out the key management thread's sleep
    interval, which can be tens of seconds for a long key lifetime."""
    sock = make_socket(lifetime=600)

    start = time.time()
    sock.stop(timeout=5.0)
    elapsed = time.time() - start

    assert elapsed < 2.0
    assert sock._key_mgmt_thread.is_alive() is False
