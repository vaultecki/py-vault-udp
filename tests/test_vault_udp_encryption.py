import struct
import time

import pytest

import vault_udp_encryption as ve
import vault_udp_socket_helper as helper


@pytest.fixture
def encryption():
    enc = ve.VaultAsymmetricEncryption(lifetime=60)
    yield enc
    enc.stop(timeout=0.2)


@pytest.fixture
def peer_pair(encryption):
    """Two encryption managers that know about each other's keys."""
    peer = ve.VaultAsymmetricEncryption(lifetime=60)
    addr_a = ("10.0.0.1", 5001)
    addr_b = ("10.0.0.2", 5002)

    encryption.update_peer_keys(addr_b, peer.enc_public_key, peer.sign_public_key)
    peer.update_peer_keys(addr_a, encryption.enc_public_key, encryption.sign_public_key)

    yield encryption, peer, addr_a, addr_b
    peer.stop(timeout=0.2)


def test_init_generates_distinct_key_material():
    enc1 = ve.VaultAsymmetricEncryption(lifetime=60)
    enc2 = ve.VaultAsymmetricEncryption(lifetime=60)
    try:
        assert enc1.enc_public_key and enc1.sign_public_key
        assert enc1.enc_public_key != enc2.enc_public_key
        assert enc1.sign_public_key != enc2.sign_public_key
    finally:
        enc1.stop(timeout=0.2)
        enc2.stop(timeout=0.2)


def test_set_private_keys_derives_matching_public_keys():
    enc_pub, enc_priv, sign_pub, sign_priv = helper.generate_keys_asym()
    enc = ve.VaultAsymmetricEncryption(
        lifetime=60, enc_private_key=enc_priv, sign_private_key=sign_priv
    )
    try:
        assert enc.enc_public_key == enc_pub
        assert enc.sign_public_key == sign_pub
    finally:
        enc.stop(timeout=0.2)


def test_update_and_check_and_remove_peer_keys(encryption):
    addr = ("192.168.1.1", 6000)
    assert encryption.peer_keys_exist(addr) is False

    encryption.update_peer_keys(addr, "enc-key", "sign-key")
    assert encryption.peer_keys_exist(addr) is True

    encryption.remove_peer_keys(addr)
    assert encryption.peer_keys_exist(addr) is False


def test_update_peer_keys_ignores_empty_keys(encryption):
    addr = ("192.168.1.1", 6000)
    encryption.update_peer_keys(addr, "", "sign-key")
    assert encryption.peer_keys_exist(addr) is False


def test_encrypt_decrypt_roundtrip_between_peers(peer_pair):
    encryption, peer, addr_a, addr_b = peer_pair

    ciphertext = encryption.encrypt(b"hello peer", addr_b)
    plaintext = peer.decrypt(ciphertext, addr_a)

    assert plaintext == b"hello peer"


def test_encrypt_without_peer_key_raises_key_not_found_error(encryption):
    with pytest.raises(ve.KeyNotFoundError):
        encryption.encrypt(b"data", ("unknown", 1))


def test_decrypt_without_peer_key_raises_decryption_error(encryption):
    with pytest.raises(ve.DecryptionError):
        encryption.decrypt(b"data", ("unknown", 1))


def test_encrypt_without_own_private_key_raises_encryption_error(encryption):
    encryption._enc_private_key = None
    with pytest.raises(ve.EncryptionError):
        encryption.encrypt(b"data", ("10.0.0.2", 5002))


def test_decrypt_without_own_private_key_raises_decryption_error(encryption):
    encryption._enc_private_key = None
    with pytest.raises(ve.DecryptionError):
        encryption.decrypt(b"data", ("10.0.0.2", 5002))


def test_decrypt_detects_replayed_nonce(peer_pair):
    encryption, peer, addr_a, addr_b = peer_pair

    ciphertext = encryption.encrypt(b"once only", addr_b)

    assert peer.decrypt(ciphertext, addr_a) == b"once only"
    with pytest.raises(ve.ReplayAttackError):
        peer.decrypt(ciphertext, addr_a)


def test_decrypt_rejects_stale_message(peer_pair):
    encryption, peer, addr_a, addr_b = peer_pair

    # Build a message with a timestamp far in the past, bypassing encrypt()'s
    # use of the current time.
    nonce = b"\x00" * 16
    old_timestamp = struct.pack("!d", time.time() - ve.MAX_MESSAGE_AGE_SECONDS - 10)
    message = nonce + old_timestamp + b"stale payload"
    stale_ciphertext = helper.encrypt_asym(
        encryption._enc_private_key, peer.enc_public_key, message
    )

    with pytest.raises(ve.ReplayAttackError):
        peer.decrypt(stale_ciphertext, addr_a)


def test_decrypt_rejects_short_message(peer_pair):
    encryption, peer, addr_a, addr_b = peer_pair

    ciphertext = helper.encrypt_asym(
        encryption._enc_private_key, peer.enc_public_key, b"short"
    )

    with pytest.raises(ve.DecryptionError):
        peer.decrypt(ciphertext, addr_a)


def test_encrypt_if_possible_falls_back_to_plaintext_without_key(encryption):
    result = encryption.encrypt_if_possible(b"data", ("unknown", 1))
    assert result == b"data"


def test_decrypt_if_possible_returns_original_on_failure(encryption):
    result = encryption.decrypt_if_possible(b"not encrypted", ("unknown", 1))
    assert result == b"not encrypted"


def test_decrypt_if_possible_returns_plaintext_on_success(peer_pair):
    encryption, peer, addr_a, addr_b = peer_pair
    ciphertext = encryption.encrypt(b"payload", addr_b)
    assert peer.decrypt_if_possible(ciphertext, addr_a) == b"payload"


def test_cleanup_expired_keys_removes_old_entries(encryption):
    addr = ("192.168.1.1", 6000)
    encryption.update_peer_keys(addr, "enc-key", "sign-key")

    # Force the stored timestamp far into the past.
    encryption._peer_keys_timestamp[addr] = encryption._current_timestamp() - 1000
    encryption._key_max_lifetime = 60

    removed = encryption.cleanup_expired_keys()

    assert removed == 1
    assert encryption.peer_keys_exist(addr) is False


def test_cleanup_expired_keys_keeps_fresh_entries(encryption):
    addr = ("192.168.1.1", 6000)
    encryption.update_peer_keys(addr, "enc-key", "sign-key")

    removed = encryption.cleanup_expired_keys()

    assert removed == 0
    assert encryption.peer_keys_exist(addr) is True


def test_get_stats_reports_expected_fields(encryption):
    addr = ("192.168.1.1", 6000)
    encryption.update_peer_keys(addr, "enc-key", "sign-key")

    stats = encryption.get_stats()

    assert stats["active_peer_keys"] == 1
    assert stats["key_lifetime_seconds"] == 60
    assert stats["has_enc_private_key"] is True
    assert stats["has_sign_private_key"] is True
    assert stats["total_tracked_nonces"] == 0
    assert stats["peers_with_nonces"] == 0
