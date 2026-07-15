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
    """Two encryption managers that know about each other's public keys."""
    peer = ve.VaultAsymmetricEncryption(lifetime=60)
    addr_a = ("10.0.0.1", 5001)
    addr_b = ("10.0.0.2", 5002)

    encryption.update_peer_keys(addr_b, peer.enc_public_key)
    peer.update_peer_keys(addr_a, encryption.enc_public_key)

    yield encryption, peer, addr_a, addr_b
    peer.stop(timeout=0.2)


def test_init_generates_distinct_key_material():
    enc1 = ve.VaultAsymmetricEncryption(lifetime=60)
    enc2 = ve.VaultAsymmetricEncryption(lifetime=60)
    try:
        assert enc1.enc_public_key
        assert enc1.enc_public_key != enc2.enc_public_key
    finally:
        enc1.stop(timeout=0.2)
        enc2.stop(timeout=0.2)


def test_set_private_keys_derives_matching_public_key():
    enc_pub, enc_priv = helper.generate_keys_asym()
    enc = ve.VaultAsymmetricEncryption(lifetime=60, enc_private_key=enc_priv)
    try:
        assert enc.enc_public_key == enc_pub
    finally:
        enc.stop(timeout=0.2)


def test_update_and_check_and_remove_peer_keys(encryption):
    addr = ("192.168.1.1", 6000)
    assert encryption.peer_keys_exist(addr) is False

    encryption.update_peer_keys(addr, "enc-key")
    assert encryption.peer_keys_exist(addr) is True

    encryption.remove_peer_keys(addr)
    assert encryption.peer_keys_exist(addr) is False


def test_update_peer_keys_ignores_empty_key(encryption):
    addr = ("192.168.1.1", 6000)
    encryption.update_peer_keys(addr, "")
    assert encryption.peer_keys_exist(addr) is False


def test_encrypt_decrypt_roundtrip_between_peers(peer_pair):
    encryption, peer, addr_a, addr_b = peer_pair

    ciphertext = encryption.encrypt(b"hello peer", addr_b)
    plaintext = peer.decrypt(ciphertext)

    assert plaintext == b"hello peer"


def test_encrypt_without_peer_key_raises_key_not_found_error(encryption):
    with pytest.raises(ve.KeyNotFoundError):
        encryption.encrypt(b"data", ("unknown", 1))


def test_decrypt_without_own_private_key_raises_decryption_error(encryption):
    encryption._enc_private_key = None
    with pytest.raises(ve.DecryptionError):
        encryption.decrypt(b"data")


def test_decrypt_of_garbage_raises_decryption_error(encryption):
    with pytest.raises(ve.DecryptionError):
        encryption.decrypt(b"not a sealed box message")


def test_decrypt_does_not_need_sender_identity(peer_pair):
    """SealedBox decryption only needs our own private key -- anyone
    holding our public key can produce a message we'll decrypt, and there
    is no addr-based lookup involved in decrypt() at all."""
    encryption, peer, addr_a, addr_b = peer_pair

    # A stranger who only knows peer's public key (never exchanged an addr
    # with peer) can still send peer a message that decrypts cleanly.
    stranger_ciphertext = helper.encrypt_sealed(peer.enc_public_key, b"from nowhere")
    assert peer.decrypt(stranger_ciphertext) == b"from nowhere"


def test_encrypt_if_possible_falls_back_to_plaintext_without_key(encryption):
    result = encryption.encrypt_if_possible(b"data", ("unknown", 1))
    assert result == b"data"


def test_decrypt_if_possible_returns_original_on_failure(encryption):
    result = encryption.decrypt_if_possible(b"not encrypted")
    assert result == b"not encrypted"


def test_decrypt_if_possible_returns_plaintext_on_success(peer_pair):
    encryption, peer, addr_a, addr_b = peer_pair
    ciphertext = encryption.encrypt(b"payload", addr_b)
    assert peer.decrypt_if_possible(ciphertext) == b"payload"


def test_cleanup_expired_keys_removes_old_entries(encryption):
    addr = ("192.168.1.1", 6000)
    encryption.update_peer_keys(addr, "enc-key")

    # Force the stored timestamp far into the past.
    encryption._peer_keys_timestamp[addr] = encryption._current_timestamp() - 1000
    encryption._key_max_lifetime = 60

    removed = encryption.cleanup_expired_keys()

    assert removed == 1
    assert encryption.peer_keys_exist(addr) is False


def test_cleanup_expired_keys_keeps_fresh_entries(encryption):
    addr = ("192.168.1.1", 6000)
    encryption.update_peer_keys(addr, "enc-key")

    removed = encryption.cleanup_expired_keys()

    assert removed == 0
    assert encryption.peer_keys_exist(addr) is True


def test_get_stats_reports_expected_fields(encryption):
    addr = ("192.168.1.1", 6000)
    encryption.update_peer_keys(addr, "enc-key")

    stats = encryption.get_stats()

    assert stats["active_peer_keys"] == 1
    assert stats["key_lifetime_seconds"] == 60
    assert stats["has_enc_private_key"] is True
