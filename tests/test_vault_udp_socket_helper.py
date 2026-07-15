import pytest

import vault_udp_socket_helper as helper


@pytest.fixture
def keypair():
    return helper.generate_keys_asym()


@pytest.fixture
def recipient_keys():
    return helper.generate_keys_asym()


def test_bytes_to_b64_str_roundtrip():
    data = b"hello world \x00\xff"
    encoded = helper.bytes_to_b64_str(data)
    assert isinstance(encoded, str)
    assert helper.b64_str_to_bytes(encoded) == data


def test_b64_str_to_bytes_accepts_bytes_input():
    data = b"some bytes"
    encoded_str = helper.bytes_to_b64_str(data)
    encoded_bytes = encoded_str.encode("utf-8")
    assert helper.b64_str_to_bytes(encoded_bytes) == data


def test_b64_str_to_bytes_invalid_input_raises_encoding_error():
    with pytest.raises(helper.EncodingError):
        helper.b64_str_to_bytes("not valid base64!!!")


def test_generate_keys_asym_returns_two_distinct_base64_strings():
    public_key, private_key = helper.generate_keys_asym()
    assert public_key != private_key
    for key in (public_key, private_key):
        # Should not raise
        helper.b64_str_to_bytes(key)


def test_generate_keys_asym_produces_different_keys_each_call():
    first = helper.generate_keys_asym()
    second = helper.generate_keys_asym()
    assert first != second


def test_generate_public_key_matches_generated_pair(keypair):
    public_key, private_key = keypair
    assert helper.generate_public_key(private_key) == public_key


def test_generate_public_key_invalid_key_raises_key_generation_error():
    with pytest.raises(helper.KeyGenerationError):
        helper.generate_public_key(helper.bytes_to_b64_str(b"too short"))


def test_encrypt_decrypt_roundtrip(recipient_keys):
    recipient_public, recipient_private = recipient_keys
    message = b"top secret payload"

    encrypted = helper.encrypt_sealed(recipient_public, message)
    decrypted = helper.decrypt_sealed(recipient_private, encrypted)

    assert decrypted == message
    assert encrypted != message


def test_encrypt_sealed_needs_no_sender_key_material(recipient_keys):
    """SealedBox encryption only needs the recipient's public key."""
    recipient_public, _ = recipient_keys
    encrypted_once = helper.encrypt_sealed(recipient_public, b"same message")
    encrypted_twice = helper.encrypt_sealed(recipient_public, b"same message")
    # Each call uses a fresh ephemeral key internally, so ciphertexts differ
    # even for identical plaintext -- but both must still decrypt correctly.
    assert encrypted_once != encrypted_twice


def test_encrypt_sealed_rejects_non_bytes_message(recipient_keys):
    recipient_public, _ = recipient_keys
    with pytest.raises(TypeError):
        helper.encrypt_sealed(recipient_public, "not bytes")


def test_decrypt_sealed_rejects_non_bytes_message(recipient_keys):
    _, recipient_private = recipient_keys
    with pytest.raises(TypeError):
        helper.decrypt_sealed(recipient_private, "not bytes")


def test_decrypt_sealed_with_wrong_recipient_key_raises_decryption_error(recipient_keys):
    recipient_public, _ = recipient_keys
    _, other_private = helper.generate_keys_asym()

    encrypted = helper.encrypt_sealed(recipient_public, b"secret")

    with pytest.raises(helper.DecryptionError):
        helper.decrypt_sealed(other_private, encrypted)


def test_decrypt_sealed_with_tampered_ciphertext_raises_decryption_error(recipient_keys):
    recipient_public, recipient_private = recipient_keys

    encrypted = bytearray(helper.encrypt_sealed(recipient_public, b"secret"))
    encrypted[-1] ^= 0xFF

    with pytest.raises(helper.DecryptionError):
        helper.decrypt_sealed(recipient_private, bytes(encrypted))


def test_verify_key_pair_valid(keypair):
    public_key, private_key = keypair
    assert helper.verify_key_pair(public_key, private_key) is True


def test_verify_key_pair_mismatched_returns_false(keypair):
    _, private_key = keypair
    other_public, _ = helper.generate_keys_asym()
    assert helper.verify_key_pair(other_public, private_key) is False


def test_verify_key_pair_invalid_key_returns_false():
    assert helper.verify_key_pair("bad", "bad") is False


def test_encryption_roundtrip_helper_success(recipient_keys):
    recipient_public, recipient_private = recipient_keys
    assert helper.test_encryption_roundtrip(recipient_private, recipient_public, b"message") is True


def test_encryption_roundtrip_helper_failure_with_mismatched_keys(recipient_keys):
    recipient_public, _ = recipient_keys
    _, other_private = helper.generate_keys_asym()

    assert helper.test_encryption_roundtrip(other_private, recipient_public, b"message") is False
