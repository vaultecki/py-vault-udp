import pytest

import vault_udp_socket_helper as helper


@pytest.fixture
def keypair():
    return helper.generate_keys_asym()


@pytest.fixture
def sender_keys():
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


def test_generate_keys_asym_returns_four_distinct_base64_strings():
    enc_pub, enc_priv, sign_pub, sign_priv = helper.generate_keys_asym()
    keys = {enc_pub, enc_priv, sign_pub, sign_priv}
    assert len(keys) == 4
    for key in keys:
        # Should not raise
        helper.b64_str_to_bytes(key)


def test_generate_keys_asym_produces_different_keys_each_call():
    first = helper.generate_keys_asym()
    second = helper.generate_keys_asym()
    assert first != second


def test_generate_public_key_matches_generated_pair(keypair):
    enc_pub, enc_priv, _, _ = keypair
    assert helper.generate_public_key(enc_priv) == enc_pub


def test_generate_public_key_invalid_key_raises_key_generation_error():
    with pytest.raises(helper.KeyGenerationError):
        helper.generate_public_key(helper.bytes_to_b64_str(b"too short"))


def test_sign_and_verify_signature_roundtrip(keypair):
    _, _, sign_pub, sign_priv = keypair
    message = b"authenticate this message"

    signed = helper.sign_message(sign_priv, message)
    verified = helper.verify_signature(sign_pub, signed)

    assert verified == message


def test_verify_signature_with_wrong_key_raises_signature_error(keypair):
    _, _, _, sign_priv = keypair
    _, _, other_sign_pub, _ = helper.generate_keys_asym()
    message = b"authenticate this message"

    signed = helper.sign_message(sign_priv, message)

    with pytest.raises(helper.SignatureError):
        helper.verify_signature(other_sign_pub, signed)


def test_verify_signature_tampered_data_raises_signature_error(keypair):
    _, _, sign_pub, sign_priv = keypair
    signed = bytearray(helper.sign_message(sign_priv, b"original message"))
    signed[-1] ^= 0xFF  # flip a bit in the message portion

    with pytest.raises(helper.SignatureError):
        helper.verify_signature(sign_pub, bytes(signed))


def test_encrypt_decrypt_roundtrip(sender_keys, recipient_keys):
    sender_enc_pub, sender_enc_priv, _, _ = sender_keys
    recipient_enc_pub, recipient_enc_priv, _, _ = recipient_keys
    message = b"top secret payload"

    encrypted = helper.encrypt_asym(sender_enc_priv, recipient_enc_pub, message)
    decrypted = helper.decrypt_asym(recipient_enc_priv, sender_enc_pub, encrypted)

    assert decrypted == message
    assert encrypted != message


def test_encrypt_asym_rejects_non_bytes_message(sender_keys, recipient_keys):
    _, sender_enc_priv, _, _ = sender_keys
    recipient_enc_pub, _, _, _ = recipient_keys

    with pytest.raises(TypeError):
        helper.encrypt_asym(sender_enc_priv, recipient_enc_pub, "not bytes")


def test_decrypt_asym_rejects_non_bytes_message(sender_keys, recipient_keys):
    sender_enc_pub, _, _, _ = sender_keys
    _, recipient_enc_priv, _, _ = recipient_keys

    with pytest.raises(TypeError):
        helper.decrypt_asym(recipient_enc_priv, sender_enc_pub, "not bytes")


def test_decrypt_asym_with_wrong_sender_key_raises_decryption_error(sender_keys, recipient_keys):
    sender_enc_pub, sender_enc_priv, _, _ = sender_keys
    recipient_enc_pub, recipient_enc_priv, _, _ = recipient_keys
    attacker_enc_pub, _, _, _ = helper.generate_keys_asym()

    encrypted = helper.encrypt_asym(sender_enc_priv, recipient_enc_pub, b"secret")

    with pytest.raises(helper.DecryptionError):
        helper.decrypt_asym(recipient_enc_priv, attacker_enc_pub, encrypted)


def test_decrypt_asym_with_tampered_ciphertext_raises_decryption_error(sender_keys, recipient_keys):
    sender_enc_pub, sender_enc_priv, _, _ = sender_keys
    recipient_enc_pub, recipient_enc_priv, _, _ = recipient_keys

    encrypted = bytearray(helper.encrypt_asym(sender_enc_priv, recipient_enc_pub, b"secret"))
    encrypted[-1] ^= 0xFF

    with pytest.raises(helper.DecryptionError):
        helper.decrypt_asym(recipient_enc_priv, sender_enc_pub, bytes(encrypted))


def test_verify_key_pair_valid(keypair):
    enc_pub, enc_priv, _, _ = keypair
    assert helper.verify_key_pair(enc_pub, enc_priv) is True


def test_verify_key_pair_mismatched_returns_false(keypair):
    _, enc_priv, _, _ = keypair
    other_enc_pub, _, _, _ = helper.generate_keys_asym()
    assert helper.verify_key_pair(other_enc_pub, enc_priv) is False


def test_verify_key_pair_invalid_key_returns_false():
    assert helper.verify_key_pair("bad", "bad") is False


def test_encryption_roundtrip_helper_success(sender_keys, recipient_keys):
    sender_enc_pub, sender_enc_priv, _, _ = sender_keys
    recipient_enc_pub, recipient_enc_priv, _, _ = recipient_keys

    assert helper.test_encryption_roundtrip(
        sender_enc_priv, sender_enc_pub,
        recipient_enc_priv, recipient_enc_pub,
        b"message"
    ) is True


def test_encryption_roundtrip_helper_failure_with_mismatched_keys(sender_keys, recipient_keys):
    sender_enc_pub, sender_enc_priv, _, _ = sender_keys
    _, recipient_enc_priv, _, _ = recipient_keys
    attacker_enc_pub, _, _, _ = helper.generate_keys_asym()

    assert helper.test_encryption_roundtrip(
        sender_enc_priv, sender_enc_pub,
        recipient_enc_priv, attacker_enc_pub,
        b"message"
    ) is False
