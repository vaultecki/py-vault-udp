# Copyright [2025] [ecki]
# SPDX-License-Identifier: Apache-2.0

"""
Vault UDP Socket Helper Module

Provides cryptographic primitives for authenticated asymmetric encryption using NaCl/libsodium.
This module handles key generation, encoding, and encryption/decryption operations with authentication.
"""

import base64
import logging
from typing import Tuple

import nacl.encoding
import nacl.exceptions
import nacl.public
import nacl.signing
import nacl.utils

logger = logging.getLogger(__name__)


class CryptoError(Exception):
    """Base exception for cryptographic operations."""
    pass


class KeyGenerationError(CryptoError):
    """Raised when key generation fails."""
    pass


class EncryptionError(CryptoError):
    """Raised when encryption fails."""
    pass


class DecryptionError(CryptoError):
    """Raised when decryption fails."""
    pass


class EncodingError(CryptoError):
    """Raised when encoding/decoding fails."""
    pass


class SignatureError(CryptoError):
    """Raised when signature verification fails."""
    pass


def bytes_to_b64_str(data: bytes) -> str:
    """
    Convert bytes to Base64-encoded string.

    Args:
        data: Raw bytes to encode

    Returns:
        Base64-encoded string

    Raises:
        EncodingError: If encoding fails
    """
    try:
        return base64.b64encode(data).decode('utf-8')
    except Exception as e:
        logger.error("Failed to encode bytes to base64: %s", e)
        raise EncodingError(f"Base64 encoding failed: {e}") from e


def b64_str_to_bytes(data: str) -> bytes:
    """
    Convert Base64-encoded string to bytes.

    Args:
        data: Base64-encoded string (str or bytes)

    Returns:
        Decoded bytes

    Raises:
        EncodingError: If decoding fails
    """
    try:
        if isinstance(data, bytes):
            data = data.decode('utf-8')
        return base64.b64decode(data.encode('utf-8'))
    except Exception as e:
        logger.error("Failed to decode base64 to bytes: %s", e)
        raise EncodingError(f"Base64 decoding failed: {e}") from e


def generate_keys_asym() -> Tuple[str, str, str, str]:
    """
    Generate a new asymmetric key pair with signing keys.

    Returns:
        Tuple of (encryption_public, encryption_private, signing_public, signing_private) 
        as Base64-encoded strings

    Raises:
        KeyGenerationError: If key generation fails

    Note:
        - Encryption uses X25519 (Curve25519) for key exchange
        - Signing uses Ed25519 for authentication
    """
    try:
        # Encryption keys
        enc_private_key_obj = nacl.public.PrivateKey.generate()
        enc_public_str = bytes_to_b64_str(bytes(enc_private_key_obj.public_key))
        enc_private_str = bytes_to_b64_str(bytes(enc_private_key_obj))

        # Signing keys
        sign_private_key_obj = nacl.signing.SigningKey.generate()
        sign_public_str = bytes_to_b64_str(bytes(sign_private_key_obj.verify_key))
        sign_private_str = bytes_to_b64_str(bytes(sign_private_key_obj))

        logger.debug("Generated new asymmetric key pair with signing keys")
        return enc_public_str, enc_private_str, sign_public_str, sign_private_str

    except Exception as e:
        logger.error("Key generation failed: %s", e)
        raise KeyGenerationError(f"Failed to generate keys: {e}") from e


def generate_public_key(private_key: str) -> str:
    """
    Derive the public encryption key from a private key.

    Args:
        private_key: Base64-encoded private encryption key string

    Returns:
        Base64-encoded public encryption key string

    Raises:
        KeyGenerationError: If public key derivation fails
    """
    try:
        private_key_bytes = b64_str_to_bytes(private_key)
        private_key_obj = nacl.public.PrivateKey(private_key_bytes)
        public_key_str = bytes_to_b64_str(bytes(private_key_obj.public_key))

        logger.debug("Derived public key from private key")
        return public_key_str

    except EncodingError:
        raise
    except Exception as e:
        logger.error("Failed to generate public key: %s", e)
        raise KeyGenerationError(f"Public key derivation failed: {e}") from e


def sign_message(signing_private_key: str, message: bytes) -> bytes:
    """
    Sign a message using Ed25519.

    Args:
        signing_private_key: Base64-encoded signing private key
        message: Message to sign

    Returns:
        Signed message (signature + message)

    Raises:
        SignatureError: If signing fails
    """
    try:
        key_bytes = b64_str_to_bytes(signing_private_key)
        signing_key = nacl.signing.SigningKey(key_bytes)
        signed = signing_key.sign(message)

        logger.debug("Signed %d bytes", len(message))
        return bytes(signed)

    except Exception as e:
        logger.error("Message signing failed: %s", e)
        raise SignatureError(f"Signing failed: {e}") from e


def verify_signature(signing_public_key: str, signed_message: bytes) -> bytes:
    """
    Verify and extract message from signed data.

    Args:
        signing_public_key: Base64-encoded signing public key
        signed_message: Signed message to verify

    Returns:
        Original message if signature is valid

    Raises:
        SignatureError: If signature verification fails
    """
    try:
        key_bytes = b64_str_to_bytes(signing_public_key)
        verify_key = nacl.signing.VerifyKey(key_bytes)
        message = verify_key.verify(signed_message)

        logger.debug("Verified signature, extracted %d bytes", len(message))
        return message

    except nacl.exceptions.BadSignatureError as e:
        logger.warning("Signature verification failed")
        raise SignatureError("Invalid signature") from e
    except Exception as e:
        logger.error("Signature verification error: %s", e)
        raise SignatureError(f"Verification failed: {e}") from e


def encrypt_asym(
        sender_private_key: str,
        recipient_public_key: str,
        message: bytes
) -> bytes:
    """
    Encrypt a message with authenticated encryption using Box.

    Args:
        sender_private_key: Base64-encoded sender's private encryption key
        recipient_public_key: Base64-encoded recipient's public encryption key
        message: Message to encrypt as bytes

    Returns:
        Encrypted message as bytes (includes nonce and authentication)

    Raises:
        EncryptionError: If encryption fails
        TypeError: If message is not bytes

    Note:
        Uses NaCl's Box which provides authenticated encryption.
        The recipient can verify the message came from the stated sender.
    """
    if not isinstance(message, bytes):
        raise TypeError(f"Message must be bytes, not {type(message).__name__}")

    try:
        sender_key_bytes = b64_str_to_bytes(sender_private_key)
        recipient_key_bytes = b64_str_to_bytes(recipient_public_key)

        sender_key_obj = nacl.public.PrivateKey(sender_key_bytes)
        recipient_key_obj = nacl.public.PublicKey(recipient_key_bytes)

        box = nacl.public.Box(sender_key_obj, recipient_key_obj)
        encrypted = box.encrypt(message)

        logger.debug("Encrypted %d bytes to %d bytes", len(message), len(encrypted))
        return encrypted

    except EncodingError:
        raise
    except nacl.exceptions.CryptoError as e:
        logger.error("Encryption failed: %s", e)
        raise EncryptionError(f"NaCl encryption error: {e}") from e
    except Exception as e:
        logger.error("Unexpected encryption error: %s", e)
        raise EncryptionError(f"Encryption failed: {e}") from e


def decrypt_asym(
        recipient_private_key: str,
        sender_public_key: str,
        message: bytes
) -> bytes:
    """
    Decrypt a message using authenticated decryption with Box.

    Args:
        recipient_private_key: Base64-encoded recipient's private encryption key
        sender_public_key: Base64-encoded sender's public encryption key
        message: Encrypted message as bytes

    Returns:
        Decrypted message as bytes

    Raises:
        DecryptionError: If decryption fails
        TypeError: If message is not bytes

    Note:
        Decryption will fail if:
        - Wrong private key is used
        - Wrong sender public key is used
        - Message has been tampered with
        - Message format is invalid
    """
    if not isinstance(message, bytes):
        raise TypeError(f"Message must be bytes, not {type(message).__name__}")

    try:
        recipient_key_bytes = b64_str_to_bytes(recipient_private_key)
        sender_key_bytes = b64_str_to_bytes(sender_public_key)

        recipient_key_obj = nacl.public.PrivateKey(recipient_key_bytes)
        sender_key_obj = nacl.public.PublicKey(sender_key_bytes)

        box = nacl.public.Box(recipient_key_obj, sender_key_obj)
        decrypted = box.decrypt(message)

        logger.debug("Decrypted %d bytes to %d bytes", len(message), len(decrypted))
        return decrypted

    except EncodingError:
        raise
    except nacl.exceptions.CryptoError as e:
        logger.warning("Decryption failed (wrong key or corrupted data): %s", type(e).__name__)
        raise DecryptionError(f"NaCl decryption error: {type(e).__name__}") from e
    except Exception as e:
        logger.error("Unexpected decryption error: %s", e)
        raise DecryptionError(f"Decryption failed: {e}") from e


def verify_key_pair(enc_public_key: str, enc_private_key: str) -> bool:
    """
    Verify that encryption public and private key form a valid pair.

    Args:
        enc_public_key: Base64-encoded public encryption key string
        enc_private_key: Base64-encoded private encryption key string

    Returns:
        True if the keys are a valid pair, False otherwise
    """
    try:
        derived_public = generate_public_key(enc_private_key)
        return derived_public == enc_public_key
    except Exception as e:
        logger.debug("Key pair verification failed: %s", e)
        return False


def test_encryption_roundtrip(
        sender_enc_private: str,
        sender_enc_public: str,
        recipient_enc_private: str,
        recipient_enc_public: str,
        message: bytes
) -> bool:
    """
    Test authenticated encryption and decryption roundtrip.

    Args:
        sender_enc_private: Sender's private encryption key
        sender_enc_public: Sender's public encryption key
        recipient_enc_private: Recipient's private encryption key
        recipient_enc_public: Recipient's public encryption key
        message: Test message as bytes

    Returns:
        True if roundtrip successful, False otherwise
    """
    try:
        encrypted = encrypt_asym(sender_enc_private, recipient_enc_public, message)
        decrypted = decrypt_asym(recipient_enc_private, sender_enc_public, encrypted)
        return decrypted == message
    except Exception as e:
        logger.debug("Encryption roundtrip test failed: %s", e)
        return False


def main():
    """Example usage and testing of cryptographic functions."""
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    print("=" * 70)
    print("Vault UDP Socket Helper - Authenticated Crypto Demo")
    print("=" * 70)

    # Test message
    test_message = "This is a secret message! 🔒"
    test_bytes = test_message.encode('utf-8')

    print(f"\nOriginal message: '{test_message}'")
    print(f"Message length: {len(test_bytes)} bytes")

    # Generate keys for sender and recipient
    print("\n--- Key Generation ---")
    try:
        sender_enc_pub, sender_enc_priv, sender_sign_pub, sender_sign_priv = generate_keys_asym()
        recipient_enc_pub, recipient_enc_priv, recipient_sign_pub, recipient_sign_priv = generate_keys_asym()

        print(f"Sender encryption public:   {sender_enc_pub[:40]}...")
        print(f"Sender signing public:      {sender_sign_pub[:40]}...")
        print(f"Recipient encryption public: {recipient_enc_pub[:40]}...")
        print(f"Recipient signing public:    {recipient_sign_pub[:40]}...")
    except KeyGenerationError as e:
        print(f"ERROR: {e}")
        return

    # Verify key pairs
    print("\n--- Key Pair Verification ---")
    sender_valid = verify_key_pair(sender_enc_pub, sender_enc_priv)
    recipient_valid = verify_key_pair(recipient_enc_pub, recipient_enc_priv)
    print(f"Sender key pair valid: {sender_valid}")
    print(f"Recipient key pair valid: {recipient_valid}")

    # Authenticated Encryption (sender to recipient)
    print("\n--- Authenticated Encryption ---")
    try:
        encrypted = encrypt_asym(sender_enc_priv, recipient_enc_pub, test_bytes)
        print(f"Encrypted length: {len(encrypted)} bytes")
        print(f"Encrypted (hex): {encrypted[:40].hex()}...")
    except EncryptionError as e:
        print(f"ERROR: {e}")
        return

    # Authenticated Decryption
    print("\n--- Authenticated Decryption ---")
    try:
        decrypted = decrypt_asym(recipient_enc_priv, sender_enc_pub, encrypted)
        decrypted_message = decrypted.decode('utf-8')
        print(f"Decrypted message: '{decrypted_message}'")
        print(f"Decryption successful: {decrypted_message == test_message}")
    except DecryptionError as e:
        print(f"ERROR: {e}")
        return

    # Test with wrong sender key (should fail)
    print("\n--- Wrong Sender Test ---")
    attacker_enc_pub, attacker_enc_priv, _, _ = generate_keys_asym()
    try:
        decrypt_asym(recipient_enc_priv, attacker_enc_pub, encrypted)
        print("ERROR: Decryption should have failed!")
    except DecryptionError:
        print("Correctly rejected wrong sender ✓")

    # Test roundtrip
    print("\n--- Roundtrip Test ---")
    roundtrip_ok = test_encryption_roundtrip(
        sender_enc_priv, sender_enc_pub,
        recipient_enc_priv, recipient_enc_pub,
        test_bytes
    )
    print(f"Roundtrip test: {'PASSED ✓' if roundtrip_ok else 'FAILED ✗'}")

    # Signing demonstration
    print("\n--- Message Signing ---")
    try:
        signed_message = sign_message(sender_sign_priv, test_bytes)
        print(f"Signed message length: {len(signed_message)} bytes")

        verified_message = verify_signature(sender_sign_pub, signed_message)
        print(f"Verified message: '{verified_message.decode('utf-8')}'")
        print(f"Signature valid: {verified_message == test_bytes}")
    except SignatureError as e:
        print(f"ERROR: {e}")

    # Test with wrong signing key
    print("\n--- Wrong Signature Test ---")
    try:
        verify_signature(recipient_sign_pub, signed_message)
        print("ERROR: Signature verification should have failed!")
    except SignatureError:
        print("Correctly rejected wrong signature ✓")

    # Base64 encoding tests
    print("\n--- Base64 Encoding/Decoding ---")
    test_data = b"Hello, World!"
    encoded = bytes_to_b64_str(test_data)
    decoded = b64_str_to_bytes(encoded)
    print(f"Original: {test_data}")
    print(f"Encoded:  {encoded}")
    print(f"Decoded:  {decoded}")
    print(f"Match: {decoded == test_data}")

    print("\n" + "=" * 70)
    print("All tests completed successfully! ✓")
    print("=" * 70)


if __name__ == '__main__':
    main()
