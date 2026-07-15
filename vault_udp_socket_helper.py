# Copyright [2025] [ecki]
# SPDX-License-Identifier: Apache-2.0

"""
Vault UDP Socket Helper Module

Provides cryptographic primitives for anonymous public-key encryption using
NaCl/libsodium's SealedBox. This module handles key generation, encoding,
and encryption/decryption operations.

Note: SealedBox does not authenticate the sender. Anyone holding a
recipient's public key can produce a message that decrypts successfully for
that recipient; there is no cryptographic proof of who sent it.
"""

import base64
import logging
from typing import Tuple

import nacl.encoding
import nacl.exceptions
import nacl.public
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


def generate_keys_asym() -> Tuple[str, str]:
    """
    Generate a new X25519 encryption key pair.

    Returns:
        Tuple of (public_key, private_key) as Base64-encoded strings

    Raises:
        KeyGenerationError: If key generation fails
    """
    try:
        private_key_obj = nacl.public.PrivateKey.generate()
        public_str = bytes_to_b64_str(bytes(private_key_obj.public_key))
        private_str = bytes_to_b64_str(bytes(private_key_obj))

        logger.debug("Generated new asymmetric key pair")
        return public_str, private_str

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


def encrypt_sealed(recipient_public_key: str, message: bytes) -> bytes:
    """
    Encrypt a message for a recipient using an anonymous SealedBox.

    Args:
        recipient_public_key: Base64-encoded recipient's public encryption key
        message: Message to encrypt as bytes

    Returns:
        Encrypted message as bytes (ephemeral sender public key + ciphertext)

    Raises:
        EncryptionError: If encryption fails
        TypeError: If message is not bytes

    Note:
        SealedBox encryption only requires the recipient's public key -- no
        key pair of our own is needed to encrypt, and the recipient cannot
        tell who encrypted the message.
    """
    if not isinstance(message, bytes):
        raise TypeError(f"Message must be bytes, not {type(message).__name__}")

    try:
        recipient_key_bytes = b64_str_to_bytes(recipient_public_key)
        recipient_key_obj = nacl.public.PublicKey(recipient_key_bytes)

        sealed_box = nacl.public.SealedBox(recipient_key_obj)
        encrypted = sealed_box.encrypt(message)

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


def decrypt_sealed(recipient_private_key: str, message: bytes) -> bytes:
    """
    Decrypt a SealedBox message using our own private key.

    Args:
        recipient_private_key: Base64-encoded recipient's private encryption key
        message: Encrypted message as bytes

    Returns:
        Decrypted message as bytes

    Raises:
        DecryptionError: If decryption fails
        TypeError: If message is not bytes

    Note:
        Decryption only requires our own private key. This means anyone
        holding our public key can produce a message we'll happily decrypt
        -- there is no proof of who actually sent it.
    """
    if not isinstance(message, bytes):
        raise TypeError(f"Message must be bytes, not {type(message).__name__}")

    try:
        recipient_key_bytes = b64_str_to_bytes(recipient_private_key)
        recipient_key_obj = nacl.public.PrivateKey(recipient_key_bytes)

        sealed_box = nacl.public.SealedBox(recipient_key_obj)
        decrypted = sealed_box.decrypt(message)

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
        recipient_enc_private: str,
        recipient_enc_public: str,
        message: bytes
) -> bool:
    """
    Test SealedBox encryption and decryption roundtrip.

    Args:
        recipient_enc_private: Recipient's private encryption key
        recipient_enc_public: Recipient's public encryption key
        message: Test message as bytes

    Returns:
        True if roundtrip successful, False otherwise
    """
    try:
        encrypted = encrypt_sealed(recipient_enc_public, message)
        decrypted = decrypt_sealed(recipient_enc_private, encrypted)
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
    print("Vault UDP Socket Helper - Sealed Box Crypto Demo")
    print("=" * 70)

    # Test message
    test_message = "This is a secret message! 🔒"
    test_bytes = test_message.encode('utf-8')

    print(f"\nOriginal message: '{test_message}'")
    print(f"Message length: {len(test_bytes)} bytes")

    # Generate keys for the recipient
    print("\n--- Key Generation ---")
    try:
        recipient_pub, recipient_priv = generate_keys_asym()
        print(f"Recipient public key: {recipient_pub[:40]}...")
    except KeyGenerationError as e:
        print(f"ERROR: {e}")
        return

    # Verify key pair
    print("\n--- Key Pair Verification ---")
    valid = verify_key_pair(recipient_pub, recipient_priv)
    print(f"Recipient key pair valid: {valid}")

    # Anonymous encryption (no sender key pair needed)
    print("\n--- Sealed Box Encryption ---")
    try:
        encrypted = encrypt_sealed(recipient_pub, test_bytes)
        print(f"Encrypted length: {len(encrypted)} bytes")
        print(f"Encrypted (hex): {encrypted[:40].hex()}...")
    except EncryptionError as e:
        print(f"ERROR: {e}")
        return

    # Decryption
    print("\n--- Sealed Box Decryption ---")
    try:
        decrypted = decrypt_sealed(recipient_priv, encrypted)
        decrypted_message = decrypted.decode('utf-8')
        print(f"Decrypted message: '{decrypted_message}'")
        print(f"Decryption successful: {decrypted_message == test_message}")
    except DecryptionError as e:
        print(f"ERROR: {e}")
        return

    # Test with wrong recipient key (should fail)
    print("\n--- Wrong Recipient Test ---")
    _, other_priv = generate_keys_asym()
    try:
        decrypt_sealed(other_priv, encrypted)
        print("ERROR: Decryption should have failed!")
    except DecryptionError:
        print("Correctly rejected wrong recipient key ✓")

    # Test roundtrip
    print("\n--- Roundtrip Test ---")
    roundtrip_ok = test_encryption_roundtrip(recipient_priv, recipient_pub, test_bytes)
    print(f"Roundtrip test: {'PASSED ✓' if roundtrip_ok else 'FAILED ✗'}")

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
