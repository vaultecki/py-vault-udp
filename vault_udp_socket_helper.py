# Copyright [2025] [ecki]
# SPDX-License-Identifier: Apache-2.0

"""
Vault UDP Socket Helper Module

Provides cryptographic primitives for asymmetric encryption using NaCl/libsodium.
This module handles key generation, encoding, and encryption/decryption operations.
"""

import base64
import logging
from typing import Tuple

import nacl.encoding
import nacl.exceptions
import nacl.hash
import nacl.public
import nacl.secret
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
        # Handle both str and bytes input
        if isinstance(data, bytes):
            data = data.decode('utf-8')

        return base64.b64decode(data.encode('utf-8'))
    except Exception as e:
        logger.error("Failed to decode base64 to bytes: %s", e)
        raise EncodingError(f"Base64 decoding failed: {e}") from e


def generate_keys_asym() -> Tuple[str, str]:
    """
    Generate a new asymmetric key pair using NaCl.

    Returns:
        Tuple of (public_key, private_key) as Base64-encoded strings

    Raises:
        KeyGenerationError: If key generation fails

    Note:
        Uses X25519 (Curve25519) for key exchange.
    """
    try:
        private_key_obj = nacl.public.PrivateKey.generate()
        public_key_str = bytes_to_b64_str(bytes(private_key_obj.public_key))
        private_key_str = bytes_to_b64_str(bytes(private_key_obj))

        logger.debug("Generated new asymmetric key pair")
        return public_key_str, private_key_str

    except Exception as e:
        logger.error("Key generation failed: %s", e)
        raise KeyGenerationError(f"Failed to generate keys: {e}") from e


def generate_public_key(private_key: str) -> str:
    """
    Derive the public key from a private key.

    Args:
        private_key: Base64-encoded private key string

    Returns:
        Base64-encoded public key string

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


def encrypt_asym(public_key: str, message: bytes) -> bytes:
    """
    Encrypt a message using asymmetric encryption (sealed box).

    Args:
        public_key: Base64-encoded public key string
        message: Message to encrypt as bytes

    Returns:
        Encrypted message as bytes

    Raises:
        EncryptionError: If encryption fails
        TypeError: If message is not bytes

    Note:
        Uses NaCl's SealedBox which provides anonymous encryption.
        The ciphertext is authenticated but the sender is anonymous.
    """
    if not isinstance(message, bytes):
        raise TypeError(f"Message must be bytes, not {type(message).__name__}")

    try:
        public_key_bytes = b64_str_to_bytes(public_key)
        public_key_obj = nacl.public.PublicKey(public_key_bytes)
        encrypt_box = nacl.public.SealedBox(public_key_obj)
        encrypted = encrypt_box.encrypt(message)

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


def decrypt_asym(private_key: str, message: bytes) -> bytes:
    """
    Decrypt a message using asymmetric decryption (sealed box).

    Args:
        private_key: Base64-encoded private key string
        message: Encrypted message as bytes

    Returns:
        Decrypted message as bytes

    Raises:
        DecryptionError: If decryption fails
        TypeError: If message is not bytes

    Note:
        Decryption will fail if:
        - Wrong private key is used
        - Message has been tampered with
        - Message format is invalid
    """
    if not isinstance(message, bytes):
        raise TypeError(f"Message must be bytes, not {type(message).__name__}")

    try:
        private_key_bytes = b64_str_to_bytes(private_key)
        private_key_obj = nacl.public.PrivateKey(private_key_bytes)
        decrypt_box = nacl.public.SealedBox(private_key_obj)
        decrypted = decrypt_box.decrypt(message)

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


def hash_password(password: str, encoder=nacl.encoding.Base64Encoder) -> str:
    """
    Hash a password using SHA-256.

    Args:
        password: Password string to hash
        encoder: NaCl encoder to use (default: Base64)

    Returns:
        Base64-encoded hash string

    Note:
        This is a simple hash, not suitable for password storage.
        Use proper password hashing (e.g., Argon2) for authentication.
    """
    try:
        hasher = nacl.hash.sha256
        hashed = hasher(password.encode("utf-8"), encoder=encoder)
        return hashed.decode("utf-8")
    except Exception as e:
        logger.error("Password hashing failed: %s", e)
        raise CryptoError(f"Hashing failed: {e}") from e


def verify_key_pair(public_key: str, private_key: str) -> bool:
    """
    Verify that a public and private key form a valid pair.

    Args:
        public_key: Base64-encoded public key string
        private_key: Base64-encoded private key string

    Returns:
        True if the keys are a valid pair, False otherwise
    """
    try:
        derived_public = generate_public_key(private_key)
        return derived_public == public_key
    except Exception as e:
        logger.debug("Key pair verification failed: %s", e)
        return False


def test_encryption_roundtrip(public_key: str, private_key: str, message: bytes) -> bool:
    """
    Test encryption and decryption roundtrip.

    Args:
        public_key: Base64-encoded public key string
        private_key: Base64-encoded private key string
        message: Test message as bytes

    Returns:
        True if roundtrip successful, False otherwise
    """
    try:
        encrypted = encrypt_asym(public_key, message)
        decrypted = decrypt_asym(private_key, encrypted)
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

    print("=" * 60)
    print("Vault UDP Socket Helper - Cryptographic Functions Demo")
    print("=" * 60)

    # Test message
    test_message = "This is a secret message! 🔐"
    test_bytes = test_message.encode('utf-8')

    print(f"\nOriginal message: '{test_message}'")
    print(f"Message length: {len(test_bytes)} bytes")

    # Generate keys
    print("\n--- Key Generation ---")
    try:
        public_key, private_key = generate_keys_asym()
        print(f"Public key:  {public_key[:40]}...")
        print(f"Private key: {private_key[:40]}...")
        print(f"Key lengths: public={len(public_key)}, private={len(private_key)}")
    except KeyGenerationError as e:
        print(f"ERROR: {e}")
        return

    # Verify key pair
    print("\n--- Key Pair Verification ---")
    is_valid = verify_key_pair(public_key, private_key)
    print(f"Key pair valid: {is_valid}")

    # Test public key derivation
    print("\n--- Public Key Derivation ---")
    derived_public = generate_public_key(private_key)
    print(f"Derived matches original: {derived_public == public_key}")

    # Encryption
    print("\n--- Encryption ---")
    try:
        encrypted = encrypt_asym(public_key, test_bytes)
        print(f"Encrypted length: {len(encrypted)} bytes")
        print(f"Encrypted (hex): {encrypted[:40].hex()}...")
    except EncryptionError as e:
        print(f"ERROR: {e}")
        return

    # Decryption
    print("\n--- Decryption ---")
    try:
        decrypted = decrypt_asym(private_key, encrypted)
        decrypted_message = decrypted.decode('utf-8')
        print(f"Decrypted message: '{decrypted_message}'")
        print(f"Decryption successful: {decrypted_message == test_message}")
    except DecryptionError as e:
        print(f"ERROR: {e}")
        return

    # Test roundtrip
    print("\n--- Roundtrip Test ---")
    roundtrip_ok = test_encryption_roundtrip(public_key, private_key, test_bytes)
    print(f"Roundtrip test: {'PASSED ✓' if roundtrip_ok else 'FAILED ✗'}")

    # Test with wrong key
    print("\n--- Wrong Key Test ---")
    wrong_public, wrong_private = generate_keys_asym()
    try:
        decrypt_asym(wrong_private, encrypted)
        print("ERROR: Decryption should have failed!")
    except DecryptionError:
        print("Correctly rejected wrong key ✓")

    # Password hashing demo
    print("\n--- Password Hashing ---")
    password = "mySecretPassword123"
    hashed = hash_password(password)
    print(f"Password: {password}")
    print(f"Hash: {hashed[:50]}...")
    print(f"Hash length: {len(hashed)}")

    # Base64 encoding tests
    print("\n--- Base64 Encoding/Decoding ---")
    test_data = b"Hello, World!"
    encoded = bytes_to_b64_str(test_data)
    decoded = b64_str_to_bytes(encoded)
    print(f"Original: {test_data}")
    print(f"Encoded:  {encoded}")
    print(f"Decoded:  {decoded}")
    print(f"Match: {decoded == test_data}")

    print("\n" + "=" * 60)
    print("All tests completed successfully! ✓")
    print("=" * 60)


if __name__ == '__main__':
    main()
