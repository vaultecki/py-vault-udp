# Copyright [2025] [ecki]
# SPDX-License-Identifier: Apache-2.0

"""
Vault UDP Asymmetric Encryption Module

Provides thread-safe authenticated asymmetric encryption for UDP communication
with automatic key lifecycle management and replay attack prevention.
"""

import logging
import math
import os
import random
import threading
import time
from collections import defaultdict
from typing import Tuple, Optional, Dict, Set

import nacl.exceptions

import vault_udp_socket_helper

logger = logging.getLogger(__name__)

# Constants
MIN_CLEANUP_INTERVAL_SECONDS = 5
DEFAULT_KEY_LIFETIME_SECONDS = 60
MAX_MESSAGE_AGE_SECONDS = 60
NONCE_CACHE_SIZE = 10000


class EncryptionError(Exception):
    """Base exception for encryption operations."""
    pass


class DecryptionError(EncryptionError):
    """Raised when decryption fails."""
    pass


class KeyNotFoundError(EncryptionError):
    """Raised when required encryption key is not available."""
    pass


class ReplayAttackError(EncryptionError):
    """Raised when a replay attack is detected."""
    pass


class VaultAsymmetricEncryption:
    """
    Manages authenticated asymmetric encryption for UDP communications.

    This class handles:
    - Generation and storage of encryption and signing key pairs
    - Thread-safe management of peer public keys
    - Automatic cleanup of expired keys
    - Authenticated encryption/decryption operations
    - Replay attack prevention with nonce tracking
    - Message freshness validation

    Thread-safe: All public methods use internal locking.
    """

    def __init__(
            self,
            lifetime: int = DEFAULT_KEY_LIFETIME_SECONDS,
            enc_private_key: Optional[str] = None,
            sign_private_key: Optional[str] = None
    ):
        """
        Initialize the encryption manager.

        Args:
            lifetime: Maximum lifetime for peer keys in seconds
            enc_private_key: Optional existing encryption private key
            sign_private_key: Optional existing signing private key
        """
        logger.info("Initializing VaultAsymmetricEncryption")

        # Thread synchronization
        self._lock = threading.RLock()

        # Encryption key storage
        self._peer_enc_keys: Dict[Tuple[str, int], str] = {}
        self._peer_sign_keys: Dict[Tuple[str, int], str] = {}
        self._peer_keys_timestamp: Dict[Tuple[str, int], int] = {}
        self._key_max_lifetime = lifetime

        # Replay protection
        self._seen_nonces: Dict[Tuple[str, int], Set[str]] = defaultdict(set)
        self._message_timestamps: Dict[Tuple[str, int], Dict[str, float]] = defaultdict(dict)

        # Own keys
        self._enc_private_key: Optional[str] = None
        self._sign_private_key: Optional[str] = None
        self.enc_public_key: str = ""
        self.sign_public_key: str = ""

        # Initialize keys
        if enc_private_key and sign_private_key:
            self.set_private_keys(enc_private_key, sign_private_key)
        else:
            self.generate_keys()

        # Cleanup thread
        self._run_cleanup = True
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True,
            name="VaultEncryption-Cleanup"
        )
        self._cleanup_thread.start()

        logger.info("VaultAsymmetricEncryption initialized successfully")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.stop()
        return False

    def generate_keys(self) -> Tuple[str, str]:
        """
        Generate new key pairs (encryption and signing).

        Returns:
            Tuple of (encryption_public_key, signing_public_key)
        """
        logger.info("Generating new key pairs")
        (enc_public, enc_private,
         sign_public, sign_private) = vault_udp_socket_helper.generate_keys_asym()

        self.set_private_keys(enc_private, sign_private)
        logger.info("New key pairs generated")
        return self.enc_public_key, self.sign_public_key

    def set_private_keys(self, enc_private_key: str, sign_private_key: str) -> Tuple[str, str]:
        """
        Set the private keys and derive the public keys.

        Args:
            enc_private_key: The encryption private key to use
            sign_private_key: The signing private key to use

        Returns:
            Tuple of (encryption_public_key, signing_public_key)
        """
        with self._lock:
            logger.debug("Setting new private keys")
            self._enc_private_key = enc_private_key
            self._sign_private_key = sign_private_key

            self.enc_public_key = vault_udp_socket_helper.generate_public_key(
                self._enc_private_key
            )

            # For signing key, we derive verify key differently
            try:
                sign_bytes = vault_udp_socket_helper.b64_str_to_bytes(sign_private_key)
                import nacl.signing
                signing_key = nacl.signing.SigningKey(sign_bytes)
                self.sign_public_key = vault_udp_socket_helper.bytes_to_b64_str(
                    bytes(signing_key.verify_key)
                )
            except Exception as e:
                logger.error("Failed to derive signing public key: %s", e)
                raise

            logger.info("Private keys updated, public keys derived")
            return self.enc_public_key, self.sign_public_key

    def update_peer_keys(
        self,
        addr: Tuple[str, int],
        enc_key: str,
        sign_key: str
    ) -> None:
        """
        Store or update a peer's public keys.

        Args:
            addr: Tuple of (ip_address, port)
            enc_key: The peer's public encryption key
            sign_key: The peer's public signing key
        """
        if not enc_key or not sign_key:
            logger.warning("Attempted to update with empty keys for %s", addr)
            return

        with self._lock:
            addr_tuple = tuple(addr)
            self._peer_enc_keys[addr_tuple] = enc_key
            self._peer_sign_keys[addr_tuple] = sign_key
            self._peer_keys_timestamp[addr_tuple] = self._current_timestamp()
            logger.debug("Updated peer keys for %s", addr)

    def remove_peer_keys(self, addr: Tuple[str, int]) -> None:
        """
        Remove a peer's public keys and replay protection data.

        Args:
            addr: Tuple of (ip_address, port)
        """
        with self._lock:
            addr_tuple = tuple(addr)
            if addr_tuple in self._peer_enc_keys:
                self._peer_enc_keys.pop(addr_tuple)
                self._peer_sign_keys.pop(addr_tuple, None)
                self._peer_keys_timestamp.pop(addr_tuple)
                self._seen_nonces.pop(addr_tuple, None)
                self._message_timestamps.pop(addr_tuple, None)
                logger.info("Removed peer keys for %s", addr)

    def peer_keys_exist(self, addr: Tuple[str, int]) -> bool:
        """
        Check if peer keys exist.

        Args:
            addr: Tuple of (ip_address, port)

        Returns:
            True if keys exist, False otherwise
        """
        with self._lock:
            addr_tuple = tuple(addr)
            return (addr_tuple in self._peer_enc_keys and
                    addr_tuple in self._peer_sign_keys)

    def decrypt(self, data: bytes, addr: Tuple[str, int]) -> bytes:
        """
        Decrypt and verify data from a peer with replay protection.

        Args:
            data: Encrypted data as bytes (format: nonce + timestamp + encrypted_payload)
            addr: Tuple of (ip_address, port)

        Returns:
            Decrypted data as bytes

        Raises:
            DecryptionError: If decryption fails
            ReplayAttackError: If replay attack is detected
        """
        logger.debug("Attempting decryption from %s", addr)

        if not self._enc_private_key:
            raise DecryptionError("No private encryption key configured")

        addr_tuple = tuple(addr)

        with self._lock:
            peer_enc_key = self._peer_enc_keys.get(addr_tuple)

        if not peer_enc_key:
            raise DecryptionError(f"No encryption key available for {addr}")

        try:
            # Decrypt with authenticated encryption
            decrypted_bytes = vault_udp_socket_helper.decrypt_asym(
                self._enc_private_key,
                peer_enc_key,
                data
            )

            # Extract nonce (16 bytes), timestamp (8 bytes), and payload
            if len(decrypted_bytes) < 24:
                raise DecryptionError("Invalid message format")

            nonce = decrypted_bytes[:16].hex()
            timestamp_bytes = decrypted_bytes[16:24]
            payload = decrypted_bytes[24:]

            # Convert timestamp
            import struct
            timestamp = struct.unpack('!d', timestamp_bytes)[0]

            # Verify message freshness
            current_time = time.time()
            age = current_time - timestamp

            if age < 0 or age > MAX_MESSAGE_AGE_SECONDS:
                raise ReplayAttackError(
                    f"Message too old or from future: {age:.1f}s"
                )

            # Check for replay (nonce reuse)
            with self._lock:
                if nonce in self._seen_nonces[addr_tuple]:
                    raise ReplayAttackError(f"Nonce reused from {addr}")

                # Add nonce to seen set
                self._seen_nonces[addr_tuple].add(nonce)
                self._message_timestamps[addr_tuple][nonce] = current_time

                # Limit cache size
                if len(self._seen_nonces[addr_tuple]) > NONCE_CACHE_SIZE:
                    self._cleanup_old_nonces(addr_tuple)

            logger.debug("Successfully decrypted and verified data from %s", addr)
            return payload

        except ReplayAttackError:
            raise
        except nacl.exceptions.CryptoError as e:
            logger.warning("Crypto error during decryption from %s: %s",
                          addr, type(e).__name__)
            raise DecryptionError(f"Decryption failed: {type(e).__name__}") from e
        except Exception as e:
            logger.error("Unexpected error during decryption from %s: %s",
                        addr, type(e).__name__)
            raise DecryptionError(f"Unexpected decryption error: {type(e).__name__}") from e

    def encrypt(self, data: bytes, addr: Tuple[str, int]) -> bytes:
        """
        Encrypt data for a peer with authentication and replay protection.

        Args:
            data: Plain data as bytes
            addr: Tuple of (ip_address, port)

        Returns:
            Encrypted data as bytes (format: encrypted(nonce + timestamp + data))

        Raises:
            KeyNotFoundError: If peer key not found
            EncryptionError: If encryption fails
        """
        logger.debug("Attempting encryption for %s", addr)

        if not self._enc_private_key:
            raise EncryptionError("No private encryption key configured")

        addr_tuple = tuple(addr)

        with self._lock:
            peer_enc_key = self._peer_enc_keys.get(addr_tuple)

        if not peer_enc_key:
            raise KeyNotFoundError(f"No encryption key available for {addr}")

        try:
            # Generate nonce and timestamp
            nonce = os.urandom(16)
            timestamp = time.time()

            # Pack timestamp as double
            import struct
            timestamp_bytes = struct.pack('!d', timestamp)

            # Combine nonce + timestamp + data
            message = nonce + timestamp_bytes + data

            # Encrypt with authenticated encryption
            encrypted_data = vault_udp_socket_helper.encrypt_asym(
                self._enc_private_key,
                peer_enc_key,
                message
            )

            logger.debug("Successfully encrypted data for %s", addr)
            return encrypted_data

        except Exception as e:
            logger.error("Encryption failed for %s: %s", addr, type(e).__name__)
            raise EncryptionError(f"Encryption failed: {type(e).__name__}") from e

    def encrypt_if_possible(self, data: bytes, addr: Tuple[str, int]) -> bytes:
        """
        Encrypt data if key available, otherwise return unencrypted.

        Args:
            data: Plain data as bytes
            addr: Tuple of (ip_address, port)

        Returns:
            Encrypted data if key available, otherwise original data
        """
        try:
            return self.encrypt(data, addr)
        except KeyNotFoundError:
            logger.debug("No key for %s, sending unencrypted", addr)
            return data
        except EncryptionError as e:
            logger.warning("Encryption failed for %s: %s, sending unencrypted", addr, e)
            return data

    def decrypt_if_possible(self, data: bytes, addr: Tuple[str, int]) -> bytes:
        """
        Attempt to decrypt data, return original if decryption fails.

        Args:
            data: Potentially encrypted data as bytes
            addr: Tuple of (ip_address, port)

        Returns:
            Decrypted data if successful, otherwise original data
        """
        try:
            return self.decrypt(data, addr)
        except (DecryptionError, ReplayAttackError) as e:
            logger.debug("Decryption failed for %s: %s, data may be unencrypted",
                        addr, type(e).__name__)
            return data

    def cleanup_expired_keys(self) -> int:
        """
        Remove expired peer keys and old nonces.

        Returns:
            Number of keys removed
        """
        current_time = self._current_timestamp()
        expired_addrs = []

        with self._lock:
            # Find expired keys
            for addr, timestamp in self._peer_keys_timestamp.items():
                if current_time - timestamp > self._key_max_lifetime:
                    expired_addrs.append(addr)

            # Remove expired keys
            for addr in expired_addrs:
                self._peer_enc_keys.pop(addr, None)
                self._peer_sign_keys.pop(addr, None)
                self._peer_keys_timestamp.pop(addr, None)
                self._seen_nonces.pop(addr, None)
                self._message_timestamps.pop(addr, None)

            # Clean up orphaned entries
            orphaned = (set(self._peer_keys_timestamp.keys()) -
                       set(self._peer_enc_keys.keys()))
            for addr in orphaned:
                self._peer_keys_timestamp.pop(addr, None)
                self._seen_nonces.pop(addr, None)
                self._message_timestamps.pop(addr, None)

        if expired_addrs:
            logger.info("Cleaned up %d expired keys", len(expired_addrs))

        return len(expired_addrs)

    def _cleanup_old_nonces(self, addr: Tuple[str, int]) -> None:
        """
        Clean up old nonces for a specific peer to prevent unbounded growth.

        Args:
            addr: Peer address
        """
        current_time = time.time()

        # Remove nonces older than max message age
        old_nonces = [
            nonce for nonce, ts in self._message_timestamps[addr].items()
            if current_time - ts > MAX_MESSAGE_AGE_SECONDS
        ]

        for nonce in old_nonces:
            self._seen_nonces[addr].discard(nonce)
            self._message_timestamps[addr].pop(nonce, None)

        logger.debug("Cleaned up %d old nonces for %s", len(old_nonces), addr)

    def stop(self, timeout: float = 5.0) -> None:
        """
        Stop the cleanup thread gracefully.

        Args:
            timeout: Maximum seconds to wait for thread termination
        """
        logger.info("Stopping VaultAsymmetricEncryption")
        self._run_cleanup = False

        if self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=timeout)
            if self._cleanup_thread.is_alive():
                logger.warning("Cleanup thread did not terminate within timeout")
            else:
                logger.info("Cleanup thread terminated successfully")

    def get_stats(self) -> Dict[str, any]:
        """
        Get statistics about managed keys and replay protection.

        Returns:
            Dictionary with key counts and configuration
        """
        with self._lock:
            total_nonces = sum(len(nonces) for nonces in self._seen_nonces.values())
            return {
                'active_peer_keys': len(self._peer_enc_keys),
                'key_lifetime_seconds': self._key_max_lifetime,
                'has_enc_private_key': bool(self._enc_private_key),
                'has_sign_private_key': bool(self._sign_private_key),
                'total_tracked_nonces': total_nonces,
                'peers_with_nonces': len(self._seen_nonces)
            }

    def _cleanup_loop(self) -> None:
        """Background thread loop for periodic key and nonce cleanup."""
        logger.debug("Cleanup thread started")

        while self._run_cleanup:
            try:
                self.cleanup_expired_keys()

                # Also cleanup old nonces for all peers
                with self._lock:
                    for addr in list(self._seen_nonces.keys()):
                        self._cleanup_old_nonces(addr)

            except Exception as e:
                logger.error("Error during cleanup: %s", e, exc_info=True)

            # Random sleep interval to avoid synchronization
            sleep_duration = random.randint(
                MIN_CLEANUP_INTERVAL_SECONDS,
                max(MIN_CLEANUP_INTERVAL_SECONDS, self._key_max_lifetime // 2)
            )
            time.sleep(sleep_duration)

        logger.debug("Cleanup thread stopped")

    @staticmethod
    def _current_timestamp() -> int:
        """Get current Unix timestamp as integer."""
        return math.floor(time.time())


def main():
    """Example usage and testing."""
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    print("Initializing VaultAsymmetricEncryption with replay protection...")

    with VaultAsymmetricEncryption(lifetime=30) as encryption:
        print(f"Encryption public key: {encryption.enc_public_key[:32]}...")
        print(f"Signing public key: {encryption.sign_public_key[:32]}...")
        print(f"Stats: {encryption.get_stats()}")

        # Simulate peer key addition
        test_addr = ("192.168.1.100", 5000)
        peer_enc_pub, peer_enc_priv, peer_sign_pub, peer_sign_priv = (
            vault_udp_socket_helper.generate_keys_asym()
        )
        encryption.update_peer_keys(test_addr, peer_enc_pub, peer_sign_pub)
        print(f"\nAdded peer keys for {test_addr}")
        print(f"Stats: {encryption.get_stats()}")

        time.sleep(2)
        print("\nVaultAsymmetricEncryption demonstration complete")


if __name__ == '__main__':
    main()
