# Copyright [2025] [ecki]
# SPDX-License-Identifier: Apache-2.0

"""
Vault UDP Asymmetric Encryption Module

Provides thread-safe anonymous public-key encryption for UDP communication
using NaCl SealedBox, with automatic key lifecycle management.

Note: SealedBox does not authenticate the sender and this module does not
track message nonces, so it provides no replay protection. Decryption only
requires our own private key, which is what lets key exchange work without
a network-address-dependent lookup: see vault_udp_socket.py.
"""

import logging
import math
import threading
import time
from typing import Any, Tuple, Optional, Dict

import vault_udp_socket_helper

logger = logging.getLogger(__name__)

# Constants
MIN_CLEANUP_INTERVAL_SECONDS = 5
DEFAULT_KEY_LIFETIME_SECONDS = 60


class EncryptionError(Exception):
    """Base exception for encryption operations."""
    pass


class DecryptionError(EncryptionError):
    """Raised when decryption fails."""
    pass


class KeyNotFoundError(EncryptionError):
    """Raised when required encryption key is not available."""
    pass


class VaultAsymmetricEncryption:
    """
    Manages anonymous public-key encryption for UDP communications.

    This class handles:
    - Generation and storage of our own encryption key pair
    - Thread-safe management of peer public keys (used to encrypt *to* them)
    - Automatic cleanup of expired peer keys
    - SealedBox encryption/decryption operations

    Thread-safe: All public methods use internal locking.
    """

    def __init__(
            self,
            lifetime: int = DEFAULT_KEY_LIFETIME_SECONDS,
            enc_private_key: Optional[str] = None
    ):
        """
        Initialize the encryption manager.

        Args:
            lifetime: Maximum lifetime for peer keys in seconds
            enc_private_key: Optional existing encryption private key
        """
        logger.info("Initializing VaultAsymmetricEncryption")

        # Thread synchronization
        self._lock = threading.RLock()

        # Peer public key storage (needed to encrypt *to* a peer; decrypting
        # our own incoming messages never needs to know who sent them)
        self._peer_enc_keys: Dict[Tuple[str, int], str] = {}
        self._peer_keys_timestamp: Dict[Tuple[str, int], int] = {}
        self._key_max_lifetime = lifetime

        # Own keys
        self._enc_private_key: Optional[str] = None
        self.enc_public_key: str = ""

        # Initialize keys
        if enc_private_key:
            self.set_private_keys(enc_private_key)
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

    def generate_keys(self) -> str:
        """
        Generate a new encryption key pair.

        Returns:
            The new encryption public key
        """
        logger.info("Generating new key pair")
        enc_public, enc_private = vault_udp_socket_helper.generate_keys_asym()

        self.set_private_keys(enc_private)
        logger.info("New key pair generated")
        return self.enc_public_key

    def set_private_keys(self, enc_private_key: str) -> str:
        """
        Set the private key and derive the public key.

        Args:
            enc_private_key: The encryption private key to use

        Returns:
            The derived encryption public key
        """
        with self._lock:
            logger.debug("Setting new private key")
            self._enc_private_key = enc_private_key
            self.enc_public_key = vault_udp_socket_helper.generate_public_key(
                self._enc_private_key
            )
            logger.info("Private key updated, public key derived")
            return self.enc_public_key

    def update_peer_keys(self, addr: Tuple[str, int], enc_key: str) -> None:
        """
        Store or update a peer's public key.

        Args:
            addr: Tuple of (ip_address, port)
            enc_key: The peer's public encryption key
        """
        if not enc_key:
            logger.warning("Attempted to update with empty key for %s", addr)
            return

        with self._lock:
            addr_tuple: Tuple[str, int] = (addr[0], addr[1])
            self._peer_enc_keys[addr_tuple] = enc_key
            self._peer_keys_timestamp[addr_tuple] = self._current_timestamp()
            logger.debug("Updated peer key for %s", addr)

    def remove_peer_keys(self, addr: Tuple[str, int]) -> None:
        """
        Remove a peer's public key.

        Args:
            addr: Tuple of (ip_address, port)
        """
        with self._lock:
            addr_tuple: Tuple[str, int] = (addr[0], addr[1])
            if addr_tuple in self._peer_enc_keys:
                self._peer_enc_keys.pop(addr_tuple)
                self._peer_keys_timestamp.pop(addr_tuple, None)
                logger.info("Removed peer key for %s", addr)

    def peer_keys_exist(self, addr: Tuple[str, int]) -> bool:
        """
        Check if a peer key exists.

        Args:
            addr: Tuple of (ip_address, port)

        Returns:
            True if a key exists, False otherwise
        """
        with self._lock:
            addr_tuple: Tuple[str, int] = (addr[0], addr[1])
            return addr_tuple in self._peer_enc_keys

    def get_peer_key(self, addr: Tuple[str, int]) -> Optional[str]:
        """
        Get the currently stored public key for a peer, if any.

        Args:
            addr: Tuple of (ip_address, port)

        Returns:
            The stored public key, or None if we don't have one
        """
        with self._lock:
            addr_tuple: Tuple[str, int] = (addr[0], addr[1])
            return self._peer_enc_keys.get(addr_tuple)

    def set_key_lifetime(self, lifetime: int) -> None:
        """
        Change how long peer keys are kept before they're treated as expired.

        Args:
            lifetime: New maximum lifetime for peer keys, in seconds
        """
        with self._lock:
            self._key_max_lifetime = lifetime
            logger.info("Key lifetime updated to %d seconds", lifetime)

    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypt data addressed to us.

        Args:
            data: SealedBox-encrypted data as bytes

        Returns:
            Decrypted data as bytes

        Raises:
            DecryptionError: If decryption fails

        Note:
            This only requires our own private key. It does not (and
            cannot) verify who sent the message.
        """
        logger.debug("Attempting decryption")

        if not self._enc_private_key:
            raise DecryptionError("No private encryption key configured")

        try:
            decrypted_bytes = vault_udp_socket_helper.decrypt_sealed(
                self._enc_private_key,
                data
            )
            logger.debug("Successfully decrypted data")
            return decrypted_bytes

        # decrypt_sealed() already wraps NaCl/encoding errors into its own
        # CryptoError hierarchy before they get here.
        except vault_udp_socket_helper.CryptoError as e:
            raise DecryptionError(f"Decryption failed: {e}") from e
        except Exception as e:
            logger.error("Unexpected error during decryption: %s", type(e).__name__)
            raise DecryptionError(f"Unexpected decryption error: {type(e).__name__}") from e

    def encrypt(self, data: bytes, addr: Tuple[str, int]) -> bytes:
        """
        Encrypt data for a peer.

        Args:
            data: Plain data as bytes
            addr: Tuple of (ip_address, port)

        Returns:
            Encrypted data as bytes

        Raises:
            KeyNotFoundError: If peer key not found
            EncryptionError: If encryption fails
        """
        logger.debug("Attempting encryption for %s", addr)

        addr_tuple: Tuple[str, int] = (addr[0], addr[1])

        with self._lock:
            peer_enc_key = self._peer_enc_keys.get(addr_tuple)

        if not peer_enc_key:
            raise KeyNotFoundError(f"No encryption key available for {addr}")

        try:
            encrypted_data = vault_udp_socket_helper.encrypt_sealed(peer_enc_key, data)
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

    def decrypt_if_possible(self, data: bytes) -> bytes:
        """
        Attempt to decrypt data, return original if decryption fails.

        Args:
            data: Potentially encrypted data as bytes

        Returns:
            Decrypted data if successful, otherwise original data
        """
        try:
            return self.decrypt(data)
        except DecryptionError as e:
            logger.debug("Decryption failed: %s, data may be unencrypted", type(e).__name__)
            return data

    def cleanup_expired_keys(self) -> int:
        """
        Remove expired peer keys.

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
                self._peer_keys_timestamp.pop(addr, None)

        if expired_addrs:
            logger.info("Cleaned up %d expired keys", len(expired_addrs))

        return len(expired_addrs)

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

    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics about managed keys.

        Returns:
            Dictionary with key counts and configuration
        """
        with self._lock:
            return {
                'active_peer_keys': len(self._peer_enc_keys),
                'key_lifetime_seconds': self._key_max_lifetime,
                'has_enc_private_key': bool(self._enc_private_key),
            }

    def _cleanup_loop(self) -> None:
        """Background thread loop for periodic key cleanup."""
        logger.debug("Cleanup thread started")

        while self._run_cleanup:
            try:
                self.cleanup_expired_keys()
            except Exception as e:
                logger.error("Error during cleanup: %s", e, exc_info=True)

            # Fixed sleep between cleanup passes, bounded below regardless of
            # a very short key lifetime.
            sleep_duration = max(MIN_CLEANUP_INTERVAL_SECONDS, self._key_max_lifetime // 2)
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

    print("Initializing VaultAsymmetricEncryption (SealedBox)...")

    with VaultAsymmetricEncryption(lifetime=30) as encryption:
        print(f"Encryption public key: {encryption.enc_public_key[:32]}...")
        print(f"Stats: {encryption.get_stats()}")

        # Simulate peer key addition
        test_addr = ("192.168.1.100", 5000)
        peer_enc_pub, _ = vault_udp_socket_helper.generate_keys_asym()
        encryption.update_peer_keys(test_addr, peer_enc_pub)
        print(f"\nAdded peer key for {test_addr}")
        print(f"Stats: {encryption.get_stats()}")

        time.sleep(2)
        print("\nVaultAsymmetricEncryption demonstration complete")


if __name__ == '__main__':
    main()
