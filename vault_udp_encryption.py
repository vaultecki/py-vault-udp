"""
Vault UDP Asymmetric Encryption Module

Provides thread-safe asymmetric encryption for UDP communication with 
automatic key lifecycle management.
"""

import binascii
import logging
import math
import random
import threading
import time
from typing import Tuple, Optional, Dict

import nacl.exceptions

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
    Manages asymmetric encryption for UDP communications with automatic key expiration.

    This class handles:
    - Generation and storage of key pairs
    - Thread-safe management of peer public keys
    - Automatic cleanup of expired keys
    - Encryption/decryption operations

    Thread-safe: All public methods use internal locking.
    """

    def __init__(
            self,
            lifetime: int = DEFAULT_KEY_LIFETIME_SECONDS,
            private_key: Optional[str] = None
    ):
        """
        Initialize the encryption manager.

        Args:
            lifetime: Maximum lifetime for peer keys in seconds
            private_key: Optional existing private key to use
        """
        logger.info("Initializing VaultAsymmetricEncryption")

        # Thread synchronization
        self._lock = threading.RLock()

        # Key storage
        self._peer_keys: Dict[Tuple[str, int], str] = {}
        self._peer_keys_timestamp: Dict[Tuple[str, int], int] = {}
        self._key_max_lifetime = lifetime

        # Own keys
        self._private_key: Optional[str] = None
        self.public_key: str = ""

        # Initialize keys
        if private_key:
            self.set_private_key(private_key)
        else:
            self.generate_key()

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

    def generate_key(self) -> str:
        """
        Generate a new key pair.

        Returns:
            The generated public key
        """
        logger.info("Generating new key pair")
        public_key, private_key = vault_udp_socket_helper.generate_keys_asym()
        self.set_private_key(private_key)
        logger.info("New key pair generated")
        return self.public_key

    def set_private_key(self, private_key: str) -> str:
        """
        Set the private key and derive the public key.

        Args:
            private_key: The private key to use

        Returns:
            The corresponding public key
        """
        with self._lock:
            logger.debug("Setting new private key")
            self._private_key = private_key
            self.public_key = vault_udp_socket_helper.generate_public_key(
                self._private_key
            )
            logger.info("Private key updated, public key derived")
            return self.public_key

    def update_peer_key(self, addr: Tuple[str, int], key: str) -> None:
        """
        Store or update a peer's public key.

        Args:
            addr: Tuple of (ip_address, port)
            key: The peer's public key
        """
        if not key:
            logger.warning("Attempted to update with empty key for %s", addr)
            return

        with self._lock:
            addr_tuple = tuple(addr)
            self._peer_keys[addr_tuple] = key
            self._peer_keys_timestamp[addr_tuple] = self._current_timestamp()
            logger.debug("Updated peer key for %s", addr)

    def remove_peer_key(self, addr: Tuple[str, int]) -> None:
        """
        Remove a peer's public key.

        Args:
            addr: Tuple of (ip_address, port)
        """
        with self._lock:
            addr_tuple = tuple(addr)
            if addr_tuple in self._peer_keys:
                self._peer_keys.pop(addr_tuple)
                self._peer_keys_timestamp.pop(addr_tuple)
                logger.info("Removed peer key for %s", addr)

    def peer_key_exists(self, addr: Tuple[str, int]) -> bool:
        """
        Check if a peer key exists.

        Args:
            addr: Tuple of (ip_address, port)

        Returns:
            True if key exists, False otherwise
        """
        with self._lock:
            return tuple(addr) in self._peer_keys

    def find_peer_by_ip(self, ip: str) -> Optional[Tuple[str, int]]:
        """
        Find a peer address by IP address.

        Args:
            ip: The IP address to search for

        Returns:
            The full address tuple if found, None otherwise
        """
        with self._lock:
            for addr in self._peer_keys.keys():
                if addr[0] == ip:
                    return addr
            return None

    def decrypt(self, data: bytes, addr: Tuple[str, int]) -> bytes:
        """
        Decrypt data from a peer.

        Args:
            data: Encrypted data as bytes
            addr: Tuple of (ip_address, port)

        Returns:
            Decrypted data as bytes

        Raises:
            DecryptionError: If decryption fails
        """
        logger.debug("Attempting decryption from %s", addr)

        if not self._private_key:
            raise DecryptionError("No private key configured")

        try:
            decrypted_bytes = vault_udp_socket_helper.decrypt_asym(
                self._private_key,
                data
            )
            logger.debug("Successfully decrypted data from %s", addr)
            return decrypted_bytes

        except nacl.exceptions.CryptoError as e:
            logger.warning("Crypto error during decryption from %s: %s", addr, type(e).__name__)
            raise DecryptionError(f"Decryption failed: {type(e).__name__}") from e

        except (TypeError, binascii.Error) as e:
            logger.warning("Data format error during decryption from %s: %s", addr, type(e).__name__)
            raise DecryptionError(f"Invalid data format: {type(e).__name__}") from e

        except Exception as e:
            logger.error("Unexpected error during decryption from %s: %s", addr, type(e).__name__)
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

        with self._lock:
            addr_tuple = tuple(addr)
            peer_key = self._peer_keys.get(addr_tuple)

        if not peer_key:
            raise KeyNotFoundError(f"No encryption key available for {addr}")

        try:
            encrypted_data = vault_udp_socket_helper.encrypt_asym(peer_key, data)
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
        except DecryptionError:
            logger.debug("Decryption failed for %s, data may be unencrypted", addr)
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
            for addr, timestamp in self._peer_keys_timestamp.items():
                if current_time - timestamp > self._key_max_lifetime:
                    expired_addrs.append(addr)

            for addr in expired_addrs:
                self._peer_keys.pop(addr, None)
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

    def get_stats(self) -> Dict[str, int]:
        """
        Get statistics about managed keys.

        Returns:
            Dictionary with key counts and configuration
        """
        with self._lock:
            return {
                'active_peer_keys': len(self._peer_keys),
                'key_lifetime_seconds': self._key_max_lifetime,
                'has_private_key': bool(self._private_key)
            }

    def _cleanup_loop(self) -> None:
        """Background thread loop for periodic key cleanup."""
        logger.debug("Cleanup thread started")

        while self._run_cleanup:
            try:
                self.cleanup_expired_keys()
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

    print("Initializing VaultAsymmetricEncryption...")

    with VaultAsymmetricEncryption(lifetime=30) as encryption:
        print(f"Public key: {encryption.public_key[:32]}...")
        print(f"Stats: {encryption.get_stats()}")

        # Simulate peer key addition
        test_addr = ("192.168.1.100", 5000)
        encryption.update_peer_key(test_addr, "test_peer_public_key")
        print(f"Added peer key for {test_addr}")
        print(f"Stats: {encryption.get_stats()}")

        time.sleep(2)
        print("VaultAsymmetricEncryption demonstration complete")


if __name__ == '__main__':
    main()