# Copyright [2025] [ecki]
# SPDX-License-Identifier: Apache-2.0

"""
Vault UDP Socket Module

Provides bidirectional UDP communication with authenticated encryption,
automatic key exchange, message compression, and rate limiting.
"""

import json
import logging
import math
import os
import random
import socket
import threading
import time
from collections import defaultdict
from typing import Optional, Tuple, List, Any, Dict

import msgpack
import PySignal
import pyzstd

import vault_ip
import vault_udp_encryption
import vault_udp_socket_helper

logger = logging.getLogger(__name__)

# Constants
DEFAULT_RECV_PORT = 11000
MIN_PORT = 1500
MAX_PORT = 65000

# MTU calculation with proper overhead
IP_HEADER_SIZE = 20  # IPv4 (IPv6 would be 40)
UDP_HEADER_SIZE = 8
NACL_BOX_OVERHEAD = 40  # Box overhead (24 nonce + 16 authenticator)
MSGPACK_OVERHEAD = 10
REPLAY_PROTECTION_OVERHEAD = 24  # 16 bytes nonce + 8 bytes timestamp

DEFAULT_KEY_LIFETIME = 60
KEY_MGMT_MIN_INTERVAL = 5

# Rate limiting
DEFAULT_RATE_LIMIT = 100  # messages per second per peer


class UDPSocketError(Exception):
    """Base exception for UDP socket operations."""
    pass


class MessageTooLargeError(UDPSocketError):
    """Raised when message exceeds MTU."""
    pass


class InvalidPortError(UDPSocketError):
    """Raised when port number is invalid."""
    pass


class RateLimitExceededError(UDPSocketError):
    """Raised when rate limit is exceeded."""
    pass


class RateLimiter:
    """Simple token bucket rate limiter."""

    def __init__(self, max_per_second: int = DEFAULT_RATE_LIMIT):
        """
        Initialize rate limiter.

        Args:
            max_per_second: Maximum messages per second per peer
        """
        self._max_per_second = max_per_second
        self._requests: Dict[Tuple[str, int], List[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def allow_request(self, addr: Tuple[str, int]) -> bool:
        """
        Check if request from addr should be allowed.

        Args:
            addr: Peer address

        Returns:
            True if allowed, False if rate limited
        """
        now = time.time()

        with self._lock:
            # Remove entries older than 1 second
            self._requests[addr] = [
                t for t in self._requests[addr]
                if now - t < 1.0
            ]

            # Check limit
            if len(self._requests[addr]) >= self._max_per_second:
                return False

            # Add new request
            self._requests[addr].append(now)
            return True

    def cleanup_old_entries(self) -> None:
        """Remove old entries to prevent memory growth."""
        now = time.time()

        with self._lock:
            # Remove peers with no recent activity
            inactive_peers = [
                addr for addr, times in self._requests.items()
                if not times or (now - max(times) > 60.0)
            ]

            for addr in inactive_peers:
                del self._requests[addr]


class UDPSocketClass:
    """
    Bidirectional UDP socket with authenticated encryption and rate limiting.

    Features:
    - Authenticated asymmetric encryption with replay protection
    - Automatic key exchange with signature verification
    - Message compression (zstd)
    - Rate limiting per peer
    - Thread-safe operations
    - Multiple peers support (multiple peers per IP allowed)
    - PySignal integration for events

    Signals:
        udp_recv_data: Emitted when user data is received (data: str, addr: tuple)
        udp_send_data: Connected to send_data method for external sending

    Thread-safe: All operations use internal locking.
    """

    # Class-level signals
    udp_recv_data = PySignal.ClassSignal()
    udp_send_data = PySignal.ClassSignal()

    def __init__(
        self,
        recv_port: int = DEFAULT_RECV_PORT,
        rate_limit: int = DEFAULT_RATE_LIMIT
    ):
        """
        Initialize UDP socket.

        Args:
            recv_port: Port to listen on for incoming messages
            rate_limit: Maximum messages per second per peer
        """
        logger.info("Initializing UDPSocketClass on port %d", recv_port)

        # Port configuration
        self.recv_port = self._validate_port(recv_port)

        # Network configuration with proper MTU calculation
        base_mtu = vault_ip.get_min_mtu()
        total_overhead = (IP_HEADER_SIZE + UDP_HEADER_SIZE + NACL_BOX_OVERHEAD +
                         MSGPACK_OVERHEAD + REPLAY_PROTECTION_OVERHEAD)
        self.mtu = base_mtu - total_overhead
        logger.info("Base MTU: %d, Effective MTU: %d bytes", base_mtu, self.mtu)

        # Thread synchronization
        self._lock = threading.RLock()
        self._stop_flag = False

        # Peer management
        self._peer_addresses: List[Tuple[str, int]] = []

        # Rate limiting
        self._rate_limiter = RateLimiter(rate_limit)

        # Sockets
        self._read_socket: Optional[socket.socket] = None
        self._write_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Encryption
        self.lifetime = DEFAULT_KEY_LIFETIME
        self._encryption = vault_udp_encryption.VaultAsymmetricEncryption(
            lifetime=self.lifetime
        )

        # Threads
        self._read_thread: Optional[threading.Thread] = None
        self._key_mgmt_thread: Optional[threading.Thread] = None

        # Connect send signal
        self.udp_send_data.connect(self.send_data)

        # Start threads
        self._start_threads()

        logger.info("UDPSocketClass initialized successfully")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.stop()
        return False

    def add_peer(self, addr: Tuple[str, int]) -> None:
        """
        Add a peer address to send messages to.

        Args:
            addr: Tuple of (ip_address, port)
        """
        if not addr or len(addr) != 2:
            logger.warning("Invalid address format: %s", addr)
            return

        ip, port = addr
        validated_port = self._validate_port(port)
        validated_addr = (ip, validated_port)

        with self._lock:
            if validated_addr in self._peer_addresses:
                logger.debug("Peer %s already exists", validated_addr)
                return

            self._peer_addresses.append(validated_addr)
            logger.info("Added peer: %s", validated_addr)

        # Initiate key exchange
        self._send_public_keys(validated_addr)

    def remove_peer(self, addr: Tuple[str, int]) -> None:
        """
        Remove a peer address.

        Args:
            addr: Tuple of (ip_address, port)
        """
        with self._lock:
            if addr in self._peer_addresses:
                self._peer_addresses.remove(addr)
                self._encryption.remove_peer_keys(addr)
                logger.info("Removed peer: %s", addr)
            else:
                logger.warning("Peer %s not found", addr)

    def get_peers(self) -> List[Tuple[str, int]]:
        """
        Get list of all peer addresses.

        Returns:
            List of (ip, port) tuples
        """
        with self._lock:
            return self._peer_addresses.copy()

    def has_peer(self, addr: Tuple[str, int]) -> bool:
        """
        Check if a peer exists.

        Args:
            addr: Tuple of (ip_address, port)

        Returns:
            True if peer exists, False otherwise
        """
        with self._lock:
            return addr in self._peer_addresses

    def get_peers_by_ip(self, ip: str) -> List[Tuple[str, int]]:
        """
        Get all peers with a specific IP address.

        Args:
            ip: IP address to search for

        Returns:
            List of (ip, port) tuples matching the IP
        """
        with self._lock:
            return [addr for addr in self._peer_addresses if addr[0] == ip]

    def update_recv_port(self, recv_port: int) -> None:
        """
        Update the listening port atomically.

        Args:
            recv_port: New port to listen on
        """
        validated_port = self._validate_port(recv_port)

        if validated_port == self.recv_port:
            logger.debug("Port unchanged: %d", validated_port)
            return

        logger.info("Changing receive port: %d -> %d", self.recv_port, validated_port)

        with self._lock:
            # Create new socket
            new_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            new_socket.settimeout(1.0)

            try:
                new_socket.bind(('', validated_port))
            except OSError as e:
                logger.error("Failed to bind to new port %d: %s", validated_port, e)
                new_socket.close()
                raise

            # Atomic swap
            old_socket = self._read_socket
            self._read_socket = new_socket
            self.recv_port = validated_port

            # Close old socket
            if old_socket:
                try:
                    old_socket.close()
                except Exception as e:
                    logger.debug("Error closing old socket: %s", e)

        logger.info("Receive port updated to %d", validated_port)

    def send_data(self, data: Any, addr: Optional[Tuple[str, int]] = None) -> None:
        """
        Send data to peer(s).

        Args:
            data: Data to send (str or bytes)
            addr: Target address, or None to send to all peers

        Raises:
            MessageTooLargeError: If message exceeds MTU after compression
            TypeError: If data is not str or bytes
        """
        # Convert to bytes
        if isinstance(data, str):
            data_bytes = data.encode("utf-8")
        elif isinstance(data, bytes):
            data_bytes = data
        else:
            raise TypeError(f"Data must be str or bytes, not {type(data).__name__}")

        # Compress
        try:
            compressed_data = pyzstd.compress(data_bytes, 16)
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("Compressed %d bytes to %d bytes",
                            len(data_bytes), len(compressed_data))
        except Exception as e:
            logger.error("Compression failed: %s", e)
            raise UDPSocketError(f"Compression failed: {e}") from e

        # Send
        self._send_internal(compressed_data, addr)

    def stop(self, timeout: float = 5.0) -> None:
        """
        Stop all threads and close sockets.

        Args:
            timeout: Maximum seconds to wait for threads
        """
        logger.info("Stopping UDPSocketClass")

        self._stop_flag = True

        # Stop encryption manager
        self._encryption.stop(timeout=timeout)

        # Close sockets
        if self._read_socket:
            try:
                self._read_socket.close()
            except Exception as e:
                logger.debug("Error closing read socket: %s", e)

        try:
            self._write_socket.close()
        except Exception as e:
            logger.debug("Error closing write socket: %s", e)

        # Wait for threads
        threads = [
            (self._read_thread, "Read"),
            (self._key_mgmt_thread, "KeyManagement")
        ]

        for thread, name in threads:
            if thread and thread.is_alive():
                thread.join(timeout=timeout)
                if thread.is_alive():
                    logger.warning("%s thread did not terminate within timeout", name)
                else:
                    logger.debug("%s thread terminated", name)

        logger.info("UDPSocketClass stopped")

    def get_stats(self) -> dict:
        """
        Get statistics about the socket.

        Returns:
            Dictionary with socket statistics
        """
        with self._lock:
            peers_by_ip = {}
            for ip, port in self._peer_addresses:
                if ip not in peers_by_ip:
                    peers_by_ip[ip] = []
                peers_by_ip[ip].append(port)

            return {
                'recv_port': self.recv_port,
                'mtu': self.mtu,
                'peer_count': len(self._peer_addresses),
                'unique_ips': len(peers_by_ip),
                'peers': self._peer_addresses.copy(),
                'peers_by_ip': peers_by_ip,
                'encryption_stats': self._encryption.get_stats(),
                'enc_public_key': self._encryption.enc_public_key[:32] + "..."
                                 if self._encryption.enc_public_key else None,
                'sign_public_key': self._encryption.sign_public_key[:32] + "..."
                                  if self._encryption.sign_public_key else None
            }

    # Private methods

    def _start_threads(self) -> None:
        """Start all background threads."""
        self._start_read_thread()
        self._start_key_mgmt_thread()

    def _start_read_thread(self) -> None:
        """Start the socket reading thread."""
        self._read_thread = threading.Thread(
            target=self._read_loop,
            daemon=True,
            name="UDPSocket-Read"
        )
        self._read_thread.start()
        logger.debug("Read thread started")

    def _start_key_mgmt_thread(self) -> None:
        """Start the key management thread."""
        self._key_mgmt_thread = threading.Thread(
            target=self._key_management_loop,
            daemon=True,
            name="UDPSocket-KeyMgmt"
        )
        self._key_mgmt_thread.start()
        logger.debug("Key management thread started")

    def _read_loop(self) -> None:
        """Main loop for reading from socket."""
        try:
            self._read_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._read_socket.settimeout(1.0)
            self._read_socket.bind(('', self.recv_port))
            logger.info("Socket bound to port %d", self.recv_port)
        except Exception as e:
            logger.error("Failed to bind socket to port %d: %s", self.recv_port, e)
            return

        while not self._stop_flag:
            try:
                self._read_and_process_packet()
            except socket.timeout:
                continue
            except OSError as e:
                if self._stop_flag:
                    break
                logger.debug("Socket error (likely during shutdown): %s", e)
                break
            except Exception as e:
                if self._stop_flag:
                    break
                logger.error("Error in read loop: %s", e, exc_info=True)
                time.sleep(0.1)

        logger.info("Read thread stopped")

    def _read_and_process_packet(self) -> None:
        """Read one packet and process it."""
        packet, addr = self._read_socket.recvfrom(48000)

        # Rate limiting
        if not self._rate_limiter.allow_request(addr):
            logger.warning("Rate limit exceeded for %s, dropping packet", addr)
            return

        # Try to decrypt (with replay protection)
        try:
            decrypted_data = self._encryption.decrypt_if_possible(packet, addr)
        except Exception as e:
            logger.warning("Decryption error from %s: %s", addr, e)
            return

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Received %d bytes from %s", len(decrypted_data), addr)

        # Unpack msgpack
        try:
            unpacked_data = msgpack.unpackb(decrypted_data)
            if not isinstance(unpacked_data, (list, tuple)) or len(unpacked_data) < 1:
                logger.warning("Invalid msgpack structure from %s", addr)
                return

            payload_compressed = unpacked_data[0]
        except Exception as e:
            logger.debug("Failed to unpack msgpack from %s: %s", addr, e)
            return

        # Decompress
        try:
            payload_bytes = pyzstd.decompress(payload_compressed)
        except Exception as e:
            logger.debug("Failed to decompress data from %s: %s", addr, e)
            return

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Decompressed to %d bytes", len(payload_bytes))

        # Try to parse as JSON for key exchange
        try:
            msg_dict = json.loads(payload_bytes.decode("utf-8"))

            # Handle key exchange
            if "enc_key" in msg_dict and "sign_key" in msg_dict:
                self._handle_key_exchange(msg_dict, addr)
                return

            # Handle user data in JSON format
            if "data" in msg_dict:
                user_data = msg_dict["data"]
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("Emitting user data from %s", addr)
                self.udp_recv_data.emit(user_data, addr)
                return

        except (json.JSONDecodeError, UnicodeDecodeError, AttributeError):
            # Not JSON, treat as plain string
            try:
                data_str = payload_bytes.decode('utf-8')
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("Emitting plain string from %s", addr)
                self.udp_recv_data.emit(data_str, addr)
            except UnicodeDecodeError:
                logger.warning("Received non-UTF-8 data from %s", addr)

    def _handle_key_exchange(self, msg_dict: dict, addr: Tuple[str, int]) -> None:
        """
        Handle incoming public key exchange with signature verification.

        Args:
            msg_dict: Message dictionary containing 'enc_key' and 'sign_key'
            addr: Sender address
        """
        enc_key = msg_dict.get("enc_key")
        sign_key = msg_dict.get("sign_key")

        if not enc_key or not sign_key:
            logger.warning("Key exchange message without keys from %s", addr)
            return

        # Update address if port is specified
        if "port" in msg_dict:
            port = msg_dict.get("port")
            if isinstance(port, int):
                addr = (addr[0], port)

        # Verify signature if present
        signature = msg_dict.get("signature")
        if signature:
            try:
                # The signature should be over enc_key + sign_key
                signed_data = (enc_key + sign_key).encode('utf-8')
                sig_bytes = vault_udp_socket_helper.b64_str_to_bytes(signature)

                # Verify using the sign_key from the message
                vault_udp_socket_helper.verify_signature(sign_key, sig_bytes)
                logger.debug("Signature verified for %s", addr)
            except vault_udp_socket_helper.SignatureError:
                logger.warning("Invalid signature from %s, rejecting keys", addr)
                return

        # Check if this is a new key
        key_exists = self._encryption.peer_keys_exist(addr)

        if not key_exists:
            logger.info("Received new public keys from %s", addr)
            self._encryption.update_peer_keys(addr, enc_key, sign_key)
            # Send our keys in response
            self._send_public_keys(addr)
        else:
            # Update existing keys (refresh timestamp)
            self._encryption.update_peer_keys(addr, enc_key, sign_key)
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("Updated public keys for %s", addr)

    def _key_management_loop(self) -> None:
        """Background loop for periodic key exchange and cleanup."""
        logger.debug("Key management thread started")

        while not self._stop_flag:
            try:
                with self._lock:
                    peers = self._peer_addresses.copy()

                for addr in peers:
                    if self._stop_flag:
                        break
                    self._send_public_keys(addr)
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug("Sent periodic key update to %s", addr)

                # Cleanup old rate limiter entries
                self._rate_limiter.cleanup_old_entries()

            except Exception as e:
                logger.error("Error in key management loop: %s", e, exc_info=True)

            # Random sleep to avoid synchronization
            sleep_duration = random.randint(
                KEY_MGMT_MIN_INTERVAL,
                max(KEY_MGMT_MIN_INTERVAL, self.lifetime // 3)
            )
            time.sleep(sleep_duration)

        logger.debug("Key management thread stopped")

    def _send_public_keys(self, addr: Tuple[str, int]) -> None:
        """
        Send our public keys to a peer with signature.

        Args:
            addr: Target address
        """
        # Create signature over our keys
        keys_data = (self._encryption.enc_public_key +
                    self._encryption.sign_public_key).encode('utf-8')

        try:
            signed_data = vault_udp_socket_helper.sign_message(
                self._encryption._sign_private_key,
                keys_data
            )
            signature = vault_udp_socket_helper.bytes_to_b64_str(signed_data)
        except Exception as e:
            logger.error("Failed to sign keys: %s", e)
            signature = None

        key_data = {
            "enc_key": self._encryption.enc_public_key,
            "sign_key": self._encryption.sign_public_key,
            "signature": signature,
            "port": self.recv_port,
            "ign": ""
        }

        try:
            json_data = json.dumps(key_data)
            self.send_data(json_data, addr)
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("Sent public keys to %s", addr)
        except Exception as e:
            logger.error("Failed to send public keys to %s: %s", addr, e)

    def _send_internal(
        self,
        data: bytes,
        addr: Optional[Tuple[str, int]] = None
    ) -> None:
        """
        Internal send method with encryption and padding.

        Args:
            data: Compressed data to send
            addr: Target address, or None for all peers

        Raises:
            MessageTooLargeError: If message exceeds MTU
        """
        # Pack data with msgpack (reserve space for padding)
        packed_data = msgpack.packb([data, b""])

        if len(packed_data) > self.mtu:
            raise MessageTooLargeError(
                f"Message too large: {len(packed_data)} bytes (MTU: {self.mtu})"
            )

        # Add padding to reach MTU
        padding_size = self.mtu - len(packed_data)
        padding = self._generate_padding(padding_size)
        packed_data = msgpack.packb([data, padding])

        # Determine target addresses
        with self._lock:
            if addr:
                target_addrs = [addr]
            else:
                target_addrs = self._peer_addresses.copy()

        if not target_addrs:
            logger.warning("No peers to send data to")
            return

        # Send to each peer
        for target_addr in target_addrs:
            try:
                # Try to encrypt (with authentication and replay protection)
                encrypted = self._encryption.encrypt_if_possible(
                    packed_data,
                    target_addr
                )

                # Send
                self._write_socket.sendto(encrypted, target_addr)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("Sent %d bytes to %s", len(encrypted), target_addr)

            except Exception as e:
                logger.error("Failed to send to %s: %s", target_addr, e)

    @staticmethod
    def _validate_port(port: Any) -> int:
        """
        Validate and clamp port number.

        Args:
            port: Port number (int or str)

        Returns:
            Valid port number

        Raises:
            InvalidPortError: If port cannot be converted
        """
        try:
            port_int = int(port)
        except (ValueError, TypeError) as e:
            raise InvalidPortError(f"Invalid port: {port}") from e

        # Clamp to valid range
        if port_int < MIN_PORT:
            logger.warning("Port %d below minimum, using %d", port_int, MIN_PORT)
            port_int = MIN_PORT
        elif port_int > MAX_PORT:
            logger.warning("Port %d above maximum, using %d", port_int, MAX_PORT)
            port_int = MAX_PORT

        return port_int

    @staticmethod
    def _generate_padding(length: int) -> bytes:
        """
        Generate random padding bytes.

        Args:
            length: Number of bytes to generate

        Returns:
            Random bytes
        """
        if length <= 0:
            return b""
        return os.urandom(length)


def print_received_data(data: str, addr: Tuple[str, int]) -> None:
    """Example callback for received data."""
    print(f"Received: '{data}' from {addr}")


def main():
    """Example usage and testing."""
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    print("Creating UDP sockets with authenticated encryption...")

    # Create first socket with multiple peers on same IP
    with UDPSocketClass(11000) as socket1:
        socket1.add_peer(("127.0.0.1", 8000))
        socket1.add_peer(("127.0.0.1", 8001))
        socket1.add_peer(("127.0.0.1", 8002))
        socket1.udp_recv_data.connect(print_received_data)
        print(f"Socket 1 stats: {socket1.get_stats()}")

        time.sleep(1)

        # Create three sockets listening on different ports
        with UDPSocketClass(8000) as socket2, \
             UDPSocketClass(8001) as socket3, \
             UDPSocketClass(8002) as socket4:

            socket2.add_peer(("127.0.0.1", 11000))
            socket3.add_peer(("127.0.0.1", 11000))
            socket4.add_peer(("127.0.0.1", 11000))

            socket2.udp_recv_data.connect(print_received_data)
            socket3.udp_recv_data.connect(print_received_data)
            socket4.udp_recv_data.connect(print_received_data)

            print(f"Socket 2 stats: {socket2.get_stats()}")

            # Wait for key exchange
            time.sleep(3)

            # Send test messages
            print("\n--- Broadcasting from socket1 to all peers ---")
            socket1.send_data("Broadcast to all!")
            time.sleep(1)

            print("\n--- Individual responses ---")
            socket2.send_data("Response from port 8000")
            socket3.send_data("Response from port 8001")
            socket4.send_data("Response from port 8002")
            time.sleep(1)

            print("\nTest complete!")


if __name__ == '__main__':
    main()
