"""
Vault UDP Socket Module

Provides bidirectional UDP communication with opportunistic encryption,
automatic key exchange, and message compression.
"""

import json
import logging
import math
import os
import random
import socket
import threading
import time
from typing import Optional, Tuple, List, Callable, Any

import msgpack
import PySignal
import pyzstd

import vault_ip
import vault_udp_encryption

logger = logging.getLogger(__name__)

# Constants
DEFAULT_RECV_PORT = 11000
MIN_PORT = 1500
MAX_PORT = 65000
MTU_OVERHEAD = 10
DEFAULT_KEY_LIFETIME = 60
KEY_MGMT_MIN_INTERVAL = 5


class UDPSocketError(Exception):
    """Base exception for UDP socket operations."""
    pass


class MessageTooLargeError(UDPSocketError):
    """Raised when message exceeds MTU."""
    pass


class InvalidPortError(UDPSocketError):
    """Raised when port number is invalid."""
    pass


class UDPSocketClass:
    """
    Bidirectional UDP socket with opportunistic encryption.

    Features:
    - Automatic asymmetric key exchange
    - Message compression (zstd)
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

    def __init__(self, recv_port: int = DEFAULT_RECV_PORT):
        """
        Initialize UDP socket.

        Args:
            recv_port: Port to listen on for incoming messages
        """
        logger.info("Initializing UDPSocketClass on port %d", recv_port)

        # Port configuration
        self.recv_port = self._validate_port(recv_port)

        # Network configuration
        self.mtu = vault_ip.get_min_mtu() - MTU_OVERHEAD
        logger.info("Using MTU: %d bytes", self.mtu)

        # Thread synchronization
        self._lock = threading.RLock()
        self._stop_flag = False

        # Peer management - now supports multiple peers per IP
        self._peer_addresses: List[Tuple[str, int]] = []

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

        Note:
            Multiple peers with the same IP but different ports are now supported.
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
        self._send_public_key(validated_addr)

    def remove_peer(self, addr: Tuple[str, int]) -> None:
        """
        Remove a peer address.

        Args:
            addr: Tuple of (ip_address, port)
        """
        with self._lock:
            if addr in self._peer_addresses:
                self._peer_addresses.remove(addr)
                self._encryption.remove_peer_key(addr)
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
        Update the listening port (restarts read thread).

        Args:
            recv_port: New port to listen on
        """
        validated_port = self._validate_port(recv_port)

        if validated_port == self.recv_port:
            logger.debug("Port unchanged: %d", validated_port)
            return

        logger.info("Changing receive port: %d -> %d", self.recv_port, validated_port)

        # Stop read thread
        self._stop_flag = True
        if self._read_socket:
            try:
                self._read_socket.close()
            except Exception as e:
                logger.debug("Error closing socket: %s", e)

        # Wait for thread to finish
        if self._read_thread and self._read_thread.is_alive():
            self._read_thread.join(timeout=2.0)
            if self._read_thread.is_alive():
                logger.warning("Read thread did not terminate within timeout")

        # Update port and restart
        self.recv_port = validated_port
        self._stop_flag = False
        self._start_read_thread()

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
            # Group peers by IP for stats
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
                'public_key': self._encryption.public_key[:32] + "..."
                             if self._encryption.public_key else None
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
            self._read_socket.settimeout(1.0)  # 1 second timeout
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
        # Receive packet
        packet, addr = self._read_socket.recvfrom(48000)

        # Try to decrypt
        try:
            decrypted_data = self._encryption.decrypt_if_possible(packet, addr)
        except Exception as e:
            logger.warning("Decryption error from %s: %s", addr, e)
            return

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

        logger.debug("Decompressed to %d bytes", len(payload_bytes))

        # Try to parse as JSON for key exchange
        try:
            msg_dict = json.loads(payload_bytes.decode("utf-8"))

            # Handle key exchange
            if "akey" in msg_dict:
                self._handle_key_exchange(msg_dict, addr)
                return

            # Handle user data in JSON format
            if "data" in msg_dict:
                user_data = msg_dict["data"]
                logger.debug("Emitting user data from %s: %s", addr, user_data)
                self.udp_recv_data.emit(user_data, addr)
                return

        except (json.JSONDecodeError, UnicodeDecodeError, AttributeError):
            # Not JSON, treat as plain string
            try:
                data_str = payload_bytes.decode('utf-8')
                logger.debug("Emitting plain string from %s", addr)
                self.udp_recv_data.emit(data_str, addr)
            except UnicodeDecodeError:
                logger.warning("Received non-UTF-8 data from %s", addr)

    def _handle_key_exchange(self, msg_dict: dict, addr: Tuple[str, int]) -> None:
        """
        Handle incoming public key exchange.

        Args:
            msg_dict: Message dictionary containing 'akey'
            addr: Sender address
        """
        public_key = msg_dict.get("akey")
        if not public_key:
            logger.warning("Key exchange message without key from %s", addr)
            return

        # Update address if port is specified
        if "port" in msg_dict:
            port = msg_dict.get("port")
            if isinstance(port, int):
                addr = (addr[0], port)

        # Check if this is a new key
        key_exists = self._encryption.peer_key_exists(addr)

        if not key_exists:
            logger.info("Received new public key from %s", addr)
            self._encryption.update_peer_key(addr, public_key)
            # Send our key in response
            self._send_public_key(addr)
        else:
            # Update existing key (refresh timestamp)
            self._encryption.update_peer_key(addr, public_key)
            logger.debug("Updated public key for %s", addr)

    def _key_management_loop(self) -> None:
        """Background loop for periodic key exchange."""
        logger.debug("Key management thread started")

        while not self._stop_flag:
            try:
                with self._lock:
                    peers = self._peer_addresses.copy()

                for addr in peers:
                    if self._stop_flag:
                        break
                    self._send_public_key(addr)
                    logger.debug("Sent periodic key update to %s", addr)

            except Exception as e:
                logger.error("Error in key management loop: %s", e, exc_info=True)

            # Random sleep to avoid synchronization
            sleep_duration = random.randint(
                KEY_MGMT_MIN_INTERVAL,
                max(KEY_MGMT_MIN_INTERVAL, self.lifetime // 3)
            )
            time.sleep(sleep_duration)

        logger.debug("Key management thread stopped")

    def _send_public_key(self, addr: Tuple[str, int]) -> None:
        """
        Send our public key to a peer.

        Args:
            addr: Target address
        """
        key_data = {
            "akey": self._encryption.public_key,
            "port": self.recv_port,
            "ign": ""  # Ignored field for compatibility
        }

        try:
            json_data = json.dumps(key_data)
            self.send_data(json_data, addr)
            logger.debug("Sent public key to %s", addr)
        except Exception as e:
            logger.error("Failed to send public key to %s: %s", addr, e)

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
                # Try to encrypt
                encrypted = self._encryption.encrypt_if_possible(
                    packed_data,
                    target_addr
                )

                # Send
                self._write_socket.sendto(encrypted, target_addr)
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

    print("Creating UDP sockets with multiple peers per IP...")

    # Create first socket with multiple peers on same IP
    with UDPSocketClass(11000) as socket1:
        socket1.add_peer(("127.0.0.1", 8000))
        socket1.add_peer(("127.0.0.1", 8001))  # Second peer on same IP
        socket1.add_peer(("127.0.0.1", 8002))  # Third peer on same IP
        socket1.udp_recv_data.connect(print_received_data)
        print(f"Socket 1 stats: {socket1.get_stats()}")

        time.sleep(1)

        # Create three sockets listening on different ports
        with UDPSocketClass(8000) as socket2, \
             UDPSocketClass(8001) as socket3, \
             UDPSocketClass(8002) as socket4:

            # Each connects back to socket1
            socket2.add_peer(("127.0.0.1", 11000))
            socket3.add_peer(("127.0.0.1", 11000))
            socket4.add_peer(("127.0.0.1", 11000))

            socket2.udp_recv_data.connect(print_received_data)
            socket3.udp_recv_data.connect(print_received_data)
            socket4.udp_recv_data.connect(print_received_data)

            print(f"Socket 2 stats: {socket2.get_stats()}")
            print(f"Socket 3 stats: {socket3.get_stats()}")
            print(f"Socket 4 stats: {socket4.get_stats()}")

            # Wait for key exchange
            time.sleep(2)

            # Send test messages
            print("\n--- Broadcasting from socket1 to all peers ---")
            socket1.send_data("Broadcast to all!")  # Goes to all 3 peers
            time.sleep(1)

            print("\n--- Individual responses ---")
            socket2.send_data("Response from port 8000")
            socket3.send_data("Response from port 8001")
            socket4.send_data("Response from port 8002")
            time.sleep(1)

            # Test get_peers_by_ip
            peers_on_localhost = socket1.get_peers_by_ip("127.0.0.1")
            print(f"\nPeers on 127.0.0.1: {peers_on_localhost}")

            print("\nTest complete!")


if __name__ == '__main__':
    main()
