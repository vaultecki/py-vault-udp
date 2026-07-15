# py-vault-udp

Python UDP communication library with opportunistic encryption, authenticated encryption, automatic key exchange, and replay attack prevention.

## Features

### Security
- 🔒 **Authenticated Encryption**: Uses NaCl Box (X25519 + XSalsa20-Poly1305) for authenticated encryption
- ✍️ **Signature Support**: Ed25519 signing for key exchange verification
- 🛡️ **Replay Attack Prevention**: Automatic nonce tracking and message timestamp verification
- 🔑 **Automatic Key Exchange**: Seamless public key distribution with signature verification
- ⏰ **Key Lifecycle Management**: Automatic expiration and cleanup of old keys
- ⚠️ **Warning**: opportunistic encryption, fallback is unencrypted UDP

### Performance
- 📦 **Message Compression**: Zstd compression for reduced bandwidth
- 🚀 **Thread-Safe**: RLock-based synchronization for concurrent operations
- 📊 **Rate Limiting**: Configurable per-peer rate limiting to prevent DoS
- 🎯 **MTU-Aware**: Automatic MTU calculation with proper overhead accounting

### Reliability
- 🔄 **Multiple Peers**: Support for multiple peers on same IP address
- 🌐 **Network Discovery**: Automatic interface and MTU detection
- 📝 **Comprehensive Logging**: Detailed logging at all levels
- 🧹 **Resource Management**: Automatic cleanup of expired keys and nonces
- 📡 **Protocol Versioning**: Future-proof design with version negotiation (currently v2)

## Protocol Version 2

Version 2 introduces a structured protocol with clear separation of concerns:

- **Version Field**: Enables future protocol evolution and backward compatibility
- **Separate Channels**: 
  - **Payload Channel (`p`)**: User data transmission
  - **Control Channel (`c`)**: Key exchange and protocol management
- **Structured Format**: msgpack dict `{'v': version, 'p': payload, 'c': control, 'g': padding}`

## Installation

```bash
pip install -e .
```

### Requirements
- Python 3.10+
- msgpack
- pyzstd
- psutil
- psygnal>=0.10
- PyNaCl>=1.6.0

## Quick Start

### Basic Usage

```python
from vault_udp_socket import UDPSocketClass

# Create socket
socket = UDPSocketClass(recv_port=11000)

# Add peer
socket.add_peer(("192.168.1.100", 8000))

# Connect callback for received data
def on_data(data, addr):
    print(f"Received: {data} from {addr}")

socket.udp_recv_data.connect(on_data)

# Send data
socket.send_data("Hello, World!")

# Send to specific peer
socket.send_data("Direct message", ("192.168.1.100", 8000))

# Cleanup
socket.stop()
```

### Context Manager

```python
with UDPSocketClass(recv_port=11000) as socket:
    socket.add_peer(("192.168.1.100", 8000))
    socket.send_data("Hello!")
    # Automatic cleanup on exit
```

### Multiple Peers

```python
# Multiple peers on same IP
socket.add_peer(("127.0.0.1", 8000))
socket.add_peer(("127.0.0.1", 8001))
socket.add_peer(("127.0.0.1", 8002))

# Get peers by IP
peers = socket.get_peers_by_ip("127.0.0.1")
print(f"Peers on localhost: {peers}")

# Broadcast to all peers
socket.send_data("Broadcast message")
```

### Rate Limiting

```python
# Custom rate limit (messages per second per peer)
socket = UDPSocketClass(recv_port=11000, rate_limit=50)
```

### Check Protocol Version

```python
stats = socket.get_stats()
print(f"Protocol version: {stats['protocol_version']}")
# Output: Protocol version: 2
```

## Architecture

### Components

```
vault_udp_socket.py          # Main UDP socket with encryption (Protocol v2)
├── vault_udp_encryption.py  # Encryption manager with replay protection
│   └── vault_udp_socket_helper.py  # Crypto primitives (NaCl wrapper)
└── vault_ip.py             # Network utilities (MTU, IP detection)
```

### Protocol v2 Design

#### Packet Structure

```
Encrypted Packet (after encryption):
┌─────────────────────────────────────────┐
│ NaCl Box (authenticated encryption)     │
│ ┌─────────────────────────────────────┐ │
│ │ Nonce (16 bytes)                    │ │
│ │ Timestamp (8 bytes, double)         │ │
│ │ Msgpack Payload:                    │ │
│ │ ┌─────────────────────────────────┐ │ │
│ │ │ {                               │ │ │
│ │ │   'v': 2,          # version    │ │ │
│ │ │   'p': bytes,      # payload    │ │ │
│ │ │   'c': bytes,      # control    │ │ │
│ │ │   'g': bytes       # padding    │ │ │
│ │ │ }                               │ │ │
│ │ └─────────────────────────────────┘ │ │
│ └─────────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

#### Channel Separation

**Payload Channel (`p`)**:
- Compressed user data (zstd)
- Empty for control-only packets
- Emits `udp_recv_data` signal when received

**Control Channel (`c`)**:
- Key exchange messages (JSON)
- Protocol management
- Processed internally, not exposed to user

**Version Field (`v`)**:
- Current version: 2
- Future versions can add features
- Receivers check version compatibility

**Padding Field (`g`)**:
- Random padding to reach MTU
- Prevents traffic analysis based on size

### Security Design

#### Authenticated Encryption
- Uses NaCl Box for authenticated encryption between peers
- Each message includes sender authentication
- Prevents tampering and impersonation attacks

#### Replay Attack Prevention
- 16-byte random nonce per message
- 8-byte timestamp in each message
- Nonce cache with automatic cleanup
- Configurable message freshness window (default: 60 seconds)

#### Key Exchange Protocol
1. Generate encryption keypair (X25519) and signing keypair (Ed25519)
2. Sign public keys with signing private key
3. Exchange signed public keys with peers via control channel, **always in
   plaintext** — a peer's Box public key can't be used to encrypt the very
   message that first announces it, so authenticity here comes from the
   Ed25519 signature alone, not from confidentiality
4. Verify signatures before accepting keys
5. Periodic key refresh with configurable lifetime

Once both sides know each other's keys, all further payload traffic is
encrypted with NaCl Box as described above.

### Message Format Examples

#### User Data (Payload Channel)
```python
# When you call: socket.send_data("Hello")
# Sent packet structure (after all processing):
{
    'v': 2,                    # Protocol version
    'p': b'compressed("Hello")', # Compressed payload
    'c': b'',                  # Empty control
    'g': b'random...'          # Padding
}
```

#### Key Exchange (Control Channel)
```python
# Automatically sent during key exchange:
{
    'v': 2,
    'p': b'',                  # Empty payload
    'c': b'{"enc_key": "...", "sign_key": "...", "signature": "..."}',
    'g': b'random...'
}
```

## API Reference

### UDPSocketClass

#### Methods

**`__init__(recv_port: int = 11000, rate_limit: int = 100)`**
- Initialize UDP socket with protocol v2
- `recv_port`: Port to listen on
- `rate_limit`: Maximum messages per second per peer

**`add_peer(addr: Tuple[str, int])`**
- Add peer and initiate key exchange
- `addr`: Tuple of (ip, port)

**`remove_peer(addr: Tuple[str, int])`**
- Remove peer and cleanup keys

**`send_data(data: Union[str, bytes], addr: Optional[Tuple[str, int]] = None)`**
- Send data to peer(s) via payload channel
- `addr`: Specific peer or None for broadcast

**`get_peers() -> List[Tuple[str, int]]`**
- Get list of all peers

**`get_peers_by_ip(ip: str) -> List[Tuple[str, int]]`**
- Get all peers with specific IP

**`has_peer(addr: Tuple[str, int]) -> bool`**
- Check if peer exists

**`update_recv_port(recv_port: int)`**
- Change listening port (atomic)

**`get_stats() -> dict`**
- Get socket statistics including protocol version

**`stop(timeout: float = 5.0)`**
- Stop all threads and close sockets

#### Signals

**`udp_recv_data`**
- Emitted when user data is received (payload channel)
- Signature: `(data: str, addr: Tuple[str, int])`

**`udp_send_data`**
- Connected to `send_data` method
- For external triggering

### VaultAsymmetricEncryption

Lower-level encryption manager (usually not used directly).

#### Methods

**`generate_keys() -> Tuple[str, str]`**
- Generate new key pairs
- Returns: (enc_public_key, sign_public_key)

**`encrypt(data: bytes, addr: Tuple[str, int]) -> bytes`**
- Encrypt with authentication and replay protection

**`decrypt(data: bytes, addr: Tuple[str, int]) -> bytes`**
- Decrypt and verify (with replay detection)

**`update_peer_keys(addr, enc_key: str, sign_key: str)`**
- Update peer's public keys

### Network Utilities (vault_ip.py)

**`get_min_mtu() -> int`**
- Get minimum MTU across all interfaces

**`get_ipv4_addresses() -> List[str]`**
- Get all IPv4 addresses

**`get_ipv6_addresses() -> List[str]`**
- Get all IPv6 addresses

**`get_network_info() -> dict`**
- Get comprehensive network information

## Configuration

### Key Lifetime

Peer keys currently expire after a fixed 60 seconds
(`DEFAULT_KEY_LIFETIME` in `vault_udp_socket.py`). There is no constructor
argument or public setter to change this yet — setting `socket.lifetime`
after construction only changes the periodic key-resend cadence, it does
*not* reach the encryption manager's actual expiry check, so it won't
change when keys are dropped. Edit `DEFAULT_KEY_LIFETIME` directly if you
need a different value for now.

### MTU Overhead Calculation

The library automatically calculates effective MTU:
```
Base MTU: 1500 (from interface)
- IP Header: 20 bytes
- UDP Header: 8 bytes
- NaCl Box: 40 bytes (nonce + authenticator)
- Msgpack: ~15 bytes (v2 structured format)
- Replay Protection: 24 bytes (nonce + timestamp)
= Effective MTU: ~1393 bytes
```

### Replay Protection

```python
# In vault_udp_encryption.py
MAX_MESSAGE_AGE_SECONDS = 60  # Reject messages older than 60s
NONCE_CACHE_SIZE = 10000      # Max nonces tracked per peer
```

## Protocol Evolution

### Version History

**v2 (Current)**:
- Structured msgpack format with version field
- Separate payload and control channels
- Improved extensibility for future features

### Future Compatibility

The protocol is designed for evolution:
- New versions can add fields to the msgpack dict
- Unknown fields are ignored by older implementations
- Version mismatch is logged but doesn't break connections
- Control channel can negotiate capabilities

## Security Considerations

### Threats Mitigated
✅ **Man-in-the-Middle**: Authenticated encryption prevents tampering  
✅ **Replay Attacks**: Nonce and timestamp validation  
✅ **Impersonation**: Signature verification on key exchange  
✅ **DoS**: Rate limiting per peer  
✅ **Eavesdropping**: All data encrypted with NaCl  
✅ **Protocol Downgrade**: Version checking prevents downgrade attacks

### Threats Not Mitigated
⚠️ **Initial Key Exchange (Trust-On-First-Use)**: The signature on a peer's first key-exchange message proves the message wasn't tampered with and that the sender controls the matching private key — it does *not* prove the sender is who you think they are. There's no external identity check, so a first-contact MITM can present its own, self-consistently signed keys (use TLS/certificates or an out-of-band fingerprint check if you need to verify peer identity)  
⚠️ **Denial of Service**: UDP is inherently vulnerable to packet floods  
⚠️ **Traffic Analysis**: Packet sizes are padded to MTU but timing is visible  

### Best Practices

1. **Use TLS for initial setup** if you need to verify peer identity
2. **Limit key lifetime** to reduce impact of compromised keys
3. **Monitor rate limits** and adjust based on your use case
4. **Use firewall rules** to restrict allowed peers at network level
5. **Regular updates** of PyNaCl and dependencies
6. **Check protocol version** in get_stats() after connecting

## Performance

### Optimization Tips

1. **Adjust compression level**: `pyzstd.compress(data, level=1)` for speed
2. **Increase MTU** on local networks (jumbo frames)
3. **Batch messages** when possible
4. **Use multiple sockets** for parallel communication

## Troubleshooting

### "Message too large" error
- Check your MTU: `socket.get_stats()['mtu']`
- Reduce message size or split into chunks
- Data is compressed automatically but some data doesn't compress well

### Keys not exchanging
- Check network connectivity
- Verify firewall allows UDP on specified ports
- Wait 2-3 seconds after `add_peer()` for initial exchange
- Check logs: `logging.basicConfig(level=logging.DEBUG)`
- Verify protocol version compatibility

### Rate limit exceeded
- Increase rate limit: `UDPSocketClass(rate_limit=200)`
- Check for message loops
- Verify peer isn't flooding

### Replay attack warnings
- Check system clocks are synchronized
- Adjust `MAX_MESSAGE_AGE_SECONDS` if needed
- Verify no message duplication in network

### Protocol version mismatch
- Check logs for version mismatch warnings
- Packets with a different version number are dropped, not translated — there
  is currently no cross-version compatibility, so all peers need to run the
  same protocol version

## Testing

The `tests/` directory has a pytest suite covering the crypto primitives,
the encryption manager (including replay protection), the network utilities,
and a real end-to-end encrypted UDP exchange between two sockets:

```bash
pip install -e ".[dev]"
pytest
```

Each module also has a `main()` with a runnable demo (not an automated
test) that you can use to explore the library interactively:

```bash
python vault_udp_socket.py        # Protocol v2 demo with multiple peers
python vault_udp_encryption.py
python vault_udp_socket_helper.py
python vault_ip.py
```

## Examples

See `main()` functions in each module for working examples.

### Simple Echo Server

```python
from vault_udp_socket import UDPSocketClass

def echo_handler(data, addr):
    print(f"Echo from {addr}: {data}")
    socket.send_data(f"Echo: {data}", addr)

with UDPSocketClass(11000) as socket:
    socket.udp_recv_data.connect(echo_handler)
    
    print(f"Running protocol v{socket.get_stats()['protocol_version']}")
    
    # Keep running
    import time
    while True:
        time.sleep(1)
```

### Version Check

```python
from vault_udp_socket import UDPSocketClass

with UDPSocketClass(11000) as socket:
    stats = socket.get_stats()
    print(f"Protocol: v{stats['protocol_version']}")
    print(f"MTU: {stats['mtu']} bytes")
    print(f"Peers: {stats['peer_count']}")
```

## License

- Copyright [2025] [ecki]
- SPDX-License-Identifier: Apache-2.0

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## Changelog

### Unreleased
- 🐛 Fixed key-exchange signature verification: the signed payload was
  never compared against the claimed keys, so any validly-signed message
  was accepted regardless of its content
- 🐛 Fixed encrypted traffic being silently dropped: the send socket was
  unbound, so outgoing packets used a random ephemeral source port instead
  of `recv_port`, which peers rely on to look up stored keys
- 🐛 Fixed key-exchange replies being sent encrypted with a key the
  recipient couldn't have yet (it was inside that very message); key
  exchange is now always sent in plaintext, authenticated by its Ed25519
  signature
- 🔧 Migrated dependencies from `requirements.txt` into `pyproject.toml`
  (`pip install -e .`)
- 🔧 Replaced the unmaintained, untyped `PySignal` with `psygnal`
- 🔥 Removed the dead top-level `__init__.py` (its relative imports could
  never work in a directory whose name isn't a valid Python identifier)
- ✅ Added a pytest suite covering crypto primitives, replay protection,
  network utilities, and end-to-end encrypted UDP exchange

### Version 0.2.0 (2025) - Protocol v2
- ✨ Introduced protocol v2 with version field
- ✨ Separated control and payload channels
- ✨ Structured msgpack format for extensibility
- 📝 Updated documentation for protocol v2

### Version 0.1.0 (2024)
- ✨ Added authenticated encryption with NaCl Box
- ✨ Added replay attack prevention
- ✨ Added signature verification for key exchange
- ✨ Added rate limiting per peer
- 🐛 Fixed MTU calculation to include all overheads
- 🐛 Fixed memory leaks in nonce tracking
- 🐛 Fixed race condition in port updates
- 🔥 Removed password hashing (unused feature)
- 📝 Completely rewrote documentation

### Version 0.0.1 (2023)
- Initial release with basic UDP + encryption

## Support

For issues and questions:
- Documentation: This README

## Acknowledgments

- [NaCl/libsodium](https://libsodium.gitbook.io/) for cryptography
- [Zstandard](https://facebook.github.io/zstd/) for compression
- [MessagePack](https://msgpack.org/) for efficient serialization
