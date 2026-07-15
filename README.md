# py-vault-udp (sealedbox branch)

Python UDP communication library with opportunistic, anonymous encryption,
automatic key exchange, message compression, and rate limiting.

This branch replaces the previous NaCl `Box`-based (authenticated,
signed) encryption with NaCl `SealedBox` (anonymous, unauthenticated)
encryption. **Read the [Security Model](#security-model) section before
using this** — the trade-offs are different from what "authenticated
encryption" usually implies.

## Why SealedBox

The `Box`-based design had two structural problems:

1. **Bootstrap chicken-and-egg**: `Box` encryption needs *both* the
   sender's private key and the recipient's public key (it's
   Diffie-Hellman based). A peer's first key announcement can't be
   encrypted with the peer's own key, because the recipient doesn't have
   that key yet — it's inside the very message announcing it.
2. **Source-port coupling**: decrypting a `Box` message requires knowing
   who sent it, which this library resolved by looking up a stored key by
   the packet's source address. That's fragile against port/address
   changes.

`SealedBox` sidesteps both: encrypting only needs the *recipient's*
public key, and decrypting only needs *our own* private key — the
recipient's identity never has to be known or looked up to open a
message. The cost is that `SealedBox` provides no sender authentication
at all (see below).

## Features

- 🔓 **Anonymous Encryption**: NaCl `SealedBox` (X25519 + XSalsa20-Poly1305), opportunistic — falls back to plaintext UDP if no peer key is known yet
- 🔑 **Automatic Key Exchange**: peers announce their public key on `add_peer()` and periodically afterward; announcements are encrypted once a peer's key is already known, plaintext otherwise
- ⏰ **Key Lifecycle Management**: automatic expiration and cleanup of stored peer keys
- 📦 **Message Compression**: Zstd compression for reduced bandwidth
- 🎯 **MTU-Aware Padding**: packets are padded to a constant size to resist size-based traffic analysis
- 📊 **Rate Limiting**: configurable per-peer rate limiting
- 🔄 **Multiple Peers**: supports multiple peers on the same IP address
- 🌐 **Network Discovery**: automatic interface and MTU detection
- 📡 **Protocol Versioning**: structured, versioned msgpack format (currently v2)
- 🚀 **Thread-Safe**: all public operations use internal locking

## Security Model

Read this carefully — it differs meaningfully from a typical "encrypted
messaging" library.

### What SealedBox gives you
✅ **Confidentiality against passive eavesdroppers**: anyone without the
recipient's private key cannot read a message's plaintext.
✅ **Opportunistic protection**: traffic is encrypted whenever a peer's
key is known, with a plaintext fallback otherwise (so the library keeps
working even before/without key exchange).
✅ **Size-based traffic analysis resistance**: all packets are padded to
the same MTU-derived size.

### What it does NOT give you
⚠️ **No sender authentication**: `SealedBox` proves a message was
encrypted for *your* public key. It proves nothing about who encrypted
it. Anyone who has your public key (which is, by design, public) can
send you a message that decrypts cleanly and looks legitimate.
⚠️ **No peer identity verification**: a key announcement claiming to be
from a given IP:port is accepted at face value. There is no signature,
certificate, or other proof tying a key to a specific peer. This is
trust-on-first-use with no verification step at all — weaker than the
previous signed-but-still-TOFU design. As a (non-cryptographic) mitigation,
a key that changes for an address we'd already seen a key for is logged as
a `WARNING` instead of silently accepted, so at least there's something to
notice or alert on — it does not distinguish a legitimate key rotation
from a hijack attempt.
⚠️ **No replay protection**: there is no nonce or timestamp tracking.
A captured ciphertext can be re-sent verbatim and will decrypt
successfully again, indistinguishable from a fresh message.
⚠️ **No tamper-evidence tied to identity**: `SealedBox` still uses an
authenticated cipher (XSalsa20-Poly1305), so a *modified* ciphertext
will fail to decrypt — but a *replayed, unmodified* one won't.
⚠️ **Message injection, not just eavesdropping**: the first key
announcement between two peers is always sent in plaintext, and UDP
source addresses are trivially spoofable (there's no handshake or
cookie). So this is more than a passive confidentiality gap: anyone who
observes that one plaintext announcement can subsequently send a peer
forged data that looks like a legitimate encrypted message from the
other side, without ever needing to intercept or redirect real traffic.
⚠️ **Denial of Service**: UDP is inherently vulnerable to packet floods;
rate limiting is per-source-address only.

### When this is (and isn't) appropriate
This model fits use cases where confidentiality against passive network
observers is the goal — e.g. hiding payload content and sizes on a
network you don't fully trust — and where peers are on a network where
spoofing/replay isn't a practical threat, or where the application layer
adds its own authentication and freshness checks on top. It is **not**
appropriate if you need to know a message genuinely came from a specific
peer, or need protection against a captured packet being replayed.
If you need those properties, use TLS/mTLS, or reintroduce
signing and nonce tracking on top of this (see `main` branch history for
a signed+replay-protected variant built on `Box`).

## Protocol Version 2

- **Version Field**: enables future protocol evolution and compatibility checks
- **Separate Channels**:
  - **Payload Channel (`p`)**: user data transmission
  - **Control Channel (`c`)**: key exchange
- **Structured Format**: msgpack dict `{'v': version, 'p': payload, 'c': control, 'g': padding}`

Packets with an unexpected version number are dropped, not translated —
there's no cross-version compatibility.

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

# Add peer (triggers an immediate key announcement)
socket.add_peer(("192.168.1.100", 8000))

# Connect callback for received data
def on_data(data, addr):
    print(f"Received: {data} from {addr}")

socket.udp_recv_data.connect(on_data)

# Send data (opportunistically encrypted once the peer's key is known)
socket.send_data("Hello, World!")

# Send to a specific peer
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
socket.add_peer(("127.0.0.1", 8000))
socket.add_peer(("127.0.0.1", 8001))
socket.add_peer(("127.0.0.1", 8002))

peers = socket.get_peers_by_ip("127.0.0.1")
print(f"Peers on localhost: {peers}")

# Broadcast to all peers
socket.send_data("Broadcast message")
```

### Rate Limiting

```python
socket = UDPSocketClass(recv_port=11000, rate_limit=50)  # msgs/sec/peer
```

### Check Protocol Version / Stats

```python
stats = socket.get_stats()
print(f"Protocol version: {stats['protocol_version']}")
print(f"MTU: {stats['mtu']}")
print(f"Peers: {stats['peer_count']}")
```

## Architecture

```
vault_udp_socket.py          # UDP socket, protocol v2 framing, key exchange
├── vault_udp_encryption.py  # Peer key lifecycle + SealedBox encrypt/decrypt
│   └── vault_udp_socket_helper.py  # SealedBox crypto primitives (NaCl wrapper)
└── vault_ip.py               # Network utilities (MTU, IP detection)
```

### Packet Structure

```
Encrypted Packet (after encryption):
┌───────────────────────────────────────────┐
│ NaCl SealedBox                             │
│ ┌─────────────────────────────────────────┐│
│ │ Ephemeral public key (32 bytes)          ││
│ │ Ciphertext + Poly1305 MAC (16 bytes)     ││
│ │ Msgpack Payload:                         ││
│ │ ┌───────────────────────────────────────┐││
│ │ │ {                                     │││
│ │ │   'v': 2,          # version          │││
│ │ │   'p': bytes,      # payload          │││
│ │ │   'c': bytes,      # control          │││
│ │ │   'g': bytes       # padding          │││
│ │ │ }                                     │││
│ │ └───────────────────────────────────────┘││
│ └─────────────────────────────────────────┘│
└───────────────────────────────────────────┘
```

If no key is known for the peer yet, the msgpack payload is sent as-is,
unencrypted.

### Channel Separation

**Payload Channel (`p`)**: compressed user data; empty for control-only
packets; emits the `udp_recv_data` signal when received.

**Control Channel (`c`)**: key announcements (`{"enc_key": ..., "port":
...}` as JSON); processed internally, not exposed to user code.

### Key Exchange

1. Generate an X25519 encryption key pair (no signing key pair anymore)
2. On `add_peer()`, announce our public key + listening port via the
   control channel — encrypted if we already have that peer's key,
   plaintext otherwise (see [Security Model](#security-model))
3. On receiving an announcement, store the sender's key (address-keyed)
   and, if this is the first time we've seen that peer, reply with our
   own announcement
4. Re-announce periodically to refresh key lifetime on both sides

Decryption never needs to look up who sent a packet — it only uses our
own private key. Encryption still needs to look up the target peer's
public key by address, since that's what `SealedBox` encryption requires.

## API Reference

### UDPSocketClass (`vault_udp_socket.py`)

**`__init__(recv_port: int = 11000, rate_limit: int = 100, lifetime: int = 60)`**
Bind a single socket (used for both send and receive) and start the
read and key-management background threads.

**`add_peer(addr: Tuple[str, int])`** — add a peer and send it our key
**`remove_peer(addr: Tuple[str, int])`** — remove peer and its stored key
**`get_peers() -> List[Tuple[str, int]]`**
**`has_peer(addr: Tuple[str, int]) -> bool`**
**`get_peers_by_ip(ip: str) -> List[Tuple[str, int]]`**
**`update_recv_port(recv_port: int)`** — atomically rebind to a new port and
re-announce our key to all known peers under it
**`update_lifetime(lifetime: int)`** — change how long peer keys are kept
before they're treated as expired
**`send_data(data: Union[str, bytes], addr: Optional[Tuple[str, int]] = None)`**
Send via the payload channel; `addr=None` broadcasts to all peers.
Raises `MessageTooLargeError` if the compressed message doesn't fit the
MTU, `TypeError` if `data` isn't `str`/`bytes`.
**`get_stats() -> dict`** — protocol version, MTU, peer counts, own public key, encryption stats
**`stop(timeout: float = 5.0)`** — stop threads and close the socket

**Signals** (via [psygnal](https://github.com/pyapp-kit/psygnal)):
- `udp_recv_data`: emitted `(data: str, addr: Tuple[str, int])` when payload data is received
- `udp_send_data`: connected to `send_data` for external/signal-based triggering

### VaultAsymmetricEncryption (`vault_udp_encryption.py`)

Lower-level key/encryption manager (usually not used directly).

**`generate_keys() -> str`** / **`set_private_keys(enc_private_key: str) -> str`**
**`update_peer_keys(addr, enc_key: str)`** / **`remove_peer_keys(addr)`** / **`peer_keys_exist(addr) -> bool`**
**`get_peer_key(addr) -> Optional[str]`** — the currently stored key for a peer, or `None`
**`set_key_lifetime(lifetime: int)`** — change the expiry threshold; wakes the
background cleanup pass immediately instead of waiting out the old interval
**`encrypt(data: bytes, addr: Tuple[str, int]) -> bytes`** — raises `KeyNotFoundError` if we don't have that peer's key
**`decrypt(data: bytes) -> bytes`** — no `addr` needed; raises `DecryptionError` on failure
**`encrypt_if_possible` / `decrypt_if_possible`** — same, falling back to the original data on failure instead of raising
**`cleanup_expired_keys() -> int`** / **`get_stats() -> dict`**

### Crypto primitives (`vault_udp_socket_helper.py`)

**`generate_keys_asym() -> Tuple[str, str]`** — `(public_key, private_key)`
**`generate_public_key(private_key: str) -> str`**
**`encrypt_sealed(recipient_public_key: str, message: bytes) -> bytes`**
**`decrypt_sealed(recipient_private_key: str, message: bytes) -> bytes`**
**`verify_key_pair(enc_public_key: str, enc_private_key: str) -> bool`**
**`bytes_to_b64_str` / `b64_str_to_bytes`**

### Network Utilities (`vault_ip.py`)

**`get_min_mtu() -> int`** / **`get_ipv4_addresses() -> List[str]`** / **`get_ipv6_addresses() -> List[str]`** / **`get_network_info() -> dict`**

## Configuration

### Key Lifetime

Peer keys default to a 60 second lifetime, configurable at construction
or afterward:

```python
socket = UDPSocketClass(recv_port=11000, lifetime=120)
...
socket.update_lifetime(300)
```

`update_lifetime()` takes effect immediately: both the background key
expiry check and the periodic re-announcement cadence (roughly
`lifetime // 3`) are woken up and re-evaluated right away, rather than
waiting out whatever interval was computed under the old lifetime.

### MTU Overhead Calculation

```
Base MTU: 1500 (from interface)
- IP Header: 20 bytes
- UDP Header: 8 bytes
- SealedBox: 48 bytes (32-byte ephemeral public key + 16-byte authenticator)
- Msgpack: ~15 bytes (v2 structured format)
= Effective MTU: ~1409 bytes
```

## Testing

```bash
pip install -e ".[dev]"
pytest
```

The `tests/` directory covers the crypto primitives, peer key lifecycle,
and a real end-to-end encrypted UDP exchange between two sockets.

Each module also has a runnable `main()` demo (not an automated test):

```bash
python vault_udp_socket.py
python vault_udp_encryption.py
python vault_udp_socket_helper.py
python vault_ip.py
```

## Troubleshooting

### "Message too large" error
- Check `socket.get_stats()['mtu']`; reduce message size or split it up
- Data is compressed automatically, but some data doesn't compress well

### Keys not exchanging
- Check network connectivity and firewall rules for the UDP ports used
- Wait briefly after `add_peer()` for the announcement round-trip
- Enable debug logging: `logging.basicConfig(level=logging.DEBUG)`

### Rate limit exceeded
- Increase it: `UDPSocketClass(rate_limit=200)`
- Check for message loops or a flooding peer

## License

- Copyright [2025] [ecki]
- SPDX-License-Identifier: Apache-2.0

## Acknowledgments

- [NaCl/libsodium](https://libsodium.gitbook.io/) for cryptography
- [Zstandard](https://facebook.github.io/zstd/) for compression
- [MessagePack](https://msgpack.org/) for efficient serialization
- [psygnal](https://github.com/pyapp-kit/psygnal) for the signal/slot API
