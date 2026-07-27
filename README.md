# nosigner

NIP-46 Remote Signer (Bunker) — Python implementation.

Replaces `nak bunker` which has known bugs:
- "already connected" stale session hangs
- Empty method errors
- No NIP-44 support

## Features

- Full NIP-46 protocol: connect, sign_event, get_public_key, ping, get_relays
- NIP-44 v2 encryption (ChaCha20-Poly1305 + HKDF per-message keys)
- NIP-44 decrypt
- SQLite state persistence (~/.hermes/state/bunker/state.db)
- Exponential backoff WebSocket reconnection
- Systemd daemon deployment

## Requirements

```bash
pip install coincurve websockets>=13.0 aiohttp cryptography
```

## Usage

```bash
python3 nosigner.py \
  --sec nsec1... \
  --relay wss://relay.primal.net \
  --relay wss://nostr.mom \
  --secret my-secret-phrase \
  --daemon
```

## Known Limitation

NIP-04 decryption not yet implemented. Some clients (notably `nak`) use NIP-04
for NIP-46 request encryption instead of NIP-44. This causes "Unsupported
NIP-44 version" errors. Implementing `nip04_decrypt` is the next priority.

## License

MIT
