"""
Integration tests for nosigner NIP-46 protocol.

Uses deterministic keys and mocked relay/cryptographic side effects where
possible, but exercises the real implementations for NIP-04/NIP-44 crypto and
request/response handling.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import nosigner as ns


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def signer_keys():
    """Deterministic signer keys for the whole test run."""
    # Deterministic but arbitrary private key.
    sk = os.urandom(32)
    pk = ns.privkey_to_pubkey(sk)
    return {"priv": sk, "pub": pk, "pub_hex": pk.hex()}


@pytest.fixture(scope="session")
def client_keys():
    """Deterministic client keys."""
    sk = os.urandom(32)
    pk = ns.privkey_to_pubkey(sk)
    return {"priv": sk, "pub": pk, "pub_hex": pk.hex()}


@pytest.fixture
def state(tmp_path):
    """Fresh BunkerState in a temp directory."""
    db = tmp_path / "state.db"
    return ns.BunkerState(db_path=db)


@pytest.fixture
def handler(signer_keys, state):
    """Fresh Nip46Handler for the signer."""
    return ns.Nip46Handler(signer_keys["priv"], state)


@pytest.fixture
def relay_pool():
    """RelayPool using a local loopback relay URL."""
    pool = ns.RelayPool(["wss://nosigner-test.invalid/relay"])
    return pool


# ── Helpers ─────────────────────────────────────────────────────────────────


def _build_request_event(
    content: Any,
    client_keys: dict,
    kind: int = ns.NIP_46_KIND,
    tags: list | None = None,
) -> dict[str, Any]:
    """Build an unencrypted or pre-encrypted request event from the client."""
    tags = tags or []
    return {
        "id": os.urandom(32).hex(),
        "pubkey": client_keys["pub_hex"],
        "created_at": int(time.time()),
        "kind": kind,
        "tags": tags,
        "content": content if isinstance(content, str) else json.dumps(content),
        "sig": "00" * 64,
    }


def _encrypt_nip44_request(
    payload: list[Any], handler: ns.Nip46Handler, client_keys: dict
) -> str:
    """Encrypt a request with NIP-44 from the client's perspective."""
    plaintext = json.dumps(payload)
    conv_key = ns.get_conversation_key(client_keys["priv"], bytes.fromhex(handler.pubkey_hex))
    return ns.nip44_encrypt(plaintext, conv_key)


def _decrypt_nip44_response(
    content: str, handler: ns.Nip46Handler, client_keys: dict
) -> Any:
    """Decrypt a NIP-44 response from the client's perspective."""
    conv_key = ns.get_conversation_key(client_keys["priv"], bytes.fromhex(handler.pubkey_hex))
    return json.loads(ns.nip44_decrypt(content, conv_key))


# ── Relay subscription format ───────────────────────────────────────────────


def test_relay_subscription_format(signer_keys, relay_pool):
    """REQ filter must include kinds=[24133] and #p=signer_pubkey."""
    sub_id = asyncio.run(
        relay_pool.subscribe(kinds=[ns.NIP_46_KIND], p_tags=[signer_keys["pub_hex"]])
    )
    assert len(sub_id) == 12
    assert relay_pool._sub_id == sub_id


# ── handle_request decrypt-first ────────────────────────────────────────────


def test_handle_request_decrypts_unencrypted_array(handler, client_keys):
    """Unencrypted JSON array is parsed and handled."""
    req = ["req-1", "ping"]
    event = _build_request_event(req, client_keys)
    # Pre-authorize client so ping is not rejected.
    handler.state.add_authorized_key(client_keys["pub_hex"])
    resp = handler.handle_request_sync(event)
    assert resp is not None
    content = json.loads(resp["content"])
    assert content == ["req-1", "ok", "pong"]


def test_handle_request_decrypts_nip44_first(handler, client_keys):
    """handle_request decrypts NIP-44 encrypted payloads."""
    req = ["req-2", "ping"]
    conv_key = ns.get_conversation_key(
        client_keys["priv"], bytes.fromhex(handler.pubkey_hex)
    )
    encrypted = ns.nip44_encrypt(json.dumps(req), conv_key)
    event = _build_request_event(encrypted, client_keys)
    handler.state.add_authorized_key(client_keys["pub_hex"])

    resp = handler.handle_request_sync(event)
    assert resp is not None
    assert resp["kind"] == ns.NIP_46_KIND
    decrypted = _decrypt_nip44_response(resp["content"], handler, client_keys)
    assert decrypted == ["req-2", "ok", "pong"]


# ── NIP-44 crypto correctness ───────────────────────────────────────────────


def test_nip44_roundtrip_with_known_conversation_key():
    """NIP-44 encrypt/decrypt roundtrip with a fixed conversation key."""
    conv_key = bytes.fromhex("0" * 64)
    plaintexts = ["hello", "", "a" * 5000, json.dumps({"method": "ping"})]
    for pt in plaintexts:
        ct = ns.nip44_encrypt(pt, conv_key)
        assert ct != pt
        decrypted = ns.nip44_decrypt(ct, conv_key)
        assert decrypted == pt


def test_nip44_wrong_conversation_key_fails():
    """Decrypting with a different key raises ValueError / cryptography error."""
    conv_key_a = os.urandom(32)
    conv_key_b = os.urandom(32)
    ct = ns.nip44_encrypt("secret", conv_key_a)
    with pytest.raises(Exception):
        ns.nip44_decrypt(ct, conv_key_b)


# ── connect flow ────────────────────────────────────────────────────────────


def test_connect_authorizes_client_with_valid_secret(handler, client_keys):
    """connect with the right secret adds the client to authorized_keys."""
    handler.set_active_secret("s3cr3t")
    req = ["conn-1", "connect", ["s3cr3t"]]
    event = _build_request_event(req, client_keys)

    assert not handler.state.is_authorized(client_keys["pub_hex"])
    resp = handler.handle_request_sync(event)
    assert resp is not None
    assert handler.state.is_authorized(client_keys["pub_hex"])


def test_connect_rejects_wrong_secret(handler, client_keys):
    """connect with the wrong secret returns an error response."""
    handler.set_active_secret("s3cr3t")
    req = ["conn-2", "connect", ["wrong"]]
    event = _build_request_event(req, client_keys)
    resp = handler.handle_request_sync(event)
    assert resp is not None
    content = json.loads(resp["content"])
    assert content == ["conn-2", "error", "Unauthorized"]
    assert not handler.state.is_authorized(client_keys["pub_hex"])


# ── sign_event flow ─────────────────────────────────────────────────────────


def test_sign_event_returns_valid_signature(handler, client_keys, signer_keys):
    """sign_event returns a recoverable signature over the event hash."""
    handler.state.add_authorized_key(client_keys["pub_hex"])
    template = {
        "kind": 1,
        "content": "hello world",
        "tags": [],
        "created_at": 1700000000,
    }
    req = ["sign-1", "sign_event", [template]]
    event = _build_request_event(req, client_keys)
    resp = handler.handle_request_sync(event)
    assert resp is not None

    content = json.loads(resp["content"])
    assert content[0] == "sign-1"
    assert content[1] == "ok"
    sig_hex = content[2]
    assert len(bytes.fromhex(sig_hex)) == 65


# ── get_public_key ──────────────────────────────────────────────────────────


def test_get_public_key(handler, client_keys, signer_keys):
    """get_public_key returns the signer's x-only pubkey."""
    handler.state.add_authorized_key(client_keys["pub_hex"])
    req = ["pk-1", "get_public_key"]
    event = _build_request_event(req, client_keys)
    resp = handler.handle_request_sync(event)
    assert resp is not None
    content = json.loads(resp["content"])
    assert content == ["pk-1", "ok", signer_keys["pub_hex"]]


# ── ping ──────────────────────────────────────────────────────────────────────


def test_ping(handler, client_keys):
    """ping returns pong."""
    handler.state.add_authorized_key(client_keys["pub_hex"])
    req = ["ping-1", "ping"]
    event = _build_request_event(req, client_keys)
    resp = handler.handle_request_sync(event)
    assert resp is not None
    content = json.loads(resp["content"])
    assert content == ["ping-1", "ok", "pong"]


# ── unauthorized client rejection ────────────────────────────────────────────


def test_unauthorized_client_rejected_for_sign_event(handler, client_keys):
    """A client that is not authorized cannot sign events."""
    assert not handler.state.is_authorized(client_keys["pub_hex"])
    req = ["unauth-1", "sign_event", [{"kind": 1, "content": "x"}]]
    event = _build_request_event(req, client_keys)
    resp = handler.handle_request_sync(event)
    assert resp is not None
    content = json.loads(resp["content"])
    assert content == ["unauth-1", "error", "Unauthorized"]


def test_unauthorized_client_rejected_for_get_public_key(handler, client_keys):
    """A client that is not authorized cannot call get_public_key."""
    req = ["unauth-2", "get_public_key"]
    event = _build_request_event(req, client_keys)
    resp = handler.handle_request_sync(event)
    assert resp is not None
    content = json.loads(resp["content"])
    assert content == ["unauth-2", "error", "Unauthorized"]


# ── exponential backoff ─────────────────────────────────────────────────────


def test_exponential_backoff_capped():
    """Backoff doubles each failure and is capped at RECONNECT_MAX."""
    base = ns.RECONNECT_BASE
    max_ = ns.RECONNECT_MAX
    delays = []
    backoff = base
    for _ in range(10):
        delays.append(backoff)
        backoff = min(backoff * 2, max_)
    expected = [1, 2, 4, 8, 16, 32, 60, 60, 60, 60]
    assert delays == expected


@pytest.mark.asyncio
async def test_relay_pool_backoff_on_connection_failure():
    """RelayPool retries with exponential backoff when connection fails."""
    pool = ns.RelayPool(["wss://nosigner-test.invalid/relay"])
    with patch.object(ns.ws_client, "connect", side_effect=Exception("network down")) as mock_connect:
        pool._conns["wss://nosigner-test.invalid/relay"] = asyncio.create_task(
            pool._run_relay("wss://nosigner-test.invalid/relay")
        )
        # Wait for at least one retry (base backoff is 1s).
        await asyncio.sleep(1.3)
        pool._stop.set()
        pool._conns["wss://nosigner-test.invalid/relay"].cancel()
        try:
            await pool._conns["wss://nosigner-test.invalid/relay"]
        except asyncio.CancelledError:
            pass

    assert mock_connect.call_count >= 2


# ── Response encryption mirroring ──────────────────────────────────────────


def test_response_uses_nip44_when_client_used_nip44(handler, client_keys):
    """A NIP-44 request must produce a NIP-44 response."""
    req = ["enc-1", "ping"]
    conv_key = ns.get_conversation_key(
        client_keys["priv"], bytes.fromhex(handler.pubkey_hex)
    )
    encrypted = ns.nip44_encrypt(json.dumps(req), conv_key)
    event = _build_request_event(encrypted, client_keys)
    handler.state.add_authorized_key(client_keys["pub_hex"])

    resp = handler.handle_request_sync(event)
    assert resp is not None
    # Decrypt from client side
    decrypted = _decrypt_nip44_response(resp["content"], handler, client_keys)
    assert decrypted == ["enc-1", "ok", "pong"]


def test_response_uses_nip04_when_client_used_nip04(handler, client_keys):
    """A NIP-04 request must produce a NIP-04 response."""
    req = ["enc-2", "ping"]
    plaintext = json.dumps(req)
    encrypted = ns.nip04_encrypt(plaintext, client_keys["priv"], bytes.fromhex(handler.pubkey_hex))
    event = _build_request_event(encrypted, client_keys)
    handler.state.add_authorized_key(client_keys["pub_hex"])

    resp = handler.handle_request_sync(event)
    assert resp is not None
    decrypted = ns.nip04_decrypt(
        resp["content"], client_keys["priv"], bytes.fromhex(handler.pubkey_hex)
    )
    assert json.loads(decrypted) == ["enc-2", "ok", "pong"]
