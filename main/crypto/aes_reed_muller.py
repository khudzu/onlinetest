import base64
import hashlib
import json
import os

import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.conf import settings

from main.crypto.mceliece_reed_muller import (
    decrypt_bytes,
    encrypt_bytes,
    generate_keypair,
)


def _b64encode(data):
    return base64.urlsafe_b64encode(data).decode("ascii")


def _b64decode(data):
    return base64.urlsafe_b64decode(data.encode("ascii"))


def generate_key_salt():
    return _b64encode(os.urandom(16))


def _seed_material(password=None, salt=None, label="A"):
    if password is None:
        return f"{settings.SECRET_KEY}:{label}".encode("utf-8")

    if salt is None:
        raise ValueError("salt is required when password is provided.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_b64decode(salt),
        iterations=200000,
    )
    return kdf.derive(f"{password}:{label}".encode("utf-8"))


def _keypair_seed(password=None, salt=None, label="A"):
    digest = hashlib.sha256(_seed_material(password, salt, label)).digest()
    return int.from_bytes(digest[:8], "big")


def _reed_muller_keypair(password=None, salt=None, label="A"):
    return generate_keypair(order_m=4, seed=_keypair_seed(password, salt, label))


def generate_aes_key():
    return AESGCM.generate_key(bit_length=256)


def encrypt_text(plaintext, aes_key):
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, str(plaintext).encode("utf-8"), None)
    return json.dumps(
        {
            "alg": "AES-256-GCM",
            "nonce": _b64encode(nonce),
            "ciphertext": _b64encode(ciphertext),
        },
        separators=(",", ":"),
    )


def decrypt_text(payload, aes_key):
    try:
        data = json.loads(payload)
        nonce = _b64decode(data["nonce"])
        ciphertext = _b64decode(data["ciphertext"])
        return AESGCM(aes_key).decrypt(nonce, ciphertext, None).decode("utf-8")
    except (TypeError, ValueError, KeyError, json.JSONDecodeError):
        return payload


def encrypt_image_bytes(image_bytes, aes_key):
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, image_bytes, None)
    return json.dumps(
        {
            "alg": "AES-256-GCM",
            "nonce": _b64encode(nonce),
            "ciphertext": _b64encode(ciphertext),
        },
        separators=(",", ":"),
    ).encode("utf-8")


def decrypt_image_bytes(payload, aes_key):
    data = json.loads(payload.decode("utf-8"))
    nonce = _b64decode(data["nonce"])
    ciphertext = _b64decode(data["ciphertext"])
    return AESGCM(aes_key).decrypt(nonce, ciphertext, None)


def get_payload_ciphertext_bytes(payload):
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8")
    data = json.loads(payload)
    return _b64decode(data["ciphertext"])


def get_payload_ciphertext_text(payload):
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8")
    try:
        data = json.loads(payload)
        return data["ciphertext"]
    except (TypeError, ValueError, KeyError, json.JSONDecodeError):
        return payload


def _wrap_aes_key_once(aes_key, password=None, salt=None, label="A"):
    public_key, _ = _reed_muller_keypair(password, salt, label)
    blocks, padding = encrypt_bytes(aes_key, public_key)
    encoded_blocks = [
        _b64encode(np.packbits(block, bitorder="big").tobytes())
        for block in blocks
    ]
    return json.dumps(
        {
            "alg": "McEliece-RM(1,4)",
            "padding": padding,
            "blocks": encoded_blocks,
        },
        separators=(",", ":"),
    )


def _unwrap_aes_key_once(data, password=None, salt=None, label="A"):
    _, private_key = _reed_muller_keypair(password, salt, label)
    blocks = [
        np.unpackbits(np.frombuffer(_b64decode(block), dtype=np.uint8), bitorder="big")[
            : private_key.public_key.generator.shape[1]
        ]
        for block in data["blocks"]
    ]
    return decrypt_bytes(blocks, private_key, data.get("padding", 0))


def wrap_aes_key(aes_key, password=None, salt=None):
    return _wrap_aes_key_once(aes_key, password, salt, label="A")


def unwrap_aes_key(payload, password=None, salt=None):
    data = json.loads(payload)
    if data.get("scheme") == "double-wrap-repetition":
        try:
            return unwrap_aes_key_double(payload, password, salt)
        except ValueError:
            pass
    return _unwrap_aes_key_once(data, password, salt, label="A")


def wrap_aes_key_double(aes_key, password=None, salt=None, repetitions=3):
    data = {
        "scheme": "double-wrap-repetition",
        "alg": "McEliece-RM(1,4)",
        "repetition": repetitions,
    }
    for label in ["A", "B"]:
        for index in range(1, repetitions + 1):
            data[f"wrapped_DEK_{label}_{index}"] = json.loads(
                _wrap_aes_key_once(aes_key, password, salt, label)
            )
    return json.dumps(data, separators=(",", ":"))


def unwrap_aes_key_double(payload, password=None, salt=None):
    data = json.loads(payload)
    candidates = []

    for label in ["A", "B"]:
        for index in range(1, data.get("repetition", 3) + 1):
            wrapped = data.get(f"wrapped_DEK_{label}_{index}")
            if not wrapped:
                continue
            try:
                candidates.append(_unwrap_aes_key_once(wrapped, password, salt, label))
            except (ValueError, KeyError, json.JSONDecodeError):
                continue

    if not candidates:
        raise ValueError("No valid repeated wrapped DEK could be decrypted.")

    counts = {}
    for candidate in candidates:
        counts[candidate] = counts.get(candidate, 0) + 1

    return max(counts, key=counts.get)
