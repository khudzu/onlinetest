import base64
import hashlib
import json
import os

import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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


def _keypair_seed():
    digest = hashlib.sha256(settings.SECRET_KEY.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")


def _reed_muller_keypair():
    return generate_keypair(order_m=4, seed=_keypair_seed())


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


def wrap_aes_key(aes_key):
    public_key, _ = _reed_muller_keypair()
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


def unwrap_aes_key(payload):
    _, private_key = _reed_muller_keypair()
    data = json.loads(payload)
    blocks = [
        np.unpackbits(np.frombuffer(_b64decode(block), dtype=np.uint8), bitorder="big")[
            : private_key.public_key.generator.shape[1]
        ]
        for block in data["blocks"]
    ]
    return decrypt_bytes(blocks, private_key, data.get("padding", 0))
