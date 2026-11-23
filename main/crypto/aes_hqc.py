"""HQC KEM envelope for wrapping AES data-encryption keys.

This uses liboqs for the HQC primitive. liboqs currently targets prototyping
and research; this module is not a production security certification.
"""

import base64
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


SCHEME = "HQC-KEM-AES-256-GCM"
FORMAT_VERSION = 1
DEFAULT_ALGORITHM = "HQC-1"


def _b64encode(value):
    return base64.urlsafe_b64encode(value).decode("ascii")


def _b64decode(value):
    return base64.urlsafe_b64decode(value.encode("ascii"))


def _algorithm():
    return getattr(settings, "HQC_ALGORITHM", None) or os.environ.get(
        "HQC_ALGORITHM", DEFAULT_ALGORITHM
    )


def _oqs_module():
    try:
        import oqs
    except ImportError as exc:
        raise ImproperlyConfigured(
            "HQC requires liboqs-python and a liboqs build with HQC enabled."
        ) from exc

    algorithm = _algorithm()
    if algorithm not in oqs.get_enabled_kem_mechanisms():
        raise ImproperlyConfigured(
            f"HQC KEM {algorithm!r} is unavailable in this liboqs installation."
        )
    configured_version = getattr(settings, "HQC_IMPLEMENTATION_VERSION", None) or os.environ.get(
        "HQC_IMPLEMENTATION_VERSION"
    )
    if configured_version and configured_version != oqs.oqs_version():
        raise ImproperlyConfigured(
            "The configured HQC_IMPLEMENTATION_VERSION does not match liboqs."
        )
    return oqs


def _configured_key(name):
    value = getattr(settings, name, None) or os.environ.get(name)
    if not value:
        raise ImproperlyConfigured(
            f"{name} is required. Generate a persistent HQC keypair and configure it."
        )
    try:
        return _b64decode(value)
    except (ValueError, TypeError) as exc:
        raise ImproperlyConfigured(f"{name} must be URL-safe base64.") from exc


def generate_hqc_keypair():
    """Generate distinct persistent recipient keys for the A and B wrappers."""
    oqs = _oqs_module()
    values = {
        "HQC_ALGORITHM": _algorithm(),
        "HQC_IMPLEMENTATION_VERSION": oqs.oqs_version(),
    }
    for label in ("A", "B"):
        with oqs.KeyEncapsulation(_algorithm()) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
        values[f"HQC_PUBLIC_KEY_{label}"] = _b64encode(public_key)
        values[f"HQC_SECRET_KEY_{label}"] = _b64encode(secret_key)
    return values


def _derive_wrap_key(shared_secret, salt):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"onlinetest/dek-wrap/hqc-kem/v1",
    ).derive(shared_secret)


def wrap_aes_key(aes_key, label="A"):
    if label not in {"A", "B"}:
        raise ValueError("label must be A or B")
    oqs = _oqs_module()
    public_key = _configured_key(f"HQC_PUBLIC_KEY_{label}")
    with oqs.KeyEncapsulation(_algorithm()) as kem:
        kem_ciphertext, shared_secret = kem.encap_secret(public_key)
        implementation_version = oqs.oqs_version()

    salt = os.urandom(16)
    nonce = os.urandom(12)
    wrapping_key = _derive_wrap_key(shared_secret, salt)
    aad = f"{SCHEME}|{FORMAT_VERSION}|{label}|{_algorithm()}".encode("ascii")
    encrypted_dek = AESGCM(wrapping_key).encrypt(nonce, aes_key, aad)
    return {
        "scheme": SCHEME,
        "v": FORMAT_VERSION,
        "kem": _algorithm(),
        "kem_implementation": implementation_version,
        "label": label,
        "kem_ciphertext": _b64encode(kem_ciphertext),
        "kdf_salt": _b64encode(salt),
        "nonce": _b64encode(nonce),
        "wrapped_dek": _b64encode(encrypted_dek),
    }


def unwrap_aes_key(payload, label=None):
    data = json.loads(payload) if isinstance(payload, str) else payload
    if data.get("scheme") != SCHEME or data.get("v") != FORMAT_VERSION:
        raise ValueError("Unsupported HQC DEK envelope format.")
    algorithm = data.get("kem")
    if algorithm != _algorithm():
        raise ValueError(f"Envelope algorithm {algorithm!r} does not match configuration.")
    artifact_label = label or data.get("label")
    if artifact_label not in {"A", "B"} or data.get("label") != artifact_label:
        raise ValueError("Invalid HQC envelope label.")

    oqs = _oqs_module()
    if data.get("kem_implementation") != oqs.oqs_version():
        raise ValueError("Envelope was created by a different liboqs version.")
    secret_key = _configured_key(f"HQC_SECRET_KEY_{artifact_label}")
    with oqs.KeyEncapsulation(algorithm, secret_key=secret_key) as kem:
        shared_secret = kem.decap_secret(_b64decode(data["kem_ciphertext"]))

    salt = _b64decode(data["kdf_salt"])
    nonce = _b64decode(data["nonce"])
    encrypted_dek = _b64decode(data["wrapped_dek"])
    wrapping_key = _derive_wrap_key(shared_secret, salt)
    aad = f"{SCHEME}|{FORMAT_VERSION}|{artifact_label}|{algorithm}".encode("ascii")
    return AESGCM(wrapping_key).decrypt(nonce, encrypted_dek, aad)


def wrap_aes_key_double(aes_key, repetitions=3):
    if repetitions < 1:
        raise ValueError("repetitions must be at least 1")
    envelope = {
        "scheme": f"{SCHEME}-double-wrap-repetition",
        "v": FORMAT_VERSION,
        "kem": _algorithm(),
        "repetition": repetitions,
    }
    for label in ("A", "B"):
        for index in range(1, repetitions + 1):
            envelope[f"wrapped_DEK_{label}_{index}"] = wrap_aes_key(aes_key, label)
    return json.dumps(envelope, separators=(",", ":"))


def unwrap_aes_key_double(payload):
    data = json.loads(payload) if isinstance(payload, str) else payload
    expected_scheme = f"{SCHEME}-double-wrap-repetition"
    if data.get("scheme") != expected_scheme:
        raise ValueError("Unsupported HQC double-wrap format.")

    valid_keys = {}
    repetitions = data.get("repetition", 0)
    for label in ("A", "B"):
        for index in range(1, repetitions + 1):
            artifact = data.get(f"wrapped_DEK_{label}_{index}")
            if not artifact:
                continue
            try:
                key = unwrap_aes_key(artifact, label=label)
            except (InvalidTag, KeyError, TypeError, ValueError):
                continue
            valid_keys[key] = valid_keys.get(key, 0) + 1

    if not valid_keys:
        raise ValueError("No valid repeated HQC-wrapped DEK could be opened.")
    return max(valid_keys, key=valid_keys.get)
