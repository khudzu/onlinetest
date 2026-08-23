import base64
import hashlib
import hmac
import io
import json
import os
import struct
from datetime import datetime, timezone as datetime_timezone

import qrcode
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone


SIGNATURE_CONTEXT = b"onlinetest-family-card-ed25519-v1"
COMPACT_TOKEN_FORMAT = ">BI12s32s4s"
COMPACT_TOKEN_SIZE = struct.calcsize(COMPACT_TOKEN_FORMAT)
SIGNED_MEMBER_FIELDS = (
    "Nama",
    "NIK",
    "no_kk",
    "tempat_lahir",
    "tanggal_lahir",
    "jenis_kelamin",
    "nama_ayah",
    "nama_ibu",
    "agama",
    "pendidikan",
    "jenis_pekerjaan",
    "status_perkawinan",
    "status_hubungan_keluarga",
    "kewarganegaraan",
    "no_paspor",
    "no_kitap",
    "Alamat",
)


def _b64url_encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value):
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def _signing_seed():
    configured_key = os.getenv("FAMILY_CARD_SIGNING_PRIVATE_KEY", "").strip()
    if configured_key:
        try:
            seed = _b64url_decode(configured_key)
        except (ValueError, UnicodeEncodeError) as exc:
            raise ImproperlyConfigured(
                "FAMILY_CARD_SIGNING_PRIVATE_KEY must be a base64url value."
            ) from exc
        if len(seed) != 32:
            raise ImproperlyConfigured(
                "FAMILY_CARD_SIGNING_PRIVATE_KEY must decode to exactly 32 bytes."
            )
        return seed

    return hashlib.sha256(
        SIGNATURE_CONTEXT + b"\0" + settings.SECRET_KEY.encode("utf-8")
    ).digest()


def _private_key():
    return Ed25519PrivateKey.from_private_bytes(_signing_seed())


def _public_key():
    return _private_key().public_key()


def public_key_fingerprint():
    public_bytes = _public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    digest = hashlib.sha256(public_bytes).hexdigest()[:24].upper()
    return "-".join(digest[index : index + 4] for index in range(0, len(digest), 4))


def family_reference(no_kk):
    digest = hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        SIGNATURE_CONTEXT + b"\0ref\0" + str(no_kk).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return digest[:24]


def family_digest(members):
    rows = []
    for member in members:
        rows.append(
            {
                field: str(getattr(member, field, "") or "")
                for field in SIGNED_MEMBER_FIELDS
            }
        )
    rows.sort(key=lambda row: (row["NIK"], row["Nama"]))
    canonical = json.dumps(
        rows,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def sign_family_card(no_kk, members, issued_at=None):
    issued_at = issued_at or timezone.now()
    no_kk_last4 = str(no_kk)[-4:]
    if len(no_kk_last4) != 4 or not no_kk_last4.isdigit():
        raise ValueError("Family-card number must end with four digits.")
    payload = {
        "alg": "Ed25519",
        "digest": family_digest(members),
        "family_ref": family_reference(no_kk),
        "issued_at": issued_at.replace(microsecond=0).isoformat(),
        "no_kk_last4": no_kk_last4,
        "v": 2,
    }
    payload_bytes = struct.pack(
        COMPACT_TOKEN_FORMAT,
        payload["v"],
        int(issued_at.timestamp()),
        bytes.fromhex(payload["family_ref"]),
        bytes.fromhex(payload["digest"]),
        no_kk_last4.encode("ascii"),
    )
    signature = _private_key().sign(payload_bytes)
    token = f"{_b64url_encode(payload_bytes)}.{_b64url_encode(signature)}"
    return {
        "fingerprint": public_key_fingerprint(),
        "payload": payload,
        "token": token,
    }


def verify_family_card_token(token):
    if not token or len(token) > 4096:
        raise ValueError("Invalid family-card signature token.")
    try:
        payload_part, signature_part = token.split(".", 1)
        payload_bytes = _b64url_decode(payload_part)
        signature = _b64url_decode(signature_part)
    except ValueError as exc:
        raise ValueError("Invalid family-card signature token.") from exc

    try:
        _public_key().verify(signature, payload_bytes)
    except InvalidSignature as exc:
        raise ValueError("Invalid family-card signature.") from exc

    if len(payload_bytes) == COMPACT_TOKEN_SIZE:
        try:
            version, issued_at, family_ref, digest, no_kk_last4 = struct.unpack(
                COMPACT_TOKEN_FORMAT,
                payload_bytes,
            )
            payload = {
                "alg": "Ed25519",
                "digest": digest.hex(),
                "family_ref": family_ref.hex(),
                "issued_at": datetime.fromtimestamp(
                    issued_at,
                    tz=datetime_timezone.utc,
                ).isoformat(),
                "no_kk_last4": no_kk_last4.decode("ascii"),
                "v": version,
            }
        except (ValueError, UnicodeDecodeError, struct.error) as exc:
            raise ValueError("Invalid family-card signature payload.") from exc
    else:
        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Invalid family-card signature payload.") from exc

    required = {"alg", "digest", "family_ref", "issued_at", "no_kk_last4", "v"}
    if (
        set(payload) != required
        or payload.get("alg") != "Ed25519"
        or payload.get("v") not in (1, 2)
        or len(payload.get("digest", "")) != 64
        or len(payload.get("family_ref", "")) != 24
        or len(payload.get("no_kk_last4", "")) != 4
        or not payload.get("no_kk_last4", "").isdigit()
    ):
        raise ValueError("Invalid family-card signature payload.")
    return payload


def qr_code_data_uri(value):
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=4,
        border=3,
    )
    qr.add_data(value)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white")
    output = io.BytesIO()
    image.save(output, format="PNG")
    encoded = base64.b64encode(output.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"
