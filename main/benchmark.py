import json
import statistics
import time

import numpy as np
from django.conf import settings

from main.crypto.aes_reed_muller import (
    decrypt_image_bytes,
    decrypt_text,
    encrypt_image_bytes,
    encrypt_text,
    generate_aes_key,
    unwrap_aes_key,
    wrap_aes_key,
    wrap_aes_key_double,
)
from main.models import PostModel


CONFIGURATIONS = [
    ("T1_single_no_repetition", "single", 1),
    ("T2_single_repetition_3", "single", 3),
    ("T3_double_no_repetition", "double", 1),
    ("T4_double_repetition_3", "double", 3),
]


def percentile(values, p):
    if not values:
        return 0.0
    ordered = sorted(values)
    index = int(round((len(ordered) - 1) * (p / 100)))
    return ordered[index]


def summarize(values):
    return {
        "mean_ms": statistics.mean(values),
        "median_ms": statistics.median(values),
        "p95_ms": percentile(values, 95),
        "min_ms": min(values),
        "max_ms": max(values),
    }


def build_dummy_image(seed):
    rng = np.random.default_rng(seed)
    return rng.integers(0, 256, size=4096, dtype=np.uint8).tobytes()


def wrap_key(aes_key, wrapping, repetition):
    if wrapping == "single" and repetition == 1:
        return wrap_aes_key(aes_key)
    if wrapping == "single":
        data = {
            "scheme": "single-wrap-repetition",
            "alg": "McEliece-RM(1,4)",
            "repetition": repetition,
        }
        for index in range(1, repetition + 1):
            data[f"wrapped_DEK_A_{index}"] = json.loads(wrap_aes_key(aes_key))
        return json.dumps(data, separators=(",", ":"))
    if wrapping == "double":
        return wrap_aes_key_double(aes_key, repetitions=repetition)
    raise ValueError(f"Unknown wrapping mode: {wrapping}")


def unwrap_key(payload):
    data = json.loads(payload)
    if data.get("scheme") == "single-wrap-repetition":
        errors = []
        for index in range(1, data.get("repetition", 3) + 1):
            wrapped = data.get(f"wrapped_DEK_A_{index}")
            if not wrapped:
                continue
            try:
                return unwrap_aes_key(json.dumps(wrapped, separators=(",", ":")))
            except Exception as exc:
                errors.append(str(exc))
        raise ValueError(f"Could not unwrap repeated single-wrap DEK: {errors}")
    return unwrap_aes_key(payload)


def run_configuration(name, wrapping, repetition, sample_size, owner):
    insert_crypto_ms = []
    insert_db_ms = []
    insert_total_ms = []
    select_db_ms = []
    decrypt_ms = []
    select_total_ms = []
    storage_bytes = []
    created_ids = []

    try:
        for index in range(sample_size):
            nama = f"BENCHMARK:Nama {index:04d}"
            nik = f"3507{index:012d}"
            alamat = f"Jalan Benchmark Nomor {index}, Kota Uji"
            password = f"pw-{index:04d}"
            image_bytes = build_dummy_image(index)

            total_start = time.perf_counter()
            crypto_start = time.perf_counter()
            aes_key = generate_aes_key()
            encrypted_name = encrypt_text(nama, aes_key)
            encrypted_nik = encrypt_text(nik, aes_key)
            encrypted_alamat = encrypt_text(alamat, aes_key)
            encrypted_password = encrypt_text(password, aes_key)
            encrypted_image = encrypt_image_bytes(image_bytes, aes_key).decode("utf-8")
            wrapped_key = wrap_key(aes_key, wrapping, repetition)
            insert_crypto_ms.append((time.perf_counter() - crypto_start) * 1000)

            db_start = time.perf_counter()
            record = PostModel.objects.create(
                owner=owner,
                Nama=encrypted_name,
                Password=encrypted_password,
                NIK=encrypted_nik,
                Alamat=encrypted_alamat,
                image=f"benchmark-{name}-{index}.aes",
                image_ciphertext=encrypted_image,
                aes_key=wrapped_key,
            )
            insert_db_ms.append((time.perf_counter() - db_start) * 1000)
            insert_total_ms.append((time.perf_counter() - total_start) * 1000)
            created_ids.append(record.id)
            storage_bytes.append(
                sum(
                    len(value.encode("utf-8"))
                    for value in [
                        encrypted_name,
                        encrypted_nik,
                        encrypted_alamat,
                        encrypted_password,
                        encrypted_image,
                        wrapped_key,
                    ]
                )
            )

        for record_id in created_ids:
            total_start = time.perf_counter()
            db_start = time.perf_counter()
            record = PostModel.objects.get(id=record_id)
            select_db_ms.append((time.perf_counter() - db_start) * 1000)

            decrypt_start = time.perf_counter()
            aes_key = unwrap_key(record.aes_key)
            decrypt_text(record.Nama, aes_key)
            decrypt_text(record.NIK, aes_key)
            decrypt_text(record.Alamat, aes_key)
            decrypt_text(record.Password, aes_key)
            decrypt_image_bytes(record.image_ciphertext.encode("utf-8"), aes_key)
            decrypt_ms.append((time.perf_counter() - decrypt_start) * 1000)
            select_total_ms.append((time.perf_counter() - total_start) * 1000)

        return {
            "configuration": name,
            "wrapping": wrapping,
            "repetition": repetition,
            "sample_size": sample_size,
            "insert_crypto": summarize(insert_crypto_ms),
            "insert_db": summarize(insert_db_ms),
            "insert_total": summarize(insert_total_ms),
            "select_db": summarize(select_db_ms),
            "decrypt": summarize(decrypt_ms),
            "select_total": summarize(select_total_ms),
            "storage_mean_bytes": statistics.mean(storage_bytes),
            "storage_p95_bytes": percentile(storage_bytes, 95),
        }
    finally:
        if created_ids:
            PostModel.objects.filter(id__in=created_ids).delete()


def run_wrapping_benchmark(sample_size, owner):
    started_at = time.perf_counter()
    results = [
        run_configuration(name, wrapping, repetition, sample_size, owner)
        for name, wrapping, repetition in CONFIGURATIONS
    ]
    return {
        "environment": {
            "database_engine": settings.DATABASES["default"]["ENGINE"],
            "sample_size_per_configuration": sample_size,
            "total_runtime_ms": (time.perf_counter() - started_at) * 1000,
        },
        "results": results,
    }
