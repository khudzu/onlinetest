import io
import json
import os
import statistics
import time

import numpy as np
from PIL import Image
from django.conf import settings

from main.crypto.aes_hqc import (
    SCHEME,
    _algorithm as hqc_algorithm,
    unwrap_aes_key as unwrap_hqc_key,
    wrap_aes_key as wrap_hqc_key,
)
from main.crypto.aes_reed_muller import (
    decrypt_image_bytes,
    decrypt_text,
    encrypt_image_bytes,
    encrypt_text,
    generate_aes_key,
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
    return float(np.percentile(values, p, method="linear"))


def summarize(values):
    return {
        "mean_ms": statistics.mean(values),
        "stddev_ms": statistics.stdev(values) if len(values) > 1 else 0.0,
        "median_ms": statistics.median(values),
        "p95_ms": percentile(values, 95),
        "min_ms": min(values),
        "max_ms": max(values),
        "observations_ms": values,
    }


def build_dummy_image(seed):
    rng = np.random.default_rng(seed)
    pixels = rng.integers(0, 256, size=(512, 512, 3), dtype=np.uint8)
    image = Image.fromarray(pixels, mode="RGB")
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def _wrap_hqc(aes_key, wrapping, repetition):
    labels = ("A",) if wrapping == "single" else ("A", "B")
    artifacts = {
        f"wrapped_DEK_{label}_{index}": wrap_hqc_key(aes_key, label)
        for label in labels
        for index in range(1, repetition + 1)
    }
    return json.dumps(
        {
            "scheme": f"{SCHEME}-{wrapping}-wrap-repetition",
            "kem": hqc_algorithm(),
            "repetition": repetition,
            "wrapping": wrapping,
            **artifacts,
        },
        separators=(",", ":"),
    )


def _unwrap_hqc(payload):
    data = json.loads(payload)
    recovered = []
    for label in (("A",) if data["wrapping"] == "single" else ("A", "B")):
        for index in range(1, data["repetition"] + 1):
            artifact = data.get(f"wrapped_DEK_{label}_{index}")
            if artifact:
                recovered.append(unwrap_hqc_key(artifact, label=label))
    if not recovered or any(key != recovered[0] for key in recovered[1:]):
        raise ValueError("Repeated HQC envelopes did not recover one consistent DEK.")
    return recovered[0]


def _two_sided_sign_flip(values, seed=20261123, permutations=20000):
    """Monte Carlo paired sign-flip test for a mean contrast."""
    if not values:
        return 1.0
    observed = abs(float(np.mean(values)))
    rng = np.random.default_rng(seed)
    samples = np.asarray(values, dtype=float)
    exceed = 0
    batch_size = 1000
    completed = 0
    while completed < permutations:
        count = min(batch_size, permutations - completed)
        signs = rng.choice(np.array([-1.0, 1.0]), size=(count, len(samples)))
        exceed += int(np.count_nonzero(np.abs((signs * samples).mean(axis=1)) >= observed))
        completed += count
    return (exceed + 1) / (permutations + 1)


def _bootstrap_ci(values, seed, resamples=20000):
    rng = np.random.default_rng(seed)
    values = np.asarray(values, dtype=float)
    means = np.empty(resamples, dtype=float)
    for start in range(0, resamples, 1000):
        count = min(1000, resamples - start)
        sampled = rng.choice(values, size=(count, len(values)), replace=True)
        means[start:start + count] = sampled.mean(axis=1)
    low, high = np.percentile(means, [2.5, 97.5])
    return [float(low), float(high)]


def _paired_factor_tests(results, metric):
    rows = {row["configuration"]: row[metric]["observations_ms"] for row in results}
    pairs = min(len(values) for values in rows.values())
    t1, t2, t3, t4 = (rows[name][:pairs] for name, _, _ in CONFIGURATIONS)
    contrasts = {
        "repetition_main_effect": [((b - a) + (d - c)) / 2 for a, b, c, d in zip(t1, t2, t3, t4)],
        "double_wrap_main_effect": [((c - a) + (d - b)) / 2 for a, b, c, d in zip(t1, t2, t3, t4)],
        "interaction": [(d - c) - (b - a) for a, b, c, d in zip(t1, t2, t3, t4)],
    }
    return {
        name: {
            "mean_effect_ms": float(np.mean(values)),
            "ci95_bootstrap_ms": _bootstrap_ci(values, seed=20261201 + index),
            "p_value_sign_flip": _two_sided_sign_flip(values, seed=20261123 + index),
            "n_independent_blocks": len(values),
        }
        for index, (name, values) in enumerate(contrasts.items())
    }


def _holm_adjust(p_values):
    ordered = sorted(p_values.items(), key=lambda item: item[1])
    adjusted = {}
    running_max = 0.0
    count = len(ordered)
    for rank, (name, p_value) in enumerate(ordered):
        running_max = max(running_max, min(1.0, (count - rank) * p_value))
        adjusted[name] = running_max
    return adjusted


def run_configuration(name, wrapping, repetition, sample_size, owner, sample_offset=0):
    insert_crypto_ms, insert_db_ms, insert_total_ms = [], [], []
    select_db_ms, decrypt_ms, select_total_ms, storage_bytes = [], [], [], []
    created_ids = []

    try:
        for index in range(sample_offset, sample_offset + sample_size):
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
            wrapped_key = _wrap_hqc(aes_key, wrapping, repetition)
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
                sum(len(value.encode("utf-8")) for value in (
                    encrypted_name, encrypted_nik, encrypted_alamat,
                    encrypted_password, encrypted_image, wrapped_key,
                ))
            )

        for record_id in created_ids:
            total_start = time.perf_counter()
            db_start = time.perf_counter()
            record = PostModel.objects.get(id=record_id)
            select_db_ms.append((time.perf_counter() - db_start) * 1000)

            decrypt_start = time.perf_counter()
            aes_key = _unwrap_hqc(record.aes_key)
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
    rng = np.random.default_rng(20261123)
    results_by_configuration = {name: [] for name, _, _ in CONFIGURATIONS}
    for block in range(sample_size):
        order = rng.permutation(len(CONFIGURATIONS))
        for config_index in order:
            name, wrapping, repetition = CONFIGURATIONS[int(config_index)]
            result = run_configuration(
                name, wrapping, repetition, 1, owner, sample_offset=block
            )
            results_by_configuration[name].append(result)

    metrics = ("insert_crypto", "insert_db", "insert_total", "select_db", "decrypt", "select_total")
    results = []
    for name, wrapping, repetition in CONFIGURATIONS:
        blocks = results_by_configuration[name]
        row = {
            "configuration": name,
            "wrapping": wrapping,
            "repetition": repetition,
            "sample_size": sample_size,
        }
        for metric in metrics:
            observations = [item for block in blocks for item in block[metric]["observations_ms"]]
            row[metric] = summarize(observations)
        stored_sizes = [block["storage_mean_bytes"] for block in blocks]
        row["storage_mean_bytes"] = statistics.mean(stored_sizes)
        row["storage_p95_bytes"] = percentile(stored_sizes, 95)
        results.append(row)
    tests = {metric: _paired_factor_tests(results, metric) for metric in metrics}
    all_p_values = {
        f"{metric}.{effect}": result["p_value_sign_flip"]
        for metric, effects in tests.items()
        for effect, result in effects.items()
    }
    adjusted = _holm_adjust(all_p_values)
    for metric, effects in tests.items():
        for effect, result in effects.items():
            result["p_value_holm_18_tests"] = adjusted[f"{metric}.{effect}"]
    return {
        "environment": {
            "database_engine": settings.DATABASES["default"]["ENGINE"],
            "kem": hqc_algorithm(),
            "implementation": getattr(settings, "HQC_IMPLEMENTATION_VERSION", None)
            or os.environ.get("HQC_IMPLEMENTATION_VERSION"),
            "sample_size_per_configuration": sample_size,
            "design": f"2x2 factorial; {sample_size} randomized complete blocks; 1 or 3 HQC envelopes per recipient",
            "image_workload": "synthetic 512x512 RGB PNG; not a natural-image benchmark dataset",
            "total_runtime_ms": (time.perf_counter() - started_at) * 1000,
            "statistical_method": "paired block sign-flip tests; percentile bootstrap 95% CIs; Holm correction across 18 tests",
            "warning": "One Railway deployment/session; report as supplementary deployment evidence, not as a substitute for controlled repeated sessions.",
        },
        "results": results,
        "factorial_tests": tests,
    }
