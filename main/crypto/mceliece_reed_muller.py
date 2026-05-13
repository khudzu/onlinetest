"""
Educational McEliece cryptosystem using first-order Reed-Muller codes.

This module is meant for learning and experimentation. It is not suitable for
production cryptography.
"""

from dataclasses import dataclass

import numpy as np


@dataclass(frozen=True)
class McEliecePublicKey:
    generator: np.ndarray
    error_weight: int
    m: int


@dataclass(frozen=True)
class McEliecePrivateKey:
    public_key: McEliecePublicKey
    reed_muller_generator: np.ndarray
    scramble_inverse: np.ndarray
    permutation_inverse: np.ndarray
    codebook_messages: np.ndarray
    codebook_words: np.ndarray


def _as_binary_vector(values, length=None):
    vector = np.asarray(values, dtype=np.uint8).reshape(-1) % 2
    if length is not None and vector.size != length:
        raise ValueError(f"Expected {length} bits, got {vector.size}.")
    return vector


def _random_binary_matrix(rows, cols, rng):
    return rng.integers(0, 2, size=(rows, cols), dtype=np.uint8)


def _identity(size):
    return np.eye(size, dtype=np.uint8)


def _rank_binary(matrix):
    matrix = np.array(matrix, dtype=np.uint8, copy=True) % 2
    rows, cols = matrix.shape
    rank = 0

    for col in range(cols):
        pivot = None
        for row in range(rank, rows):
            if matrix[row, col]:
                pivot = row
                break

        if pivot is None:
            continue

        if pivot != rank:
            matrix[[rank, pivot]] = matrix[[pivot, rank]]

        for row in range(rows):
            if row != rank and matrix[row, col]:
                matrix[row] ^= matrix[rank]

        rank += 1
        if rank == rows:
            break

    return rank


def _inverse_binary_matrix(matrix):
    matrix = np.array(matrix, dtype=np.uint8, copy=True) % 2
    rows, cols = matrix.shape
    if rows != cols:
        raise ValueError("Only square matrices can be inverted.")

    augmented = np.concatenate([matrix, _identity(rows)], axis=1)
    rank = 0

    for col in range(cols):
        pivot = None
        for row in range(rank, rows):
            if augmented[row, col]:
                pivot = row
                break

        if pivot is None:
            continue

        if pivot != rank:
            augmented[[rank, pivot]] = augmented[[pivot, rank]]

        for row in range(rows):
            if row != rank and augmented[row, col]:
                augmented[row] ^= augmented[rank]

        rank += 1

    if rank != rows or not np.array_equal(augmented[:, :cols], _identity(rows)):
        raise ValueError("Matrix is not invertible over GF(2).")

    return augmented[:, cols:] % 2


def _random_invertible_binary_matrix(size, rng):
    while True:
        matrix = _random_binary_matrix(size, size, rng)
        if _rank_binary(matrix) == size:
            return matrix, _inverse_binary_matrix(matrix)


def reed_muller_generator(order_m):
    """
    Return a generator matrix for RM(1, m).

    RM(1, m) has length n = 2**m and dimension k = m + 1.
    """

    if order_m < 3:
        raise ValueError("Use m >= 3 so the code can correct at least one error.")

    n = 2**order_m
    points = np.array(
        [[(index >> bit) & 1 for index in range(n)] for bit in range(order_m)],
        dtype=np.uint8,
    )
    constant = np.ones((1, n), dtype=np.uint8)
    return np.concatenate([constant, points], axis=0)


def _build_codebook(generator):
    k = generator.shape[0]
    messages = np.array(
        [[(value >> bit) & 1 for bit in range(k)] for value in range(2**k)],
        dtype=np.uint8,
    )
    words = (messages @ generator) % 2
    return messages, words.astype(np.uint8)


def _decode_reed_muller_first_order(received, codebook_messages, codebook_words):
    distances = np.count_nonzero(codebook_words ^ received, axis=1)
    best_index = int(np.argmin(distances))
    return codebook_messages[best_index], codebook_words[best_index], int(distances[best_index])


def generate_keypair(order_m=4, error_weight=None, seed=None):
    """
    Generate a toy McEliece keypair using RM(1, m).

    For RM(1, m), the usual correction bound is t = 2**(m - 2) - 1.
    """

    rng = np.random.default_rng(seed)
    g = reed_muller_generator(order_m)
    k, n = g.shape
    max_error_weight = 2 ** (order_m - 2) - 1

    if error_weight is None:
        error_weight = max_error_weight
    if error_weight < 0 or error_weight > max_error_weight:
        raise ValueError(f"error_weight must be between 0 and {max_error_weight}.")

    scramble, scramble_inverse = _random_invertible_binary_matrix(k, rng)
    permutation = rng.permutation(n)
    permutation_inverse = np.argsort(permutation)

    public_generator = ((scramble @ g) % 2)[:, permutation]
    messages, words = _build_codebook(g)
    public_key = McEliecePublicKey(
        generator=public_generator.astype(np.uint8),
        error_weight=error_weight,
        m=order_m,
    )

    private_key = McEliecePrivateKey(
        public_key=public_key,
        reed_muller_generator=g,
        scramble_inverse=scramble_inverse,
        permutation_inverse=permutation_inverse,
        codebook_messages=messages,
        codebook_words=words,
    )
    return public_key, private_key


def encrypt_bits(message_bits, public_key, seed=None):
    """Encrypt one k-bit message block and return an n-bit ciphertext."""

    rng = np.random.default_rng(seed)
    generator = public_key.generator
    k, n = generator.shape
    message = _as_binary_vector(message_bits, length=k)

    ciphertext = (message @ generator) % 2
    if public_key.error_weight:
        error_positions = rng.choice(n, public_key.error_weight, replace=False)
        ciphertext[error_positions] ^= 1

    return ciphertext.astype(np.uint8)


def decrypt_bits(ciphertext_bits, private_key):
    """Decrypt one n-bit ciphertext block and return the original k-bit message."""

    public_key = private_key.public_key
    k, n = public_key.generator.shape
    ciphertext = _as_binary_vector(ciphertext_bits, length=n)

    unpermuted = ciphertext[private_key.permutation_inverse]
    scrambled_message, _, _ = _decode_reed_muller_first_order(
        unpermuted,
        private_key.codebook_messages,
        private_key.codebook_words,
    )
    message = (scrambled_message @ private_key.scramble_inverse) % 2
    return message.astype(np.uint8)


def bytes_to_bits(data):
    byte_array = np.frombuffer(data, dtype=np.uint8)
    return np.unpackbits(byte_array, bitorder="big")


def bits_to_bytes(bits):
    bits = _as_binary_vector(bits)
    if bits.size % 8:
        padding = 8 - (bits.size % 8)
        bits = np.pad(bits, (0, padding))
    return np.packbits(bits, bitorder="big").tobytes()


def encrypt_bytes(data, public_key, seed=None):
    """
    Encrypt bytes as a list of ciphertext blocks.

    The returned padding count is needed to recover the exact original bytes.
    """

    bits = bytes_to_bits(data)
    k = public_key.generator.shape[0]
    padding = (-bits.size) % k
    if padding:
        bits = np.pad(bits, (0, padding))

    rng = np.random.default_rng(seed)
    blocks = []
    for offset in range(0, bits.size, k):
        block_seed = int(rng.integers(0, 2**32 - 1))
        blocks.append(encrypt_bits(bits[offset : offset + k], public_key, seed=block_seed))

    return blocks, padding


def decrypt_bytes(ciphertext_blocks, private_key, padding=0):
    decrypted_blocks = [decrypt_bits(block, private_key) for block in ciphertext_blocks]
    if not decrypted_blocks:
        return b""

    bits = np.concatenate(decrypted_blocks)
    if padding:
        bits = bits[:-padding]

    return bits_to_bytes(bits)
