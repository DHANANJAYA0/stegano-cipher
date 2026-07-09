from __future__ import annotations

from typing import List, Tuple

import numpy as np

from .image_utils import (
    pad_to_block_multiple,
    split_blocks,
    merge_blocks,
)


def bytes_to_bits(data: bytes) -> List[int]:
    bits: List[int] = []
    for b in data:
        for i in range(8)[::-1]:
            bits.append((b >> i) & 1)
    return bits


def bits_to_bytes(bits: List[int]) -> bytes:
    if len(bits) % 8 != 0:
        raise ValueError("Bit length not divisible by 8")
    out = bytearray()
    for i in range(0, len(bits), 8):
        val = 0
        for j in range(8):
            val = (val << 1) | (bits[i + j] & 1)
        out.append(val)
    return bytes(out)





def embed_bits_lsb(R: np.ndarray, G: np.ndarray, B: np.ndarray, bits: List[int]) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    if not bits:
        return R, G, B
    r = np.clip(R, 0, 255).astype(np.uint8)
    h, w = r.shape
    idx = 0
    for i in range(h):
        if idx >= len(bits):
            break
        row = r[i]
        for j in range(w):
            if idx >= len(bits):
                break
            b = bits[idx] & 1
            row[j] = (row[j] & 0xFE) | b
            idx += 1
        r[i] = row
    return r.astype(np.float32), G, B


def extract_bits_lsb(R: np.ndarray, G: np.ndarray, B: np.ndarray, bit_count: int) -> List[int]:
    if bit_count <= 0:
        return []
    r = np.clip(R, 0, 255).astype(np.uint8)
    h, w = r.shape
    bits: List[int] = []
    for i in range(h):
        if len(bits) >= bit_count:
            break
        row = r[i]
        for j in range(w):
            if len(bits) >= bit_count:
                break
            bits.append(int(row[j] & 1))
    return bits
