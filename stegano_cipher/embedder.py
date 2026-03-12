from __future__ import annotations

from typing import List, Tuple

import numpy as np

from .image_utils import (
    pad_to_block_multiple,
    split_blocks,
    merge_blocks,
    dct2,
    idct2,
    mid_frequency_mask,
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


def _embed_bits_in_coeffs(coeffs: np.ndarray, mask: np.ndarray, bits: List[int], delta: float) -> Tuple[np.ndarray, List[int]]:
    coeffs = coeffs.copy()
    coords = list(zip(*np.where(mask)))
    for (i, j) in coords:
        if not bits:
            break
        c = float(coeffs[i, j])
        k = int(round(c / delta))
        b = bits.pop(0)
        k_even = 2 * ((k + 1) // 2) if k % 2 != 0 else k  # nearest even index
        k_odd = k_even + 1
        k_prime = k_even if b == 0 else k_odd
        coeffs[i, j] = k_prime * delta
    return coeffs, bits


def _decode_bits_from_coeffs(coeffs: np.ndarray, mask: np.ndarray, count: int, delta: float) -> List[int]:
    bits: List[int] = []
    coords = list(zip(*np.where(mask)))
    for (i, j) in coords:
        if len(bits) >= count:
            break
        c = float(coeffs[i, j])
        k_real = c / delta
        k_even = 2 * int(round(k_real / 2.0))
        k_odd_a = k_even - 1
        k_odd_b = k_even + 1
        dist_even = abs(k_real - k_even)
        dist_odd = min(abs(k_real - k_odd_a), abs(k_real - k_odd_b))
        bits.append(1 if dist_odd < dist_even else 0)
    return bits


def embed_bits(Y: np.ndarray, Cb: np.ndarray, Cr: np.ndarray, bits: List[int], delta: float = 2.0) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    if not bits:
        return Y, Cb, Cr

    block_size = 8
    mask = mid_frequency_mask(block_size)

    Y_pad, orig_shape_Y = pad_to_block_multiple(Y, block_size)
    Cb_pad, _ = pad_to_block_multiple(Cb, block_size)
    Cr_pad, _ = pad_to_block_multiple(Cr, block_size)

    Y_blocks = dict(split_blocks(Y_pad, block_size))
    Cb_blocks = dict(split_blocks(Cb_pad, block_size))
    Cr_blocks = dict(split_blocks(Cr_pad, block_size))

    coords = sorted(Y_blocks.keys())

    for (bi, bj) in coords:
        if not bits:
            break
        blk = Y_blocks[(bi, bj)]
        c = dct2(blk)
        c, bits = _embed_bits_in_coeffs(c, mask, bits, delta)
        Y_blocks[(bi, bj)] = idct2(c)

    if bits:
        for (bi, bj) in coords:
            if not bits:
                break
            blk = Cb_blocks[(bi, bj)]
            c = dct2(blk)
            c, bits = _embed_bits_in_coeffs(c, mask, bits, delta)
            Cb_blocks[(bi, bj)] = idct2(c)

    if bits:
        for (bi, bj) in coords:
            if not bits:
                break
            blk = Cr_blocks[(bi, bj)]
            c = dct2(blk)
            c, bits = _embed_bits_in_coeffs(c, mask, bits, delta)
            Cr_blocks[(bi, bj)] = idct2(c)

    Y_out = merge_blocks(Y_pad.shape, list(Y_blocks.items()), block_size)[:orig_shape_Y[0], :orig_shape_Y[1]]
    Cb_out = merge_blocks(Cb_pad.shape, list(Cb_blocks.items()), block_size)[:orig_shape_Y[0], :orig_shape_Y[1]]
    Cr_out = merge_blocks(Cr_pad.shape, list(Cr_blocks.items()), block_size)[:orig_shape_Y[0], :orig_shape_Y[1]]
    return Y_out, Cb_out, Cr_out


def extract_bits(Y: np.ndarray, Cb: np.ndarray, Cr: np.ndarray, bit_count: int, delta: float = 2.0) -> List[int]:
    if bit_count <= 0:
        return []

    block_size = 8
    mask = mid_frequency_mask(block_size)

    Y_pad, _ = pad_to_block_multiple(Y, block_size)
    Cb_pad, _ = pad_to_block_multiple(Cb, block_size)
    Cr_pad, _ = pad_to_block_multiple(Cr, block_size)

    Y_blocks = dict(split_blocks(Y_pad, block_size))
    Cb_blocks = dict(split_blocks(Cb_pad, block_size))
    Cr_blocks = dict(split_blocks(Cr_pad, block_size))

    coords = sorted(Y_blocks.keys())

    out_bits: List[int] = []
    for (bi, bj) in coords:
        if len(out_bits) >= bit_count:
            break
        blk = Y_blocks[(bi, bj)]
        c = dct2(blk)
        out_bits.extend(_decode_bits_from_coeffs(c, mask, bit_count - len(out_bits), delta))

    for (bi, bj) in coords:
        if len(out_bits) >= bit_count:
            break
        blk = Cb_blocks[(bi, bj)]
        c = dct2(blk)
        out_bits.extend(_decode_bits_from_coeffs(c, mask, bit_count - len(out_bits), delta))

    for (bi, bj) in coords:
        if len(out_bits) >= bit_count:
            break
        blk = Cr_blocks[(bi, bj)]
        c = dct2(blk)
        out_bits.extend(_decode_bits_from_coeffs(c, mask, bit_count - len(out_bits), delta))

    return out_bits[:bit_count]


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
