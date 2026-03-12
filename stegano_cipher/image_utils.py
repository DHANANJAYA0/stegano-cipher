from __future__ import annotations

from typing import List, Tuple

import numpy as np
from PIL import Image
import os
import cv2


Block = Tuple[int, int]  # (row_block_index, col_block_index)


def load_image_ycbcr(path: str) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Load image and return Y, Cb, Cr channels as float32 arrays in range [0,255]."""
    img = Image.open(path).convert("YCbCr")
    arr = np.array(img, dtype=np.float32)
    Y = arr[:, :, 0]
    Cb = arr[:, :, 1]
    Cr = arr[:, :, 2]
    return Y, Cb, Cr


def save_image_ycbcr(path: str, Y: np.ndarray, Cb: np.ndarray, Cr: np.ndarray, quality: int = 92) -> None:
    """Save Y, Cb, Cr channels as an image.

    If `path` ends with .png, saves lossless PNG. Otherwise saves JPEG with given quality.
    """
    Y = np.clip(Y, 0, 255).astype(np.uint8)
    Cb = np.clip(Cb, 0, 255).astype(np.uint8)
    Cr = np.clip(Cr, 0, 255).astype(np.uint8)
    arr = np.stack([Y, Cb, Cr], axis=2)
    img = Image.fromarray(arr, mode="YCbCr").convert("RGB")
    ext = os.path.splitext(path)[1].lower()
    if ext == ".png":
        img.save(path, format="PNG")
    else:
        img.save(path, format="JPEG", quality=quality)


def load_image_rgb(path: str) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    img = Image.open(path).convert("RGB")
    arr = np.array(img, dtype=np.float32)
    R = arr[:, :, 0]
    G = arr[:, :, 1]
    B = arr[:, :, 2]
    return R, G, B


def save_image_rgb(path: str, R: np.ndarray, G: np.ndarray, B: np.ndarray, quality: int = 92) -> None:
    R = np.clip(R, 0, 255).astype(np.uint8)
    G = np.clip(G, 0, 255).astype(np.uint8)
    B = np.clip(B, 0, 255).astype(np.uint8)
    arr = np.stack([R, G, B], axis=2)
    img = Image.fromarray(arr, mode="RGB")
    ext = os.path.splitext(path)[1].lower()
    if ext == ".png":
        img.save(path, format="PNG")
    else:
        img.save(path, format="JPEG", quality=quality)


def pad_to_block_multiple(channel: np.ndarray, block_size: int = 8) -> Tuple[np.ndarray, Tuple[int, int]]:
    h, w = channel.shape
    H = (h + block_size - 1) // block_size * block_size
    W = (w + block_size - 1) // block_size * block_size
    padded = np.zeros((H, W), dtype=np.float32)
    padded[:h, :w] = channel
    return padded, (h, w)


def split_blocks(channel: np.ndarray, block_size: int = 8) -> List[Tuple[Block, np.ndarray]]:
    H, W = channel.shape
    blocks: List[Tuple[Block, np.ndarray]] = []
    for i in range(0, H, block_size):
        for j in range(0, W, block_size):
            blocks.append(((i // block_size, j // block_size), channel[i:i+block_size, j:j+block_size]))
    return blocks


def merge_blocks(shape: Tuple[int, int], blocks: List[Tuple[Block, np.ndarray]], block_size: int = 8) -> np.ndarray:
    H, W = shape
    out = np.zeros((H, W), dtype=np.float32)
    for (bi, bj), blk in blocks:
        i = bi * block_size
        j = bj * block_size
        out[i:i+block_size, j:j+block_size] = blk
    return out


def dct2(block: np.ndarray) -> np.ndarray:
    return cv2.dct(block.astype(np.float32))


def idct2(coeffs: np.ndarray) -> np.ndarray:
    return cv2.idct(coeffs.astype(np.float32))


def mid_frequency_mask(block_size: int = 8) -> np.ndarray:
    """Return a boolean mask selecting mid-frequency coefficients in an NxN DCT block.

    Excludes DC (0,0) and the highest frequencies. Uses simple band selection by (i+j).
    """
    mask = np.zeros((block_size, block_size), dtype=bool)
    for i in range(block_size):
        for j in range(block_size):
            if i == 0 and j == 0:
                continue
            s = i + j
            if 3 <= s <= 6:
                mask[i, j] = True
    return mask


def block_variance(block: np.ndarray) -> float:
    return float(np.var(block))