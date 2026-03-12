"""Stegano-Cipher package: adaptive DCT steganography with AES-256.

Modules:
- crypto: AES-256-GCM password-based encryption/decryption
- image_utils: YCbCr conversion, 8x8 block ops, DCT/IDCT, masks
- adaptive_embed: variance-based adaptive selection of blocks/channels
- embedder: QIM-based embedding and extraction in mid-frequency DCT coeffs
- cli: command-line interface (hide/extract)
"""

__all__ = [
    "crypto",
    "image_utils",
    "adaptive_embed",
    "embedder",
]