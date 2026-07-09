"""Stegano-Cipher package: LSB steganography with AES-256.

Modules:
- crypto: AES-256-GCM password-based encryption/decryption
- image_utils: RGB conversion
- embedder: LSB-based embedding and extraction
- cli: command-line interface (hide/extract)
"""

__all__ = [
    "crypto",
    "image_utils",
    "adaptive_embed",
    "embedder",
]