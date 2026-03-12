from __future__ import annotations

import click
import numpy as np

from .crypto import encrypt_bytes, decrypt_bytes
from .image_utils import load_image_rgb, save_image_rgb
from .embedder import bytes_to_bits, bits_to_bytes, embed_bits_lsb, extract_bits_lsb


@click.group()
def cli():
    """Stegano-Cipher CLI: hide/extract encrypted messages in images."""


@cli.command()
@click.option("--in", "in_path", required=True, help="Input cover image (JPEG/PNG)")
@click.option("--out", "out_path", required=True, help="Output stego image (JPEG)")
@click.option("--message", "message_path", required=True, help="Plaintext file containing the secret message")
@click.option("--password", required=True, help="Password for AES-256-GCM encryption")
@click.option("--delta", type=float, default=2.0, show_default=True, help="QIM step size controlling robustness")
@click.option("--quality", type=int, default=92, show_default=True, help="Output JPEG quality")
def hide(in_path: str, out_path: str, message_path: str, password: str, delta: float, quality: int):
    """Encrypt and hide a message inside an image using adaptive DCT embedding."""
    with open(message_path, "rb") as f:
        plaintext = f.read()
    blob = encrypt_bytes(password, plaintext)
    length = len(blob)
    header = length.to_bytes(4, "big")
    header_bits = bytes_to_bits(header)
    header_reps = 8
    payload_reps = 3
    payload_bits = bytes_to_bits(blob)
    bits = [b for b in header_bits for _ in range(header_reps)] + [b for b in payload_bits for _ in range(payload_reps)]

    R, G, B = load_image_rgb(in_path)
    R2, G2, B2 = embed_bits_lsb(R, G, B, bits)
    save_image_rgb(out_path, R2, G2, B2, quality=quality)
    click.echo(f"Stego image saved to: {out_path}")


@cli.command()
@click.option("--in", "in_path", required=True, help="Input stego image (JPEG)")
@click.option("--out", "out_path", required=True, help="Output recovered plaintext file")
@click.option("--password", required=True, help="Password for AES-256-GCM decryption")
@click.option("--delta", type=float, default=2.0, show_default=True, help="QIM step size used during embedding")
def extract(in_path: str, out_path: str, password: str, delta: float):
    """Extract and decrypt a hidden message from an image."""
    R, G, B = load_image_rgb(in_path)

    header_reps = 8
    raw_header_bits = extract_bits_lsb(R, G, B, bit_count=32 * header_reps)
    voted_header_bits = []
    for i in range(0, 32 * header_reps, header_reps):
        group = raw_header_bits[i:i+header_reps]
        bit = 1 if sum(group) >= (header_reps // 2 + 1) else 0
        voted_header_bits.append(bit)
    header_bytes = bits_to_bytes(voted_header_bits)
    if len(header_bytes) < 4:
        raise click.ClickException("Failed to recover length header.")
    length = int.from_bytes(header_bytes[:4], "big")

    payload_reps = 3
    raw_payload_bits = extract_bits_lsb(R, G, B, bit_count=32 * header_reps + length * 8 * payload_reps)[32 * header_reps:]
    voted_payload_bits = []
    for i in range(0, len(raw_payload_bits), payload_reps):
        grp = raw_payload_bits[i:i+payload_reps]
        if len(grp) < payload_reps:
            break
        bit = 1 if sum(grp) >= (payload_reps // 2 + 1) else 0
        voted_payload_bits.append(bit)
    payload_bytes = bits_to_bytes(voted_payload_bits[:length * 8])

    try:
        plaintext = decrypt_bytes(password, payload_bytes)
    except Exception as e:
        raise click.ClickException(f"Decryption failed: {e}")

    with open(out_path, "wb") as f:
        f.write(plaintext)
    click.echo(f"Recovered plaintext saved to: {out_path}")


if __name__ == "__main__":
    cli()