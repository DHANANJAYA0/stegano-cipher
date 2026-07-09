import pytest
import numpy as np
from stegano_cipher.embedder import (
    bytes_to_bits,
    bits_to_bytes,
    embed_bits_lsb,
    extract_bits_lsb,
)

def test_embed_extract_lsb():
    rng = np.random.default_rng(42)
    R = rng.uniform(0, 255, (16, 16)).astype(np.float32)
    G = rng.uniform(0, 255, (16, 16)).astype(np.float32)
    B = rng.uniform(0, 255, (16, 16)).astype(np.float32)
    
    data = b"abc"
    bits = bytes_to_bits(data)
    
    R_stego, G_stego, B_stego = embed_bits_lsb(R, G, B, bits.copy())
    
    recovered_bits = extract_bits_lsb(R_stego, G_stego, B_stego, len(bits))
    recovered_data = bits_to_bytes(recovered_bits)
    
    assert recovered_data == data
