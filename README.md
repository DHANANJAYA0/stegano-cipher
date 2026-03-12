# Stegano-Cipher: Adaptive DCT Steganography with AES-256

This project hides an AES-256 encrypted message inside an image by embedding bits in mid-frequency Discrete Cosine Transform (DCT) coefficients of adaptively selected image blocks and color channels (YCbCr). It aims for robustness against JPEG compression and resistance to simple steganalysis.

## Features

- AES-256-GCM authenticated encryption for confidentiality and integrity
- Adaptive block and channel selection based on local variance (complexity)
- Frequency-domain embedding using Quantization Index Modulation (QIM) on mid-frequency DCT coefficients
- CLI commands to hide and extract messages

## Install

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

### Hide a message

```bash
python -m stegano_cipher.cli hide \
  --in cover.jpg \
  --out stego.jpg \
  --message secret.txt \
  --password "your-strong-pass" \
  --quality 92 \
  --delta 2.0
```

### Extract a message

```bash
python -m stegano_cipher.cli extract \
  --in stego.jpg \
  --out recovered.txt \
  --password "your-strong-pass" \
  --delta 2.0
```

## Notes on Robustness

- Embedding occurs in the DCT domain aligned with 8×8 blocks and YCbCr channels. Saving as JPEG recompresses the image; QIM with a suitable `delta` step helps preserve parity under quantization.
- For maximum robustness, manipulating JPEG quantized DCT coefficients directly (e.g., via specialized libraries) would be even stronger. This prototype focuses on practicality with common Python stacks.

## Limitations & Future Work

- Current approach relies on variance-based selection; more advanced detectors (e.g., texture/edge models) could improve undetectability.
- Direct JPEG coefficient manipulation and channel-specific capacity planning could improve robustness.
- Add unit tests and benchmarking (BER vs. JPEG quality), and optional error-correcting codes.