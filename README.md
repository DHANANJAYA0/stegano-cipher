# Stegano-Cipher: Robust LSB Steganography with AES-256

This project hides an AES-256 encrypted message inside an image by embedding bits using a robust Least Significant Bit (LSB) methodology.

## Features

- AES-256-GCM authenticated encryption for confidentiality and integrity
- LSB spatial-domain embedding
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

- Embedding occurs directly into the RGB LSB layer of the image. Saving as a lossless format (PNG) is required to guarantee complete data retention without error-correction overhead.

## Limitations & Future Work

- Current approach is vulnerable to structural steganalysis that detects LSB disruptions.
- Advanced features like payload splitting could improve security.
- Add unit tests and benchmarking (BER vs. JPEG quality), and optional error-correcting codes.