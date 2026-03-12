from __future__ import annotations

from pathlib import Path
import numpy as np
from PIL import Image


def main(out_path: Path):
    h, w = 1024, 682
    # Base orange gradient (sunset-like)
    y = np.linspace(0, 1, h, dtype=np.float32)[:, None]
    x = np.linspace(0, 1, w, dtype=np.float32)[None, :]
    grad = (0.9 * (1 - y) + 0.1).astype(np.float32)  # top brighter

    # Add noise to increase local variance and embedding capacity
    rng = np.random.default_rng(42)
    noise = rng.normal(loc=0.0, scale=0.08, size=(h, w)).astype(np.float32)

    # Compose RGB with orange tint and slight vignette
    vignette = (0.85 + 0.15 * (x * (1 - x) + y * (1 - y))).astype(np.float32)
    base = np.clip(grad * vignette + noise, 0, 1)
    R = np.clip(1.0 * base, 0, 1)
    G = np.clip(0.45 * base, 0, 1)
    B = np.clip(0.1 * base, 0, 1)
    img = (np.stack([R, G, B], axis=2) * 255).astype(np.uint8)
    Image.fromarray(img, mode="RGB").save(out_path, format="JPEG", quality=92)


if __name__ == "__main__":
    out = Path("cover.jpg")
    main(out)
    print(f"Wrote {out.resolve()}")