from __future__ import annotations

import io
from flask import Flask, render_template, request, send_file, jsonify, redirect, url_for, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os, sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from PIL import Image
import numpy as np

from stegano_cipher.crypto import encrypt_bytes, decrypt_bytes
from stegano_cipher.embedder import (
    bytes_to_bits,
    bits_to_bytes,
    embed_bits_lsb,
    extract_bits_lsb,
    embed_bits,
)
from stegano_cipher.image_utils import save_image_rgb, save_image_ycbcr


app = Flask(__name__)
app.secret_key = "dev-secret-key"

DB_PATH = os.path.join(os.path.dirname(__file__), "app.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            type TEXT NOT NULL,
            cover TEXT,
            stego TEXT,
            method TEXT,
            length INTEGER,
            time TEXT NOT NULL
        )
        """
    )
    try:
        conn.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
    except Exception:
        pass
    conn.commit()
    conn.close()

init_db()


def _img_to_rgb_arrays(file_bytes: bytes) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    img = Image.open(io.BytesIO(file_bytes)).convert("RGB")
    arr = np.array(img, dtype=np.float32)
    return arr[:, :, 0], arr[:, :, 1], arr[:, :, 2]


def _rgb_arrays_to_png_bytes(R: np.ndarray, G: np.ndarray, B: np.ndarray) -> bytes:
    import tempfile
    import os
    fd, path = tempfile.mkstemp(suffix=".png")
    os.close(fd)
    try:
        save_image_rgb(path, R, G, B, quality=95)
        with open(path, "rb") as f:
            return f.read()
    finally:
        try:
            os.remove(path)
        except Exception:
            pass


def _ycbcr_arrays_to_png_bytes(Y: np.ndarray, Cb: np.ndarray, Cr: np.ndarray) -> bytes:
    import tempfile
    import os
    fd, path = tempfile.mkstemp(suffix=".png")
    os.close(fd)
    try:
        save_image_ycbcr(path, Y, Cb, Cr, quality=95)
        with open(path, "rb") as f:
            return f.read()
    finally:
        try:
            os.remove(path)
        except Exception:
            pass


def _img_to_ycbcr_arrays(file_bytes: bytes) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    img = Image.open(io.BytesIO(file_bytes)).convert("YCbCr")
    arr = np.array(img, dtype=np.float32)
    return arr[:, :, 0], arr[:, :, 1], arr[:, :, 2]


def login_required(fn):
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper


@app.get("/login")
def login():
    if session.get("user"):
        return redirect(url_for("index"))
    return render_template("login.html")

@app.get("/")
def root():
    if session.get("user"):
        return redirect(url_for("index"))
    return redirect(url_for("login"))


@app.post("/login")
def do_login():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "").strip()
    if not name or not email or not password:
        return render_template("login.html", error="Provide name, email, password")
    conn = get_db()
    cur = conn.execute("SELECT name, email, password_hash, role FROM users WHERE email=?", (email,))
    row = cur.fetchone()
    if row:
        if not check_password_hash(row["password_hash"], password):
            conn.close()
            return render_template("login.html", error="Invalid credentials")
        session["user"] = {"name": row["name"], "email": row["email"], "role": row["role"] or "user"}
        conn.close()
    else:
        ph = generate_password_hash(password)
        role = "admin" if email in {"admin@local", "admin@example.com"} else "user"
        conn.execute("INSERT INTO users(email, name, password_hash, role) VALUES(?,?,?,?)", (email, name, ph, role))
        conn.commit()
        conn.close()
        session["user"] = {"name": name, "email": email, "role": role}
    return redirect(url_for("index"))


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/app")
@login_required
def index():
    return render_template("index.html", user=session.get("user"))


@app.post("/hide")
@login_required
def hide():
    cover = request.files.get("cover")
    password = request.form.get("password", "")
    text = request.form.get("text", "")
    method = request.form.get("method", "lsb")
    delta = float(request.form.get("delta", "2.0"))
    quality = int(request.form.get("quality", "92"))
    if not cover or not password or not text:
        return jsonify({"error": "missing inputs"}), 400
    if not (getattr(cover, "mimetype", "") or "").startswith("image/"):
        return jsonify({"error": "type"}), 415
    plaintext = text.encode("utf-8")
    blob = encrypt_bytes(password, plaintext)
    length = len(blob)
    header = length.to_bytes(4, "big")
    header_bits = bytes_to_bits(header)
    header_reps = 8
    payload_reps = 3
    payload_bits = bytes_to_bits(blob)
    bits = [b for b in header_bits for _ in range(header_reps)] + [b for b in payload_bits for _ in range(payload_reps)]
    data = cover.read()
    if len(data) > 25 * 1024 * 1024:
        return jsonify({"error": "size"}), 413
    out_format = (request.form.get("out_format", "png") or "png").lower()
    if out_format in ("jpeg", "jpg"):
        fmt = "JPEG"; ext = ".jpg"; mime = "image/jpeg"
        # Force high quality for JPEG steganography robustness
        quality = 100
        # Increase delta for robustness if user didn't request a very high one
        if delta < 5.0:
            delta = 5.0
    elif out_format == "webp":
        fmt = "WEBP"; ext = ".webp"; mime = "image/webp"
    else:
        fmt = "PNG"; ext = ".png"; mime = "image/png"
    if method == "lsb" and fmt != "PNG":
        method = "dct"
    buf = io.BytesIO()
    if method == "dct":
        if out_format in ("jpeg", "jpg"):
            deltas_to_try = [10.0, 15.0, 20.0, 25.0, 30.0, 40.0]
        else:
            deltas_to_try = [delta]

        final_buf = None

        for d in deltas_to_try:
            Y, Cb, Cr = _img_to_ycbcr_arrays(data)
            Y2, Cb2, Cr2 = embed_bits(Y, Cb, Cr, bits, delta=d)

            arr = np.stack([
                np.clip(Y2, 0, 255).astype(np.uint8),
                np.clip(Cb2, 0, 255).astype(np.uint8),
                np.clip(Cr2, 0, 255).astype(np.uint8)
            ], axis=2)
            img_ycbcr = Image.fromarray(arr, mode="YCbCr")

            temp_buf = io.BytesIO()
            if fmt == "PNG":
                img_ycbcr.convert("RGB").save(temp_buf, format=fmt)
            else:
                img_ycbcr.save(temp_buf, format=fmt, quality=quality, subsampling=0)

            if fmt != "PNG":
                try:
                    temp_buf.seek(0)
                    check_data = temp_buf.read()
                    temp_buf.seek(0)

                    Yc, Cbc, Crc = _img_to_ycbcr_arrays(check_data)
                    header_reps = 8
                    candidates = [d, max(1.0, d * 0.8), d * 1.2, max(1.0, d - 2.0), d + 2.0]
                    ok = False
                    for dd in candidates:
                        raw_header = extract_bits(Yc, Cbc, Crc, bit_count=32 * header_reps, delta=dd)
                        voted_header = []
                        for i in range(0, 32 * header_reps, header_reps):
                            grp = raw_header[i:i + header_reps]
                            voted_header.append(1 if sum(grp) >= (header_reps // 2 + 1) else 0)
                        hb = bits_to_bytes(voted_header)
                        if len(hb) >= 4:
                            L = int.from_bytes(hb[:4], "big")
                            payload_reps = 3
                            raw_payload = extract_bits(Yc, Cbc, Crc, bit_count=32 * header_reps + L * 8 * payload_reps, delta=dd)[32 * header_reps:]
                            voted_payload = []
                            for i in range(0, len(raw_payload), payload_reps):
                                grp = raw_payload[i:i + payload_reps]
                                if len(grp) < payload_reps:
                                    break
                                voted_payload.append(1 if sum(grp) >= (payload_reps // 2 + 1) else 0)
                            pb = bits_to_bytes(voted_payload[:L * 8])
                            try:
                                _ = decrypt_bytes(password, pb)
                                ok = True
                                break
                            except Exception:
                                continue
                    if ok:
                        final_buf = temp_buf
                        break
                except Exception:
                    continue
            else:
                final_buf = temp_buf
                break

        if final_buf is None:
            return jsonify({"error": "embed"}), 500
        buf = final_buf
    else:
        R, G, B = _img_to_rgb_arrays(data)
        R2, G2, B2 = embed_bits_lsb(R, G, B, bits)
        arr = np.stack([np.clip(R2,0,255).astype(np.uint8), np.clip(G2,0,255).astype(np.uint8), np.clip(B2,0,255).astype(np.uint8)], axis=2)
        img = Image.fromarray(arr, mode="RGB")
        if fmt == "PNG":
            img.save(buf, format=fmt)
        else:
            img.save(buf, format=fmt, quality=quality, subsampling=0)
    buf.seek(0)
    conn = get_db()
    conn.execute(
        "INSERT INTO history(email, type, cover, method, length, time) VALUES(?,?,?,?,?,?)",
        (
            session.get("user", {}).get("email", ""),
            "hide",
            getattr(cover, "filename", ""),
            method,
            len(text),
            __import__("datetime").datetime.utcnow().isoformat(),
        ),
    )
    conn.commit()
    conn.close()
    return send_file(buf, mimetype=mime, as_attachment=True, download_name=f"stego{ext}")


@app.post("/extract")
@login_required
def extract():
    stego = request.files.get("stego")
    password = request.form.get("password", "")
    if not stego or not password:
        return jsonify({"error": "missing inputs"}), 400
    if not (getattr(stego, "mimetype", "") or "").startswith("image/"):
        return jsonify({"error": "type"}), 415
    data = stego.read()
    if len(data) > 25 * 1024 * 1024:
        return jsonify({"error": "size"}), 413
    try:
        R, G, B = _img_to_rgb_arrays(data)
        header_reps = 8
        raw_header_bits = extract_bits_lsb(R, G, B, bit_count=32 * header_reps)
        voted_header_bits = []
        for i in range(0, 32 * header_reps, header_reps):
            group = raw_header_bits[i:i+header_reps]
            bit = 1 if sum(group) >= (header_reps // 2 + 1) else 0
            voted_header_bits.append(bit)
        header_bytes = bits_to_bytes(voted_header_bits)
        if len(header_bytes) < 4:
            raise ValueError("lsb header")
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
        plaintext = decrypt_bytes(password, payload_bytes)
    except Exception:
        try:
            Y, Cb, Cr = _img_to_ycbcr_arrays(data)
            header_reps = 8
            # Add higher delta values to candidates since we auto-scale delta for JPEG
            candidates = [2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 10.0, 15.0, 20.0, 25.0, 30.0, 40.0, 1.5, 2.5, 3.5]
            plaintext = None
            for delta in candidates:
                try:
                    raw_header_bits = extract_bits(Y, Cb, Cr, bit_count=32 * header_reps, delta=delta)
                    voted_header_bits = []
                    for i in range(0, 32 * header_reps, header_reps):
                        group = raw_header_bits[i:i+header_reps]
                        bit = 1 if sum(group) >= (header_reps // 2 + 1) else 0
                        voted_header_bits.append(bit)
                    header_bytes = bits_to_bytes(voted_header_bits)
                    if len(header_bytes) < 4:
                        continue
                    length = int.from_bytes(header_bytes[:4], "big")
                    payload_reps = 3
                    raw_payload_bits = extract_bits(Y, Cb, Cr, bit_count=32 * header_reps + length * 8 * payload_reps, delta=delta)[32 * header_reps:]
                    voted_payload_bits = []
                    for i in range(0, len(raw_payload_bits), payload_reps):
                        grp = raw_payload_bits[i:i+payload_reps]
                        if len(grp) < payload_reps:
                            break
                        bit = 1 if sum(grp) >= (payload_reps // 2 + 1) else 0
                        voted_payload_bits.append(bit)
                    payload_bytes = bits_to_bytes(voted_payload_bits[:length * 8])
                    plaintext = decrypt_bytes(password, payload_bytes)
                    break
                except Exception:
                    continue
            if plaintext is None:
                return jsonify({"error": "decrypt"}), 400
        except Exception:
            return jsonify({"error": "decrypt"}), 400
    text = plaintext.decode("utf-8", errors="replace")
    conn = get_db()
    conn.execute(
        "INSERT INTO history(email, type, stego, length, time) VALUES(?,?,?,?,?)",
        (
            session.get("user", {}).get("email", ""),
            "extract",
            getattr(stego, "filename", ""),
            len(text),
            __import__("datetime").datetime.utcnow().isoformat(),
        ),
    )
    conn.commit()
    conn.close()
    return jsonify({"text": text})


@app.get("/history")
@login_required
def history():
    page = int(request.args.get("page", "1") or "1")
    try:
        limit = int(request.args.get("limit", "10") or "10")
    except Exception:
        limit = 10
    if limit not in (10, 20, 50):
        limit = 10
    offset = (page - 1) * limit
    email = session.get("user", {}).get("email", "")
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) AS c FROM history WHERE email=?", (email,)).fetchone()["c"]
    cur = conn.execute(
        "SELECT id, type, cover, stego, method, length, time FROM history WHERE email=? ORDER BY id DESC LIMIT ? OFFSET ?",
        (email, limit, offset),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    pages = (total + limit - 1) // limit
    return render_template("history.html", user=session.get("user"), items=rows, page=page, pages=pages, limit=limit)


def is_admin() -> bool:
    u = session.get("user") or {}
    return (u.get("role") or "user") == "admin"


@app.post("/history/delete/<int:item_id>")
@login_required
def delete_history_item(item_id: int):
    conn = get_db()
    cur = conn.execute("SELECT email FROM history WHERE id=?", (item_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return redirect(url_for("history"))
    owner = row["email"]
    user_email = session.get("user", {}).get("email", "")
    if owner != user_email and not is_admin():
        conn.close()
        return redirect(url_for("history"))
    conn.execute("DELETE FROM history WHERE id=?", (item_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("history"))


@app.post("/history/clear")
@login_required
def clear_history():
    user_email = session.get("user", {}).get("email", "")
    conn = get_db()
    conn.execute("DELETE FROM history WHERE email=?", (user_email,))
    conn.commit()
    conn.close()
    return redirect(url_for("history"))


@app.get("/admin/history")
@login_required
def admin_history():
    if not is_admin():
        return redirect(url_for("index"))
    page = int(request.args.get("page", "1") or "1")
    try:
        limit = int(request.args.get("limit", "20") or "20")
    except Exception:
        limit = 20
    if limit not in (20, 50, 100):
        limit = 20
    offset = (page - 1) * limit
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) AS c FROM history").fetchone()["c"]
    cur = conn.execute(
        "SELECT id, email, type, cover, stego, method, length, time FROM history ORDER BY id DESC LIMIT ? OFFSET ?",
        (limit, offset),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    pages = (total + limit - 1) // limit
    return render_template("admin_history.html", user=session.get("user"), items=rows, page=page, pages=pages, limit=limit)


@app.post("/admin/history/delete/<int:item_id>")
@login_required
def admin_delete_history_item(item_id: int):
    if not is_admin():
        return redirect(url_for("index"))
    conn = get_db()
    conn.execute("DELETE FROM history WHERE id=?", (item_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_history"))


@app.get("/profile")
@login_required
def profile():
    email = session.get("user", {}).get("email", "")
    conn = get_db()
    cur = conn.execute("SELECT name, email FROM users WHERE email=?", (email,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return redirect(url_for("index"))
    return render_template("profile.html", user=dict(row))


@app.post("/profile")
@login_required
def update_profile():
    email = session.get("user", {}).get("email", "")
    name = request.form.get("name", "").strip()
    current_pw = request.form.get("current_password", "")
    new_pw = request.form.get("new_password", "")
    admin_code = request.form.get("admin_code", "").strip()
    conn = get_db()
    msg = None
    if name:
        conn.execute("UPDATE users SET name=? WHERE email=?", (name, email))
        cur = conn.execute("SELECT role FROM users WHERE email=?", (email,))
        r = cur.fetchone()
        session["user"] = {"name": name, "email": email, "role": (r["role"] if r and r["role"] else "user")}
        msg = "Name updated"
    if new_pw:
        cur = conn.execute("SELECT password_hash FROM users WHERE email=?", (email,))
        row = cur.fetchone()
        if not row or not check_password_hash(row["password_hash"], current_pw):
            conn.close()
            return render_template("profile.html", user=session.get("user"), error="Current password incorrect")
        conn.execute("UPDATE users SET password_hash=? WHERE email=?", (generate_password_hash(new_pw), email))
        msg = (msg + "; ") if msg else ""
        msg += "Password updated"
    if admin_code:
        secret = os.environ.get("ADMIN_INVITE_CODE", "000111")
        if secret and admin_code == secret:
            conn.execute("UPDATE users SET role='admin' WHERE email=?", (email,))
            session["user"] = {"name": (session.get("user") or {}).get("name", name or ""), "email": email, "role": "admin"}
            msg = (msg + "; ") if msg else ""
            msg += "Role upgraded to admin"
        else:
            conn.commit()
            conn.close()
            return render_template("profile.html", user=session.get("user"), error="Invalid admin code")
    conn.commit()
    conn.close()
    return render_template("profile.html", user=session.get("user"), msg=msg or "No changes")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True)
