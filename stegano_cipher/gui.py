from __future__ import annotations

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import qrcode

import numpy as np
from .crypto import encrypt_bytes, decrypt_bytes
from PIL import Image, ImageTk
from .image_utils import load_image_rgb, save_image_rgb
from .embedder import bytes_to_bits, bits_to_bytes, embed_bits_lsb, extract_bits_lsb


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Stegano-Cipher • QuickStego-like")
        self.root.geometry("780x520")

        self.title_var = tk.StringVar(value="Stegano-Cipher • QuickStego-like")
        ttk.Label(root, textvariable=self.title_var, anchor="center", font=("Segoe UI", 16, "bold")).pack(fill=tk.X, padx=12, pady=6)
        ttk.Separator(root, orient=tk.HORIZONTAL).pack(fill=tk.X)

        nb = ttk.Notebook(root)
        nb.pack(fill=tk.BOTH, expand=True)

        self.hide_frame = ttk.Frame(nb)
        self.extract_frame = ttk.Frame(nb)
        nb.add(self.hide_frame, text="Hide Text")
        nb.add(self.extract_frame, text="Extract Text")

        self.hide_content = self._init_scroll(self.hide_frame)
        self.extract_content = self._init_scroll(self.extract_frame)
        self._build_hide_tab()
        self._build_extract_tab()
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(root, textvariable=self.status_var, anchor="w").pack(fill=tk.X, padx=8, pady=4)
        self.progress = ttk.Progressbar(root, mode="indeterminate")

    def _build_hide_tab(self):
        f = self.hide_content
        p = ttk.LabelFrame(f, text="Cover Image")
        p.pack(fill=tk.X, padx=12, pady=8)
        self.cover_path_var = tk.StringVar()
        e1 = ttk.Entry(p, textvariable=self.cover_path_var)
        e1.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8, pady=8)
        ttk.Button(p, text="Browse", command=self._browse_cover).pack(side=tk.LEFT, padx=8, pady=8)
        self.cover_preview_label = ttk.Label(f)
        self.cover_preview_label.pack(fill=tk.X, padx=16)

        p2 = ttk.LabelFrame(f, text="Output Stego Image")
        p2.pack(fill=tk.X, padx=12, pady=8)
        self.out_path_var = tk.StringVar()
        e2 = ttk.Entry(p2, textvariable=self.out_path_var)
        e2.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8, pady=8)
        ttk.Button(p2, text="Save As", command=self._save_stego).pack(side=tk.LEFT, padx=8, pady=8)

        p3 = ttk.LabelFrame(f, text="Secret Text")
        p3.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)
        self.text_box = tk.Text(p3, wrap=tk.WORD, height=12)
        self.text_box.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        self.text_box.bind("<KeyRelease>", lambda e: self._update_text_count())
        bline = ttk.Frame(p3)
        bline.pack(fill=tk.X)
        ttk.Button(bline, text="Load From File", command=self._load_text_file).pack(side=tk.RIGHT, padx=8, pady=4)
        self.text_count_var = tk.StringVar(value="0 chars")
        ttk.Label(bline, textvariable=self.text_count_var).pack(side=tk.LEFT, padx=8)

        p4 = ttk.LabelFrame(f, text="Security & Quality")
        p4.pack(fill=tk.X, padx=12, pady=8)
        ttk.Label(p4, text="Password:").pack(side=tk.LEFT, padx=8)
        self.pass_var_hide = tk.StringVar()
        ttk.Entry(p4, textvariable=self.pass_var_hide, show="*").pack(side=tk.LEFT, padx=8)
        ttk.Label(p4, text="Method:").pack(side=tk.LEFT, padx=16)
        self.method_var = tk.StringVar(value="Robust (LSB)")
        ttk.Combobox(p4, textvariable=self.method_var, values=["Robust (LSB)"], state="readonly", width=18).pack(side=tk.LEFT)
        ttk.Label(p4, text="Delta:").pack(side=tk.LEFT, padx=16)
        self.delta_var_hide = tk.StringVar(value="2.0")
        ttk.Entry(p4, textvariable=self.delta_var_hide, width=8).pack(side=tk.LEFT)
        ttk.Label(p4, text="JPEG Quality:").pack(side=tk.LEFT, padx=16)
        self.quality_var = tk.IntVar(value=92)
        qframe = ttk.Frame(p4)
        qframe.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8)
        ttk.Scale(qframe, from_=60, to=100, orient=tk.HORIZONTAL, variable=self.quality_var, command=lambda v: self._update_quality_display()).pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.quality_disp = ttk.Label(qframe, text="92")
        self.quality_disp.pack(side=tk.LEFT, padx=8)
        self.capacity_var = tk.StringVar(value="Capacity: unknown")
        ttk.Label(p4, textvariable=self.capacity_var).pack(side=tk.LEFT, padx=16)
        ttk.Button(p4, text="Hide & Save", command=self._do_hide).pack(side=tk.RIGHT, padx=12, pady=8)

    def _build_extract_tab(self):
        f = self.extract_content
        p = ttk.LabelFrame(f, text="Stego Image")
        p.pack(fill=tk.X, padx=12, pady=8)
        self.stego_path_var = tk.StringVar()
        e1 = ttk.Entry(p, textvariable=self.stego_path_var)
        e1.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8, pady=8)
        ttk.Button(p, text="Browse", command=self._browse_stego).pack(side=tk.LEFT, padx=8, pady=8)
        self.stego_preview_label = ttk.Label(f)
        self.stego_preview_label.pack(fill=tk.X, padx=16)

        p2 = ttk.LabelFrame(f, text="Parameters")
        p2.pack(fill=tk.X, padx=12, pady=8)
        ttk.Label(p2, text="Password:").pack(side=tk.LEFT, padx=8)
        self.pass_var_extract = tk.StringVar()
        ttk.Entry(p2, textvariable=self.pass_var_extract, show="*").pack(side=tk.LEFT, padx=8)
        ttk.Label(p2, text="Delta:").pack(side=tk.LEFT, padx=16)
        self.delta_var_extract = tk.StringVar(value="2.0")
        ttk.Entry(p2, textvariable=self.delta_var_extract, width=8).pack(side=tk.LEFT)

        ttk.Button(f, text="Extract", command=self._do_extract).pack(anchor=tk.E, padx=20, pady=8)

        p3 = ttk.LabelFrame(f, text="Recovered Text")
        p3.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)
        self.out_text_box = tk.Text(p3, wrap=tk.WORD, height=12)
        self.out_text_box.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        ttk.Button(p3, text="Save To File", command=self._save_recovered_text).pack(anchor=tk.E, padx=8, pady=4)

    def _browse_cover(self):
        path = filedialog.askopenfilename(title="Select Cover Image", filetypes=[("Images", "*.jpg;*.jpeg;*.png")])
        if path:
            self.cover_path_var.set(path)
            self._update_cover_preview(path)
            self._update_capacity_display()

    def _save_stego(self):
        path = filedialog.asksaveasfilename(title="Save Stego Image", defaultextension=".png", filetypes=[("PNG", "*.png"), ("JPEG", "*.jpg;*.jpeg")])
        if path:
            self.out_path_var.set(path)

    def _load_text_file(self):
        path = filedialog.askopenfilename(title="Load Text File", filetypes=[("Text", "*.txt;*.md;*.log"), ("All Files", "*.*")])
        if path:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = f.read()
            except Exception:
                try:
                    with open(path, "rb") as f:
                        data = f.read().decode("utf-8", errors="replace")
                except Exception as e:
                    messagebox.showerror("Error", str(e))
                    return
            self.text_box.delete("1.0", tk.END)
            self.text_box.insert("1.0", data)

    def _browse_stego(self):
        path = filedialog.askopenfilename(title="Select Stego Image", filetypes=[("PNG", "*.png"), ("JPEG", "*.jpg;*.jpeg"), ("All Images", "*.png;*.jpg;*.jpeg")])
        if path:
            self.stego_path_var.set(path)
            self._update_stego_preview(path)

    def _do_hide(self):
        in_path = self.cover_path_var.get().strip()
        out_path = self.out_path_var.get().strip()
        text = self.text_box.get("1.0", tk.END).strip()
        password = self.pass_var_hide.get().strip()
        try:
            delta = float(self.delta_var_hide.get().strip())
        except Exception:
            delta = 2.0
        quality = int(self.quality_var.get())
        if not in_path or not os.path.isfile(in_path):
            messagebox.showwarning("Missing", "Select a valid cover image")
            return
        if not out_path:
            messagebox.showwarning("Missing", "Choose an output file path")
            return
        if not text:
            messagebox.showwarning("Missing", "Enter or load secret text")
            return
        if not password:
            messagebox.showwarning("Missing", "Enter a password")
            return
        self._show_progress()
        try:
            plaintext = text.encode("utf-8")
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
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self._hide_progress()
            return
        self._hide_progress()
        self._set_status(f"Saved stego image: {out_path}")
        messagebox.showinfo("Done", f"Saved stego image to:\n{out_path}")

    def _do_extract(self):
        in_path = self.stego_path_var.get().strip()
        password = self.pass_var_extract.get().strip()
        try:
            delta = float(self.delta_var_extract.get().strip())
        except Exception:
            delta = 2.0
        if not in_path or not os.path.isfile(in_path):
            messagebox.showwarning("Missing", "Select a valid stego image")
            return
        if not password:
            messagebox.showwarning("Missing", "Enter a password")
            return
        self._show_progress()
        result_text = None
        try:
            R, G, B = load_image_rgb(in_path)
            capacity_bytes = (R.shape[0] * R.shape[1]) // 8

            header_reps = 8
            raw_header_bits = extract_bits_lsb(R, G, B, bit_count=32 * header_reps)
            voted_header_bits = []
            for i in range(0, 32 * header_reps, header_reps):
                group = raw_header_bits[i:i+header_reps]
                bit = 1 if sum(group) >= (header_reps // 2 + 1) else 0
                voted_header_bits.append(bit)
            header_bytes = bits_to_bytes(voted_header_bits)
            if len(header_bytes) >= 4:
                length = int.from_bytes(header_bytes[:4], "big")
                if length >= 0 and length <= capacity_bytes:
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
                    if plaintext.startswith(b"\x89PNG\r\n\x1a\n"):
                        result_text = "[Message encoded as QR image]"
                        self.out_text_box.delete("1.0", tk.END)
                        self.out_text_box.insert("1.0", result_text)
                        self._set_status("Extracted QR Code Payload successfully")
                        self._show_qr_from_bytes(plaintext)
                        self._hide_progress()
                        return
                    else:
                        try:
                            result_text = plaintext.decode("utf-8")
                        except Exception:
                            result_text = plaintext.decode("utf-8", errors="replace")
                        
            if result_text is None:
                raise ValueError("Extraction failed. Invalid password or corrupted image.")
            self.out_text_box.delete("1.0", tk.END)
            self.out_text_box.insert("1.0", result_text)
            self._set_status("Extracted text successfully")
            self._show_qr(result_text)
        except Exception as e:
            messagebox.showerror("Error", str(e))
        self._hide_progress()

    def _save_recovered_text(self):
        path = filedialog.asksaveasfilename(title="Save Text", defaultextension=".txt", filetypes=[("Text", "*.txt")])
        if not path:
            return
        data = self.out_text_box.get("1.0", tk.END)
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(data)
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return
        messagebox.showinfo("Saved", f"Wrote text to:\n{path}")

    def _show_qr(self, text: str):
        try:
            qr = qrcode.QRCode(version=1, box_size=8, border=2)
            qr.add_data(text)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
            
            top = tk.Toplevel(self.root)
            top.title("Extracted QR Code")
            top.geometry("320x380")
            
            tk_img = ImageTk.PhotoImage(img)
            lbl = tk.Label(top, image=tk_img)
            lbl.image = tk_img
            lbl.pack(pady=10)
            
            def save_qr():
                path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image", "*.png")])
                if path:
                    img.save(path)
                    messagebox.showinfo("Saved", f"QR code saved to:\n{path}", parent=top)
            
            btn = ttk.Button(top, text="Save QR Code", command=save_qr)
            btn.pack(pady=5)
            
        except Exception as e:
            messagebox.showerror("QR Error", str(e))

    def _show_qr_from_bytes(self, img_bytes: bytes):
        import io
        try:
            img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
            top = tk.Toplevel(self.root)
            top.title("Extracted QR Payload")
            top.geometry("320x380")
            
            tk_img = ImageTk.PhotoImage(img)
            lbl = tk.Label(top, image=tk_img)
            lbl.image = tk_img
            lbl.pack(pady=10)
            
            def save_qr():
                path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image", "*.png")])
                if path:
                    img.save(path)
                    messagebox.showinfo("Saved", f"QR payload saved to:\n{path}", parent=top)
            
            btn = ttk.Button(top, text="Save QR Code", command=save_qr)
            btn.pack(pady=5)
            
        except Exception as e:
            messagebox.showerror("QR Error", str(e))

    def _init_scroll(self, container: tk.Widget) -> ttk.Frame:
        outer = ttk.Frame(container)
        outer.pack(fill=tk.BOTH, expand=True)
        canvas = tk.Canvas(outer, highlightthickness=0)
        vsb = ttk.Scrollbar(outer, orient=tk.VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        inner = ttk.Frame(canvas)
        window = canvas.create_window((0, 0), window=inner, anchor="nw")

        def _on_configure(event=None):
            canvas.configure(scrollregion=canvas.bbox("all"))
            # Resize inner to canvas width
            bbox = canvas.bbox(window)
            if bbox:
                canvas.itemconfigure(window, width=canvas.winfo_width())
        inner.bind("<Configure>", lambda e: _on_configure())
        canvas.bind("<Configure>", lambda e: _on_configure())
        self._bind_mousewheel(canvas)
        return inner

    def _bind_mousewheel(self, widget: tk.Widget):
        def _on_mousewheel(event):
            delta = -1 * (event.delta // 120)
            widget.yview_scroll(delta, "units")
        widget.bind_all("<MouseWheel>", _on_mousewheel)

    def _update_cover_preview(self, path: str):
        try:
            img = Image.open(path).convert("RGB")
            w, h = img.size
            maxw, maxh = 360, 220
            scale = min(maxw / w, maxh / h)
            img = img.resize((max(1, int(w * scale)), max(1, int(h * scale))))
            self.cover_preview_img = ImageTk.PhotoImage(img)
            self.cover_preview_label.configure(image=self.cover_preview_img)
        except Exception:
            self.cover_preview_label.configure(image="")

    def _update_stego_preview(self, path: str):
        try:
            img = Image.open(path).convert("RGB")
            w, h = img.size
            maxw, maxh = 360, 220
            scale = min(maxw / w, maxh / h)
            img = img.resize((max(1, int(w * scale)), max(1, int(h * scale))))
            self.stego_preview_img = ImageTk.PhotoImage(img)
            self.stego_preview_label.configure(image=self.stego_preview_img)
        except Exception:
            self.stego_preview_label.configure(image="")

    def _update_text_count(self):
        txt = self.text_box.get("1.0", tk.END)
        self.text_count_var.set(f"{len(txt.strip())} chars")
        self._update_capacity_display()

    def _update_quality_display(self):
        self.quality_disp.configure(text=str(int(self.quality_var.get())))

    def _update_capacity_display(self):
        path = self.cover_path_var.get().strip()
        if not path or not os.path.isfile(path):
            self.capacity_var.set("Capacity: unknown")
            return
        try:
            img = Image.open(path).convert("RGB")
            w, h = img.size
            capacity_bytes = (w * h) // 8
            txt = self.text_box.get("1.0", tk.END).strip()
            self.capacity_var.set(f"Capacity: ~{capacity_bytes} bytes • Message: {len(txt.encode('utf-8'))} bytes")
        except Exception:
            self.capacity_var.set("Capacity: unknown")

    def _set_status(self, s: str):
        self.status_var.set(s)

    def _show_progress(self):
        try:
            self.progress.pack(fill=tk.X, padx=8)
            self.progress.start(10)
        except Exception:
            pass

    def _hide_progress(self):
        try:
            self.progress.stop()
            self.progress.pack_forget()
        except Exception:
            pass


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()