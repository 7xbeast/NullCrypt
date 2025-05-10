# This script updates the given GUI tool to include dark theme, better fonts, padding,
# responsive layout, center-aligned widgets, colored buttons with hover effects, and an icon.

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64
import os

def pad(text, block_size):
    return text + ' ' * (block_size - len(text) % block_size)

def aes_encrypt(text, key):
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    ct = cipher.encrypt(pad(text, 16).encode())
    return base64.b64encode(ct).decode()

def aes_decrypt(ciphertext, key):
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    pt = cipher.decrypt(base64.b64decode(ciphertext))
    return pt.decode().strip()

def des_encrypt(text, key):
    cipher = DES.new(key.encode(), DES.MODE_ECB)
    ct = cipher.encrypt(pad(text, 8).encode())
    return base64.b64encode(ct).decode()

def des_decrypt(ciphertext, key):
    cipher = DES.new(key.encode(), DES.MODE_ECB)
    pt = cipher.decrypt(base64.b64decode(ciphertext))
    return pt.decode().strip()

def rsa_encrypt(text, key_path):
    with open(key_path, "rb") as f:
        key = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(key)
    ct = cipher.encrypt(text.encode())
    return base64.b64encode(ct).decode()

def rsa_decrypt(ciphertext, key_path):
    with open(key_path, "rb") as f:
        key = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(key)
    pt = cipher.decrypt(base64.b64decode(ciphertext))
    return pt.decode()

def run_crypto():
    algorithm = algo_var.get()
    action = mode_var.get()
    text = input_text.get("1.0", tk.END).strip()
    key = key_entry.get().strip()

    try:
        if algorithm == "AES":
            if len(key) != 16:
                raise ValueError("AES key must be 16 characters.")
            result = aes_encrypt(text, key) if action == "Encrypt" else aes_decrypt(text, key)

        elif algorithm == "DES":
            if len(key) != 8:
                raise ValueError("DES key must be 8 characters.")
            result = des_encrypt(text, key) if action == "Encrypt" else des_decrypt(text, key)

        elif algorithm == "RSA":
            if not key:
                key = filedialog.askopenfilename(title="Select RSA Key File")
                if not key:
                    return
            result = rsa_encrypt(text, key) if action == "Encrypt" else rsa_decrypt(text, key)

        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, result)

    except Exception as e:
        messagebox.showerror("Error", str(e))

# --- UI Setup ---
root = tk.Tk()
root.title("Secure Text Encryption Tool")
root.geometry("700x600")
root.configure(bg="#1e1e1e")
root.resizable(True, True)

try:
    root.iconbitmap("lock.ico")  # Provide a suitable icon path
except:
    pass  # If icon not found, skip

font_main = ("Segoe UI", 11)
label_fg = "#ffffff"
entry_bg = "#2d2d2d"
entry_fg = "#ffffff"
button_bg = "#3a3a3a"
button_fg = "#ffffff"
hover_bg = "#505050"

def on_enter(e): e.widget.config(bg=hover_bg)
def on_leave(e): e.widget.config(bg=button_bg)

frame = tk.Frame(root, bg="#1e1e1e", padx=20, pady=20)
frame.pack(expand=True, fill="both")

def create_label(text):
    return tk.Label(frame, text=text, bg="#1e1e1e", fg=label_fg, font=font_main)

# Text Input
create_label("Enter Text:").pack(anchor="w")
input_text = tk.Text(frame, height=5, bg=entry_bg, fg=entry_fg, font=font_main, insertbackground="white")
input_text.pack(fill="x", pady=5)

# Algorithm
create_label("Choose Algorithm:").pack(anchor="w")
algo_var = tk.StringVar(value="AES")
algo_menu = ttk.Combobox(frame, textvariable=algo_var, values=["AES", "DES", "RSA"], state="readonly", font=font_main)
algo_menu.pack(fill="x", pady=5)

# Mode
create_label("Choose Mode:").pack(anchor="w")
mode_var = tk.StringVar(value="Encrypt")
mode_menu = ttk.Combobox(frame, textvariable=mode_var, values=["Encrypt", "Decrypt"], state="readonly", font=font_main)
mode_menu.pack(fill="x", pady=5)

# Key
create_label("Enter Key (or browse for RSA):").pack(anchor="w")
key_entry = tk.Entry(frame, font=font_main, bg=entry_bg, fg=entry_fg, insertbackground="white")
key_entry.pack(fill="x", pady=5)

# Run Button
run_btn = tk.Button(frame, text="Run", command=run_crypto, font=font_main, bg=button_bg, fg=button_fg)
run_btn.pack(pady=15)
run_btn.bind("<Enter>", on_enter)
run_btn.bind("<Leave>", on_leave)

# Output
create_label("Output:").pack(anchor="w")
output_text = tk.Text(frame, height=10, bg=entry_bg, fg=entry_fg, font=font_main, insertbackground="white")
output_text.pack(fill="x", pady=5)

root.mainloop()



