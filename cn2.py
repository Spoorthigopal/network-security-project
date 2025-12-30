import tkinter as tk
from tkinter import scrolledtext, messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import hashlib

# ===================== SECURITY DATABASE =====================

USERS = {
    "node1": {"password": hashlib.sha256("node1pass".encode()).hexdigest(), "role": "NODE"},
    "node2": {"password": hashlib.sha256("node2pass".encode()).hexdigest(), "role": "NODE"},
    "relay": {"password": hashlib.sha256("relaypass".encode()).hexdigest(), "role": "RELAY"}
}

# ===================== SECURITY LOGIC =====================

KEY_SIZE = 2048
relay_key = RSA.generate(KEY_SIZE)

def authenticate(username, password):
    return username in USERS and \
           hashlib.sha256(password.encode()).hexdigest() == USERS[username]["password"]

def authorize(username, role):
    return USERS[username]["role"] == role

def encrypt(msg):
    return PKCS1_OAEP.new(relay_key.publickey()).encrypt(msg)

def decrypt(cipher):
    return PKCS1_OAEP.new(relay_key).decrypt(cipher)

def xor_bytes(a, b):
    return bytes(a[i] ^ b[i] for i in range(min(len(a), len(b))))

def generate_hash(m):
    return hashlib.sha256(m).hexdigest()

def verify_hash(m, h):
    return hashlib.sha256(m).hexdigest() == h

# ===================== TOOLTIP =====================

def create_tooltip(widget, text):
    tooltip = None
    def show_tooltip(event):
        nonlocal tooltip
        if tooltip:
            return
        tooltip = tk.Toplevel(widget)
        tooltip.wm_overrideredirect(True)
        tooltip.attributes("-topmost", True)
        
        # Initial position at mouse
        x, y = event.x_root, event.y_root
        tooltip.wm_geometry(f"600x300+{x}+{y}")
        
        # Frame for styling
        frame = tk.Frame(tooltip, bg="#1e293b", relief="raised", borderwidth=3)
        frame.pack(fill="both", expand=True)
        
        # Close button
        close_btn = tk.Button(frame, text="×", command=hide_tooltip, bg="#1e293b", fg="#60a5fa", font=("Arial", 16, "bold"), relief="flat", bd=0, activebackground="#1e293b", activeforeground="#60a5fa")
        close_btn.pack(anchor="ne", padx=10, pady=10)
        
        # Label for text
        label = tk.Label(frame, text=text, bg="#1e293b", fg="#60a5fa", wraplength=560, justify="left", font=("Consolas", 12))
        label.pack(pady=20, padx=20)
        
        # Animate to center
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        center_x = (screen_width - 600) // 2
        center_y = (screen_height - 300) // 2
        
        steps = 20
        dx = (center_x - x) / steps
        dy = (center_y - y) / steps
        
        def animate(step):
            if step < steps:
                new_x = int(x + dx * step)
                new_y = int(y + dy * step)
                tooltip.wm_geometry(f"600x300+{new_x}+{new_y}")
                tooltip.after(10, animate, step + 1)
        
        animate(0)
    
    def hide_tooltip():
        nonlocal tooltip
        if tooltip:
            tooltip.destroy()
            tooltip = None
    
    widget.bind("<Button-1>", show_tooltip)
    # Tooltip now appears on click instead of hover

# ===================== ANIMATION =====================

def move_packet(x1, y1, x2, y2, color, label, tag):
    p = canvas.create_oval(x1, y1, x1+16, y1+16, fill=color, tags=("packet", tag))
    t = canvas.create_text(x1+8, y1-12, text=label, fill="white",
                           font=("Segoe UI", 9), tags=("packet", tag))
    dx = (x2-x1)/60
    dy = (y2-y1)/60

    def step(i):
        if i < 60:
            canvas.move(p, dx, dy)
            canvas.move(t, dx, dy)
            canvas.after(25, step, i+1)
    step(0)

def animate_flow():
    canvas.delete("packet")
    move_packet(160,120,290,120,"#60a5fa","ENC","n1")
    move_packet(440,120,290,120,"#60a5fa","ENC","n2")
    canvas.after(1600, show_xor)

def show_xor():
    xor = canvas.create_text(290,120,text="XOR",
                             fill="yellow",font=("Segoe UI",14,"bold"))
    canvas.after(1200, lambda: canvas.delete(xor))
    canvas.after(1200, send_xor)

def send_xor():
    move_packet(290,120,160,120,"#facc15","XOR","xor1")
    move_packet(290,120,440,120,"#facc15","XOR","xor2")
    canvas.after(1600, show_decryption)

def show_decryption():
    k1 = canvas.create_text(160,60,text="🔑 DEC",
                            fill="#4ade80",font=("Segoe UI",11,"bold"))
    k2 = canvas.create_text(440,60,text="🔑 DEC",
                            fill="#4ade80",font=("Segoe UI",11,"bold"))

    # Change packet labels to DATA
    def replace_labels():
        for item in canvas.find_withtag("xor1"):
            if canvas.type(item) == "text":
                canvas.itemconfig(item, text="DATA")
        for item in canvas.find_withtag("xor2"):
            if canvas.type(item) == "text":
                canvas.itemconfig(item, text="DATA")

    canvas.after(800, replace_labels)
    canvas.after(2000, lambda: (canvas.delete(k1), canvas.delete(k2)))

# ===================== SIMULATION =====================

def run_simulation():
    for box in [e1_box, e2_box, d1_box, d2_box, r1_box, r2_box]:
        box.delete("1.0", tk.END)

    msg1 = node1_entry.get()
    msg2 = node2_entry.get()
    pwd1 = node1_pass.get()
    pwd2 = node2_pass.get()

    # ---------- AUTHENTICATION ----------
    if not authenticate("node1", pwd1):
        messagebox.showerror("Authentication Failed", "Node 1 password incorrect")
        return

    if not authenticate("node2", pwd2):
        messagebox.showerror("Authentication Failed", "Node 2 password incorrect")
        return

    # ---------- AUTHORIZATION ----------
    if not authorize("node1", "NODE") or not authorize("node2", "NODE"):
        messagebox.showerror("Authorization Error", "Unauthorized node")
        return

    # Start animation ONLY after security checks
    animate_flow()

    m1, m2 = msg1.encode(), msg2.encode()

    # ---------- INTEGRITY ----------
    h1 = generate_hash(m1)
    h2 = generate_hash(m2)

    # ---------- CONFIDENTIALITY ----------
    enc1 = encrypt(m1)
    enc2 = encrypt(m2)
    coded = xor_bytes(enc1, enc2)

    # Relay (cannot read plaintext)
    r1_box.insert(tk.END, coded.hex())
    create_tooltip(r1_box, coded.hex())
    r2_box.insert(tk.END, coded.hex())
    create_tooltip(r2_box, coded.hex())

    # Encrypted view
    e1_box.insert(tk.END, enc1.hex())
    create_tooltip(e1_box, enc1.hex())
    e2_box.insert(tk.END, enc2.hex())
    create_tooltip(e2_box, enc2.hex())

    # ---------- DECRYPTION ----------
    d1 = decrypt(xor_bytes(coded, enc1))
    d2 = decrypt(xor_bytes(coded, enc2))

    # ---------- INTEGRITY VERIFICATION ----------
    if not verify_hash(d1, h2):
        messagebox.showerror("Integrity Error", "Node 1 message tampered")
        return

    if not verify_hash(d2, h1):
        messagebox.showerror("Integrity Error", "Node 2 message tampered")
        return

    d1_box.insert(tk.END, d1.decode())
    d2_box.insert(tk.END, d2.decode())


# ===================== UI =====================

root = tk.Tk()
root.title("Enhanced Security Network Coding System")
root.geometry("1920x1080")
root.configure(bg="#0f172a")

# ---------- HEADER ----------
tk.Label(
    root,
    text="Enhanced Security Network Coding System – Two Way Relay Network",
    bg="#020617",
    fg="#e5e7eb",
    font=("Segoe UI", 20, "bold"),
    pady=18
).pack(fill="x")

# ---------- INPUT ROW ----------
input_row = tk.Frame(root, bg="#1e293b", padx=40, pady=20)
input_row.pack(fill="x", padx=50, pady=20)

input_row.grid_columnconfigure(0, weight=1)
input_row.grid_columnconfigure(1, weight=1)

# Labels
tk.Label(input_row, text="Node 1 Message", bg="#1e293b", fg="white", font=("Segoe UI", 12, "bold")).grid(row=0, column=0, padx=20, pady=(0,10))
tk.Label(input_row, text="Node 2 Message", bg="#1e293b", fg="white", font=("Segoe UI", 12, "bold")).grid(row=0, column=1, padx=20, pady=(0,10))

# Message Entries
node1_entry = tk.Entry(input_row, width=40, bg="#020617", fg="white", insertbackground="white")
node2_entry = tk.Entry(input_row, width=40, bg="#020617", fg="white", insertbackground="white")
node1_entry.grid(row=1, column=0, padx=20, pady=(0,10))
node2_entry.grid(row=1, column=1, padx=20, pady=(0,10))

# Password Labels
tk.Label(input_row, text="Node 1 Password", bg="#1e293b", fg="#93c5fd", font=("Segoe UI", 10)).grid(row=2, column=0, pady=(0,5))
tk.Label(input_row, text="Node 2 Password", bg="#1e293b", fg="#93c5fd", font=("Segoe UI", 10)).grid(row=2, column=1, pady=(0,5))

# Password Entries
node1_pass = tk.Entry(input_row, width=40, bg="#020617", fg="white",
                      insertbackground="white", show="*")
node2_pass = tk.Entry(input_row, width=40, bg="#020617", fg="white",
                      insertbackground="white", show="*")
node1_pass.grid(row=3, column=0, padx=20, pady=(0,20))
node2_pass.grid(row=3, column=1, padx=20, pady=(0,20))

# Button
send_button = tk.Button(
    input_row,
    text="▶ START TRANSMISSION",
    bg="#22c55e",
    fg="white",
    font=("Segoe UI", 11, "bold"),
    command=run_simulation,
    padx=20,
    pady=10,
    state="disabled"
)
send_button.grid(row=4, column=0, columnspan=2, pady=10)

def check_inputs(*args):
    msg1 = node1_entry.get().strip()
    msg2 = node2_entry.get().strip()
    pwd1 = node1_pass.get().strip()
    pwd2 = node2_pass.get().strip()
    if msg1 and msg2 and pwd1 and pwd2:
        send_button.config(state="normal")
    else:
        send_button.config(state="disabled")

node1_entry.bind("<KeyRelease>", check_inputs)
node2_entry.bind("<KeyRelease>", check_inputs)
node1_pass.bind("<KeyRelease>", check_inputs)
node2_pass.bind("<KeyRelease>", check_inputs)

# ---------- CARDS ----------
cards = tk.Frame(root, bg="#0f172a")
cards.pack(padx=50,pady=5)

cards.grid_columnconfigure(0, weight=1)
cards.grid_columnconfigure(1, weight=1)
cards.grid_columnconfigure(2, weight=1)

def card(parent, title, color):
    c = tk.Frame(parent, bg="#1e293b", padx=20, pady=20)
    tk.Label(c, text=title, fg=color, bg="#1e293b", font=("Segoe UI", 12, "bold")).pack(pady=5)
    b1 = scrolledtext.ScrolledText(c, height=2, bg="#020617", fg=color, font=("Consolas", 9))
    b2 = scrolledtext.ScrolledText(c, height=2, bg="#020617", fg=color, font=("Consolas", 9))
    b1.pack(fill="x", pady=2)
    b2.pack(fill="x", pady=2)
    return c, b1, b2

enc_card, e1_box, e2_box = card(cards, "🔐 RSA Encrypted Code (Node 1 / Node 2)", "#60a5fa")
e1_box.config(cursor="hand2")
e2_box.config(cursor="hand2")
dec_card, d1_box, d2_box = card(cards, "🔓 Decrypted Message (Node 1 / Node 2)", "#4ade80")
rec_card, r1_box, r2_box = card(cards, "📥 XOR Encrypted Data (Node 1 / Node 2)", "#e5e7eb")
r1_box.config(cursor="hand2")
r2_box.config(cursor="hand2")

enc_card.grid(row=0, column=0, padx=15, pady=15, sticky="nsew")
rec_card.grid(row=0, column=1, padx=15, pady=15, sticky="nsew")
dec_card.grid(row=0, column=2, padx=15, pady=15, sticky="nsew")

# ---------- ANIMATION ----------
viz = tk.Frame(root, bg="#020617", pady=10)
viz.pack(fill="x", padx=50, pady=30)

canvas = tk.Canvas(viz, width=600, height=220, bg="#020617", highlightthickness=0)
canvas.pack(anchor="center")

canvas.create_oval(120, 80, 200, 160, fill="#4ade80", outline="white", width=2)
canvas.create_text(160, 170, text="Node 1", fill="white")
canvas.create_oval(250, 80, 330, 160, fill="#ea580c", outline="white", width=2)
canvas.create_text(290, 170, text="Relay", fill="white")
canvas.create_oval(400, 80, 480, 160, fill="#f87171", outline="white", width=2)
canvas.create_text(440, 170, text="Node 2", fill="white")
canvas.create_line(200, 120, 250, 120, fill="#64748b", width=2)
canvas.create_line(330, 120, 400, 120, fill="#64748b", width=2)

root.mainloop()
