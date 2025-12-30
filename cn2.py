import tkinter as tk
from tkinter import scrolledtext, messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import hashlib

# ===================== SECURITY DATABASE =====================

USERS = {
    "node1": {"password": hashlib.sha256("node".encode()).hexdigest(), "role": "NODE"},
    "node2": {"password": hashlib.sha256("node".encode()).hexdigest(), "role": "NODE"},
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

# ===================== RELAY WINDOW =====================

relay_window = None
relay_authenticated = False
relay_status_label = None
relay_data_display = None

# ===================== ANIMATION WINDOW =====================

animation_window = None
anim_canvas = None
anim_status_label = None

def clear_relay_data(node1_data, node2_data, xor_data):
    """Clear all data display areas in the relay window"""
    node1_data.delete("1.0", tk.END)
    node1_data.insert(tk.END, "Waiting for transmission...")

    node2_data.delete("1.0", tk.END)
    node2_data.insert(tk.END, "Waiting for transmission...")

    xor_data.delete("1.0", tk.END)
    xor_data.insert(tk.END, "Waiting for XOR operation...")

def create_relay_window():
    global relay_window, relay_authenticated, relay_status_label, relay_data_display

    if relay_window is not None and relay_window.winfo_exists():
        relay_window.lift()
        return

    # Create relay window
    relay_window = tk.Toplevel(root)
    relay_window.title("Relay Control Center - Secure Transmission Hub")
    relay_window.attributes('-fullscreen', True)  # Make full screen
    relay_window.configure(bg="#0f172a")
    relay_window.resizable(True, True)  # Allow resizing since it's full screen

    # Create main container to center all content
    main_container = tk.Frame(relay_window, bg="#0f172a")
    main_container.pack(fill="both", expand=True)

    # Header
    tk.Label(
        main_container,
        text="🔗 Relay Control Center",
        bg="#020617",
        fg="#e5e7eb",
        font=("Segoe UI", 18, "bold"),
        pady=15
    ).pack(fill="x")

    # Center content frame
    center_frame = tk.Frame(main_container, bg="#0f172a")
    center_frame.pack(anchor="center", pady=20)

    # Authentication section
    auth_frame = tk.Frame(center_frame, bg="#1e293b", padx=30, pady=20)
    auth_frame.pack(pady=(0, 30))

    tk.Label(auth_frame, text="🔐 Relay Authentication", bg="#1e293b", fg="#fbbf24",
             font=("Segoe UI", 14, "bold")).pack(pady=(0, 15))

    # Password input
    pwd_frame = tk.Frame(auth_frame, bg="#1e293b")
    pwd_frame.pack(pady=(0, 10))

    tk.Label(pwd_frame, text="Relay Password:", bg="#1e293b", fg="white",
             font=("Segoe UI", 11)).grid(row=0, column=0, padx=(0, 10))
    relay_password_entry = tk.Entry(pwd_frame, width=25, bg="#020617", fg="white",
                                   insertbackground="white", show="*")
    relay_password_entry.grid(row=0, column=1, padx=(0, 10))

    auth_button = tk.Button(pwd_frame, text="Authenticate", bg="#22c55e", fg="white",
                           font=("Segoe UI", 10, "bold"), command=lambda: authenticate_relay(relay_password_entry))
    auth_button.grid(row=0, column=2)

    # Status
    relay_status_label = tk.Label(auth_frame, text="Status: Not Authenticated",
                                 bg="#1e293b", fg="#dc2626", font=("Segoe UI", 11, "bold"))
    relay_status_label.pack(pady=(10, 0))

    # Data display section
    data_frame = tk.Frame(center_frame, bg="#0f172a")
    data_frame.pack(pady=(20, 0))

    tk.Label(data_frame, text="📊 Transmission Data Monitor", bg="#0f172a", fg="#60a5fa",
             font=("Segoe UI", 14, "bold")).pack(pady=(0, 20))

    # Create data display areas with proper centering
    relay_data_display = tk.Frame(data_frame, bg="#0f172a")
    relay_data_display.pack()

    # Configure grid weights for proper centering
    relay_data_display.grid_columnconfigure(0, weight=1)
    relay_data_display.grid_columnconfigure(1, weight=1)
    relay_data_display.grid_rowconfigure(0, weight=1)
    relay_data_display.grid_rowconfigure(1, weight=1)

    # Node 1 data
    node1_frame = tk.Frame(relay_data_display, bg="#1e293b", padx=15, pady=15)
    node1_frame.grid(row=0, column=0, padx=15, pady=15, sticky="nsew")

    tk.Label(node1_frame, text="📨 Node 1 RSA Encrypted Data", bg="#1e293b", fg="#60a5fa",
             font=("Segoe UI", 12, "bold")).pack(pady=(0, 10))
    node1_data = scrolledtext.ScrolledText(node1_frame, height=4, bg="#020617", fg="#60a5fa",
                                          font=("Consolas", 9))
    node1_data.pack(fill="both", expand=True)
    node1_data.insert(tk.END, "Waiting for transmission...")

    # Node 2 data
    node2_frame = tk.Frame(relay_data_display, bg="#1e293b", padx=15, pady=15)
    node2_frame.grid(row=0, column=1, padx=15, pady=15, sticky="nsew")

    tk.Label(node2_frame, text="📨 Node 2 RSA Encrypted Data", bg="#1e293b", fg="#60a5fa",
             font=("Segoe UI", 12, "bold")).pack(pady=(0, 10))
    node2_data = scrolledtext.ScrolledText(node2_frame, height=4, bg="#020617", fg="#60a5fa",
                                          font=("Consolas", 9))
    node2_data.pack(fill="both", expand=True)
    node2_data.insert(tk.END, "Waiting for transmission...")

    # XOR operation - centered below the nodes
    xor_frame = tk.Frame(relay_data_display, bg="#1e293b", padx=15, pady=15)
    xor_frame.grid(row=1, column=0, columnspan=2, padx=15, pady=15, sticky="ew")

    tk.Label(xor_frame, text="⚡ XOR Operation Result", bg="#1e293b", fg="#f59e0b",
             font=("Segoe UI", 12, "bold")).pack(pady=(0, 10))
    xor_data = scrolledtext.ScrolledText(xor_frame, height=4, bg="#020617", fg="#f59e0b",
                                        font=("Consolas", 9))
    xor_data.pack(fill="both", expand=True)
    xor_data.insert(tk.END, "Waiting for XOR operation...")

    # Control buttons - centered at bottom
    control_frame = tk.Frame(center_frame, bg="#0f172a", pady=20)
    control_frame.pack(pady=(30, 0))

    # Button container for centering
    button_container = tk.Frame(control_frame, bg="#0f172a")
    button_container.pack()

    # Button to open main transmission interface
    main_button = tk.Button(
        button_container,
        text="🚀 Open Transmission Interface",
        bg="#22c55e",
        fg="white",
        font=("Segoe UI", 11, "bold"),
        command=lambda: open_main_interface(relay_window),
        padx=20,
        pady=10
    )
    main_button.pack(side="left", padx=10)

    tk.Button(
        button_container,
        text="🔄 Clear Data",
        bg="#64748b",
        fg="white",
        font=("Segoe UI", 10, "bold"),
        command=lambda: clear_relay_data(node1_data, node2_data, xor_data)
    ).pack(side="left", padx=10)

    tk.Button(
        button_container,
        text="❌ Close Window",
        bg="#dc2626",
        fg="white",
        font=("Segoe UI", 10, "bold"),
        command=relay_window.destroy
    ).pack(side="left", padx=10)

    # Store references for later use
    relay_window.node1_data = node1_data
    relay_window.node2_data = node2_data
    relay_window.xor_data = xor_data

def authenticate_relay(password_entry):
    global relay_authenticated, relay_status_label

    password = password_entry.get().strip()
    if authenticate("relay", password):
        relay_authenticated = True
        relay_status_label.config(text="Status: Authenticated ✓", fg="#22c55e")
        messagebox.showinfo("Relay Authentication", "Relay successfully authenticated!")
    else:
        relay_authenticated = False
        relay_status_label.config(text="Status: Authentication Failed ✗", fg="#dc2626")
        messagebox.showerror("Relay Authentication", "Invalid relay password!")

def open_main_interface(relay_window):
    """Open the main transmission interface window"""
    # Show the main window
    root.deiconify()
    root.lift()
    # Focus on the main window
    root.focus_force()
    # Optionally close or minimize the relay window
    # relay_window.iconify()  # Minimize instead of close

def update_relay_display(enc1, enc2, coded):
    global relay_window

    if relay_window and relay_window.winfo_exists():
        relay_window.node1_data.delete("1.0", tk.END)
        relay_window.node1_data.insert(tk.END, enc1.hex())

        relay_window.node2_data.delete("1.0", tk.END)
        relay_window.node2_data.insert(tk.END, enc2.hex())

        relay_window.xor_data.delete("1.0", tk.END)
        relay_window.xor_data.insert(tk.END, f"XOR Result: {coded.hex()}\n\nOperation: enc1 ⊕ enc2")

def start_animation_from_window():
    global anim_status_label, integrity_var
    if not anim_status_label:
        return

    # Get current integrity case from main window
    integrity_case = integrity_var.get() if integrity_var else "Normal Operation"

    # Start the animation
    animate_packet_flow(anim_status_label, integrity_case)

def replay_animation():
    global anim_status_label, integrity_var
    if not anim_status_label:
        return

    # Reset first, then replay
    reset_animation()

    # Get current integrity case from main window
    integrity_case = integrity_var.get() if integrity_var else "Normal Operation"

    # Start the animation
    animate_packet_flow(anim_status_label, integrity_case)

def create_animation_window():
    global animation_window, anim_canvas, anim_status_label

    if animation_window is not None and animation_window.winfo_exists():
        animation_window.lift()
        return anim_status_label

    # Create animation window
    animation_window = tk.Toplevel(root)
    animation_window.title("Network Coding Animation - Live Simulation")
    animation_window.geometry("800x400")
    animation_window.configure(bg="#0f172a")
    animation_window.resizable(False, False)

    # Header
    tk.Label(
        animation_window,
        text="🔄 Live Network Coding Animation",
        bg="#020617",
        fg="#e5e7eb",
        font=("Segoe UI", 16, "bold"),
        pady=10
    ).pack(fill="x")

    # Status label
    anim_status_label = tk.Label(
        animation_window,
        text="Click 'Start Animation' to begin simulation...",
        bg="#0f172a",
        fg="#60a5fa",
        font=("Segoe UI", 10),
        pady=5
    )
    anim_status_label.pack()

    # Animation canvas
    canvas_frame = tk.Frame(animation_window, bg="#020617", padx=20, pady=10)
    canvas_frame.pack(fill="both", expand=True)

    anim_canvas = tk.Canvas(canvas_frame, width=700, height=250, bg="#020617", highlightthickness=0)
    anim_canvas.pack(anchor="center")

    # Draw network topology
    anim_canvas.create_oval(150, 80, 230, 160, fill="#4ade80", outline="white", width=2)
    anim_canvas.create_text(190, 170, text="Node 1", fill="white", font=("Segoe UI", 10, "bold"))
    anim_canvas.create_oval(280, 80, 360, 160, fill="#ea580c", outline="white", width=2)
    anim_canvas.create_text(320, 170, text="Relay", fill="white", font=("Segoe UI", 10, "bold"))
    anim_canvas.create_oval(430, 80, 510, 160, fill="#f87171", outline="white", width=2)
    anim_canvas.create_text(470, 170, text="Node 2", fill="white", font=("Segoe UI", 10, "bold"))
    anim_canvas.create_line(230, 120, 280, 120, fill="#64748b", width=2)
    anim_canvas.create_line(360, 120, 430, 120, fill="#64748b", width=2)

    # Control buttons
    control_frame = tk.Frame(animation_window, bg="#0f172a", pady=10)
    control_frame.pack(fill="x")

    tk.Button(
        control_frame,
        text="▶️ Start Animation",
        bg="#16a34a",
        fg="white",
        font=("Segoe UI", 9, "bold"),
        command=lambda: start_animation_from_window()
    ).pack(side="left", padx=10)

    tk.Button(
        control_frame,
        text="🔄 Replay Animation",
        bg="#ca8a04",
        fg="white",
        font=("Segoe UI", 9, "bold"),
        command=lambda: replay_animation()
    ).pack(side="left", padx=10)

    tk.Button(
        control_frame,
        text="🔄 Reset Animation",
        bg="#64748b",
        fg="white",
        font=("Segoe UI", 9, "bold"),
        command=reset_animation
    ).pack(side="left", padx=10)

    tk.Button(
        control_frame,
        text="❌ Close Window",
        bg="#dc2626",
        fg="white",
        font=("Segoe UI", 9, "bold"),
        command=animation_window.destroy
    ).pack(side="right", padx=10)

    return anim_status_label

def reset_animation():
    global anim_canvas, anim_status_label
    if anim_canvas:
        anim_canvas.delete("packet")
    if anim_status_label:
        anim_status_label.config(text="Animation reset - Click 'Start Animation' to begin...")

def animate_packet_flow(status_label, integrity_case="Normal Operation"):
    global anim_canvas
    if not anim_canvas:
        return

    status_label.config(text="Starting transmission animation...")

    # Clear previous packets
    anim_canvas.delete("packet")

    if integrity_case == "Normal Operation":
        # Normal flow - green theme
        status_label.config(text="Sending encrypted packets to relay...")
        move_packet_anim(190, 120, 320, 120, "#60a5fa", "ENC", "n1")
        move_packet_anim(470, 120, 320, 120, "#60a5fa", "ENC", "n2")

        # Phase 2: XOR operation
        anim_canvas.after(2000, lambda: status_label.config(text="Performing XOR operation..."))
        anim_canvas.after(2000, show_xor_anim)

        # Phase 3: Send XOR results back
        anim_canvas.after(4000, lambda: status_label.config(text="Sending XOR results back to nodes..."))
        anim_canvas.after(4000, send_xor_anim)

        # Phase 4: Decryption
        anim_canvas.after(6000, lambda: status_label.config(text="Decrypting messages..."))
        anim_canvas.after(6000, show_decryption_anim)

        # Phase 5: Complete
        anim_canvas.after(8000, lambda: status_label.config(text="SUCCESS: Transmission complete!"))

    else:
        # Attack scenarios - red theme
        status_label.config(text="Sending encrypted packets to relay...")
        move_packet_anim(190, 120, 320, 120, "#60a5fa", "ENC", "n1")
        move_packet_anim(470, 120, 320, 120, "#60a5fa", "ENC", "n2")

        # Show attack indicator
        if integrity_case in ["Message 1 Modified", "Both Messages Modified"]:
            anim_canvas.after(1500, lambda: show_attack_anim(190, 120, "red", "MODIFIED"))
        if integrity_case in ["Message 2 Modified", "Both Messages Modified"]:
            anim_canvas.after(1500, lambda: show_attack_anim(470, 120, "red", "MODIFIED"))
        if integrity_case == "Hash Compromised":
            anim_canvas.after(1500, lambda: show_attack_anim(320, 80, "purple", "HASH ATTACK"))

        anim_canvas.after(1500, lambda: status_label.config(text=f"ATTACK DETECTED: {integrity_case}"))

        # Phase 2: XOR operation with tampered data
        anim_canvas.after(3000, lambda: status_label.config(text="Performing XOR operation (with compromised data)..."))
        anim_canvas.after(3000, show_xor_anim)

        # Phase 3: Send XOR results back
        anim_canvas.after(5000, lambda: status_label.config(text="Sending XOR results back..."))
        anim_canvas.after(5000, send_xor_anim)

        # Phase 4: Decryption - show integrity failure
        anim_canvas.after(7000, lambda: status_label.config(text="Decrypting messages - INTEGRITY CHECK FAILED!"))
        anim_canvas.after(7000, show_decryption_anim_failed)

        # Phase 5: Complete with error
        anim_canvas.after(9000, lambda: status_label.config(text=f"FAILED: {integrity_case} - Security breach detected!"))

def move_packet_anim(x1, y1, x2, y2, color, label, tag):
    if not anim_canvas:
        return
    p = anim_canvas.create_oval(x1, y1, x1+16, y1+16, fill=color, tags=("packet", tag))
    t = anim_canvas.create_text(x1+8, y1-12, text=label, fill="white",
                               font=("Segoe UI", 9), tags=("packet", tag))
    dx = (x2-x1)/60
    dy = (y2-y1)/60

    def step(i):
        if i < 60:
            anim_canvas.move(p, dx, dy)
            anim_canvas.move(t, dx, dy)
            anim_canvas.after(25, step, i+1)
    step(0)

def show_xor_anim():
    if not anim_canvas:
        return
    xor = anim_canvas.create_text(320, 120, text="XOR",
                                 fill="yellow", font=("Segoe UI", 14, "bold"))
    anim_canvas.after(1200, lambda: anim_canvas.delete(xor))

def send_xor_anim():
    if not anim_canvas:
        return
    move_packet_anim(320, 120, 190, 120, "#facc15", "XOR", "xor1")
    move_packet_anim(320, 120, 470, 120, "#facc15", "XOR", "xor2")

def show_attack_anim(x, y, color, label):
    if not anim_canvas:
        return
    # Show attack indicator
    attack = anim_canvas.create_oval(x-10, y-10, x+10, y+10, fill=color, outline="white", width=2)
    attack_text = anim_canvas.create_text(x, y, text=label, fill="white", font=("Segoe UI", 8, "bold"))
    # Flash effect
    def flash(count):
        if count > 0:
            current_color = anim_canvas.itemcget(attack, "fill")
            new_color = "yellow" if current_color == color else color
            anim_canvas.itemconfig(attack, fill=new_color)
            anim_canvas.after(200, lambda: flash(count - 1))
        else:
            anim_canvas.delete(attack)
            anim_canvas.delete(attack_text)
    flash(6)

def show_decryption_anim():
    if not anim_canvas:
        return
    # Show successful decryption with green indicators
    k1 = anim_canvas.create_text(190, 60, text="✅ DEC\nSUCCESS",
                                fill="#16a34a", font=("Segoe UI", 10, "bold"))
    k2 = anim_canvas.create_text(470, 60, text="✅ DEC\nSUCCESS",
                                fill="#16a34a", font=("Segoe UI", 10, "bold"))

    # Change packet labels to SUCCESS
    def replace_labels():
        for item in anim_canvas.find_withtag("xor1"):
            if anim_canvas.type(item) == "text":
                anim_canvas.itemconfig(item, text="SUCCESS")
        for item in anim_canvas.find_withtag("xor2"):
            if anim_canvas.type(item) == "text":
                anim_canvas.itemconfig(item, text="SUCCESS")

    anim_canvas.after(800, replace_labels)
    anim_canvas.after(2000, lambda: (anim_canvas.delete(k1), anim_canvas.delete(k2)))

def show_decryption_anim_failed():
    if not anim_canvas:
        return
    # Show failed decryption with red indicators
    k1 = anim_canvas.create_text(190, 60, text="❌ DEC\nFAILED",
                                fill="#dc2626", font=("Segoe UI", 10, "bold"))
    k2 = anim_canvas.create_text(470, 60, text="❌ DEC\nFAILED",
                                fill="#dc2626", font=("Segoe UI", 10, "bold"))

    # Change packet labels to ERROR
    def replace_labels():
        for item in anim_canvas.find_withtag("xor1"):
            if anim_canvas.type(item) == "text":
                anim_canvas.itemconfig(item, text="ERROR")
        for item in anim_canvas.find_withtag("xor2"):
            if anim_canvas.type(item) == "text":
                anim_canvas.itemconfig(item, text="ERROR")

    anim_canvas.after(800, replace_labels)
    anim_canvas.after(2000, lambda: (anim_canvas.delete(k1), anim_canvas.delete(k2)))

# ===================== SIMULATION =====================

def run_simulation():
    global relay_authenticated

    # Check if relay is authenticated
    if not relay_authenticated:
        messagebox.showerror("Relay Unavailable", "No relay available! Please authenticate the relay first.")
        return

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

    m1, m2 = msg1.encode(), msg2.encode()

    # ---------- INTEGRITY ----------
    h1 = generate_hash(m1)
    h2 = generate_hash(m2)

    # ---------- CONFIDENTIALITY ----------
    enc1 = encrypt(m1)
    enc2 = encrypt(m2)
    coded = xor_bytes(enc1, enc2)

    # Get integrity test case
    integrity_case = integrity_var.get()

    # Animation is now controlled separately from animation window
    # No automatic animation trigger here

    # Apply integrity modifications based on selected case
    if integrity_case == "Message 1 Modified":
        # Simulate message 1 being modified during transmission
        m1_modified = (msg1 + " [MODIFIED]").encode()
        enc1 = encrypt(m1_modified)
        coded = xor_bytes(enc1, enc2)
    elif integrity_case == "Message 2 Modified":
        # Simulate message 2 being modified during transmission
        m2_modified = (msg2 + " [MODIFIED]").encode()
        enc2 = encrypt(m2_modified)
        coded = xor_bytes(enc1, enc2)
    elif integrity_case == "Both Messages Modified":
        # Simulate both messages being modified
        m1_modified = (msg1 + " [MODIFIED]").encode()
        m2_modified = (msg2 + " [MODIFIED]").encode()
        enc1 = encrypt(m1_modified)
        enc2 = encrypt(m2_modified)
        coded = xor_bytes(enc1, enc2)
    elif integrity_case == "Hash Compromised":
        # Simulate man-in-the-middle attack on hash
        h1 = generate_hash((msg1 + " [ATTACK]").encode())  # Wrong hash
        h2 = generate_hash((msg2 + " [ATTACK]").encode())  # Wrong hash

    # Update relay display with encrypted data
    update_relay_display(enc1, enc2, coded)

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
    integrity_status = ""

    if integrity_case == "Normal Operation":
        integrity_status = "✓ INTEGRITY VERIFIED: Messages intact"
    else:
        integrity_status = "⚠ INTEGRITY TEST: " + integrity_case

    # Check integrity
    integrity_passed = True
    error_msg = ""

    if not verify_hash(d1, h2):
        integrity_passed = False
        error_msg += "Node 1 message integrity check FAILED\n"
    else:
        error_msg += "Node 1 message integrity check PASSED\n"

    if not verify_hash(d2, h1):
        integrity_passed = False
        error_msg += "Node 2 message integrity check FAILED\n"
    else:
        error_msg += "Node 2 message integrity check PASSED\n"

    # Show integrity results
    if integrity_case != "Normal Operation":
        if integrity_passed:
            messagebox.showwarning("Integrity Test Result",
                                 f"{integrity_status}\n\n{error_msg}\n"
                                 "❌ INTEGRITY CHECK SHOULD HAVE FAILED!\n"
                                 "This indicates a security vulnerability.")
        else:
            messagebox.showinfo("Integrity Test Result",
                              f"{integrity_status}\n\n{error_msg}\n"
                              "✅ INTEGRITY CHECK CORRECTLY DETECTED MODIFICATION!")

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

# ---------- INTEGRITY TEST CASES ----------
tk.Label(input_row, text="🔒 Integrity Test Cases (HAS MESSAGE BEEN MODIFIED?)", bg="#1e293b", fg="#fbbf24", font=("Segoe UI", 11, "bold")).grid(row=4, column=0, columnspan=2, pady=(10,5))

integrity_var = tk.StringVar(value="Normal Operation")
integrity_frame = tk.Frame(input_row, bg="#1e293b")
integrity_frame.grid(row=5, column=0, columnspan=2, pady=(0,15))

cases = [
    ("Normal Operation", "#4ade80"),
    ("Message 1 Modified", "#f87171"),
    ("Message 2 Modified", "#f87171"),
    ("Both Messages Modified", "#dc2626"),
    ("Hash Compromised", "#7c3aed")
]

for i, (case, color) in enumerate(cases):
    rb = tk.Radiobutton(
        integrity_frame,
        text=case,
        variable=integrity_var,
        value=case,
        bg="#1e293b",
        fg=color,
        selectcolor="#020617",
        activebackground="#1e293b",
        activeforeground=color,
        font=("Segoe UI", 9, "bold")
    )
    rb.grid(row=0, column=i, padx=10, pady=2)

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
send_button.grid(row=6, column=0, columnspan=2, pady=10)

# Animation Window Button
anim_button = tk.Button(
    input_row,
    text="🎬 Open Animation Window",
    bg="#8b5cf6",
    fg="white",
    font=("Segoe UI", 10, "bold"),
    command=create_animation_window,
    padx=15,
    pady=8
)
anim_button.grid(row=7, column=0, columnspan=2, pady=(0,10))

# Relay Window Button
relay_button = tk.Button(
    input_row,
    text="🔗 Open Relay Control Center",
    bg="#f59e0b",
    fg="white",
    font=("Segoe UI", 10, "bold"),
    command=create_relay_window,
    padx=15,
    pady=8
)
relay_button.grid(row=8, column=0, columnspan=2, pady=(0,10))

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

# Hide main window initially and open relay window by default
root.withdraw()  # Hide the main window
create_relay_window()  # Open relay window by default

root.mainloop()
