import subprocess
import os
import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext


skms_binary = os.path.join(os.path.dirname(__file__), 'skms.exe')


current_user = None
master_password = None
dark_mode_enabled = True


def run_skms_command(args):
    try:
        result = subprocess.run([skms_binary] + args, capture_output=True, text=True)
        if result.returncode != 0:
            return f"[Error] {result.stderr.strip()}"
        return result.stdout.strip()
    except Exception as e:
        return f"[Exception] {e}"


def get_theme_colors():
    if dark_mode_enabled:
        return {
            "bg": "#1e1e1e",     
            "fg": "#ffffff",     
            "btn": "#00bcd4",    
            "highlight": "#444"
        }
    else:
        return {
            "bg": "#f0f0f0",     
            "fg": "#000000",    
            "btn": "#005f99",  
            "highlight": "#ccc"
        }


def apply_theme(container):
    colors = get_theme_colors()
    container.configure(bg=colors["bg"])

    for widget in container.winfo_children():
        if isinstance(widget, tk.Button):
            widget.configure(bg=colors["btn"], fg=colors["fg"])
        elif isinstance(widget, tk.Label):
            widget.configure(bg=colors["bg"], fg=colors["fg"])
        elif isinstance(widget, scrolledtext.ScrolledText):
            widget.configure(bg=colors["bg"], fg=colors["fg"], insertbackground=colors["fg"])
        elif isinstance(widget, tk.Frame):
            apply_theme(widget)


def toggle_theme(container, toggle_btn=None):
    global dark_mode_enabled
    dark_mode_enabled = not dark_mode_enabled
    apply_theme(container)
    if toggle_btn:
        toggle_btn.configure(text=f"Switch to {'Light' if dark_mode_enabled else 'Dark'} Mode")


def register():
    global current_user, master_password
    username = simpledialog.askstring("Register", "Enter username:")
    password = simpledialog.askstring("Register", "Enter password:", show="*")
    if not username or not password:
        return
    output = run_skms_command(["register", username, password])
    if "User registered" in output:
        current_user = username
        master_password = password
        messagebox.showinfo("Success", output)
        open_dashboard()
    else:
        messagebox.showerror("Registration Failed", output)


def login():
    global current_user, master_password
    username = simpledialog.askstring("Login", "Enter username:")
    password = simpledialog.askstring("Login", "Enter password:", show="*")
    if not username or not password:
        return
    output = run_skms_command(["login", username, password])
    if "Login successful" in output:
        current_user = username
        master_password = password
        open_dashboard()
    else:
        messagebox.showerror("Login Failed", output)


def perform_action(command, extra_args=[]):
    if not current_user or not master_password:
        return messagebox.showerror("Error", "You must be logged in.")
    args = [command, current_user, master_password] + extra_args
    output = run_skms_command(args)
    output_box.delete(1.0, tk.END)
    output_box.insert(tk.END, output)


def view_key(): perform_action("viewkey")
def delete_key(): perform_action("deletekey")
def reset_key(): perform_action("resetkey")
def rotate_key(): perform_action("rotatekey")
def list_users():
    output = run_skms_command(["listusers"])
    output_box.delete(1.0, tk.END)
    output_box.insert(tk.END, output)

def delete_account():
    if messagebox.askyesno("Confirm", "Are you sure you want to delete your account?"):
        perform_action("deleteuser")

def change_password():
    global master_password
    new_pass = simpledialog.askstring("New Password", "Enter new password:", show="*")
    if new_pass:
        output = run_skms_command(["changepassword", current_user, master_password, new_pass])
        output_box.delete(1.0, tk.END)
        output_box.insert(tk.END, output)
        if "Password changed" in output:
            master_password = new_pass

def set_custom_key():
    custom = simpledialog.askstring("Custom Key", "Enter custom key (min 8 characters):")
    if custom:
        perform_action("setcustomkey", [custom])

def open_dashboard():
    root.withdraw()
    dash = tk.Toplevel()
    dash.title(f"Dashboard - {current_user}")
    dash.geometry("700x600")

    canvas = tk.Canvas(dash, borderwidth=0, highlightthickness=0)
    scrollbar = tk.Scrollbar(dash, orient="vertical", command=canvas.yview)
    scroll_frame = tk.Frame(canvas)

    scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    tk.Label(scroll_frame, text=f"Welcome, {current_user}", font=("Arial", 14, "bold")).pack(pady=10)

    global output_box
    output_box = scrolledtext.ScrolledText(scroll_frame, width=80, height=15, font=("Courier", 10))
    output_box.pack(pady=10)

    
    theme_btn = tk.Button(scroll_frame, text="Switch to Light Mode")
    theme_btn.config(command=lambda: toggle_theme(scroll_frame, theme_btn))

 
    buttons = [
        ("Register Another User", register),
        ("View Key", view_key),
        ("Delete Key", delete_key),
        ("Change Password", change_password),
        ("Reset Key", reset_key),
        ("Rotate Key", rotate_key),
        ("Set Custom Key", set_custom_key),
        ("List All Users", list_users),
        ("Delete Account", delete_account),
        ("Toggle Theme", theme_btn.invoke),
        ("Exit Dashboard", dash.destroy)
    ]

    for label, action in buttons:
        btn = tk.Button(scroll_frame, text=label, command=action, width=30, font=("Arial", 10))
        btn.pack(pady=4)

    theme_btn.pack(pady=10)
    apply_theme(scroll_frame)


root = tk.Tk()
root.title("Secure Key Management System")
root.geometry("400x250")

colors = get_theme_colors()
root.configure(bg=colors["bg"])

tk.Label(root, text="Welcome to SKMS", font=("Arial", 16, "bold"),
         bg=colors["btn"], fg=colors["fg"]).pack(pady=15)

tk.Button(root, text="Register", width=20, command=register,
          bg="green", fg="white", font=("Arial", 10)).pack(pady=5)

tk.Button(root, text="Login", width=20, command=login,
          bg="orange", fg="black", font=("Arial", 10)).pack(pady=5)

tk.Button(root, text="Exit", width=10, command=root.quit,
          bg="red", fg="white", font=("Arial", 10)).pack(pady=20)

root.mainloop()
