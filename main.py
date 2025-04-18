import os
import platform
import logging
import subprocess
import time
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox, scrolledtext, Toplevel, Text, Label, Button, PhotoImage
from datetime import datetime

# Configure logging
logging.basicConfig(filename="system_call_log.txt", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

USER_DATABASE = {
    "admin": {"password": "adminpass", "role": "admin"},
    "user1": {"password": "userpass", "role": "user"},
}

is_windows = platform.system() == "Windows"

COMMAND_MAP = {
    "pwd": "cd" if is_windows else "pwd",
    "whoami": "whoami",
    "ls": "dir" if is_windows else "ls",
    "mkdir": "mkdir",
    "touch": "type nul >" if is_windows else "touch",
    "cd": "cd",
    "cat": "type" if is_windows else "cat",
    "rm": "del" if is_windows else "rm",
    "rmdir": "rmdir /s /q" if is_windows else "rm -r",
    "getpid": "echo %PROCESS_ID%" if is_windows else "echo $$",
    "get_pids": "tasklist" if is_windows else "ps -e -o pid,cmd"
}

ADMIN_COMMANDS = list(COMMAND_MAP.keys()) + ["log"]
USER_COMMANDS = ["pwd", "whoami", "ls", "mkdir", "touch", "cd", "cat", "getpid", "rmdir", "get_pids"]

themes = ["darkly", "cyborg", "superhero", "flatly", "morph"]

class SecureSystemGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔒 Secure System Dashboard")
        self.root.geometry("1200x800")
        # self.root.resizable(False, False)
        self.root.resizable(True, True)
        self.root.state("zoomed")
        self.theme_idx = 0
        self.command_history = []
        self.history_index = -1
        self.create_login_ui()

    def create_login_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        login_frame = ttk.Frame(self.root, padding=30)
        login_frame.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(login_frame, text="🔐 Secure Login", font=("Helvetica", 18, "bold"), bootstyle="info").pack(pady=20)

        ttk.Label(login_frame, text="Username:").pack(pady=5)
        self.username_entry = ttk.Entry(login_frame, width=30)
        self.username_entry.pack()

        ttk.Label(login_frame, text="Password:").pack(pady=5)
        self.password_entry = ttk.Entry(login_frame, width=30, show="*")
        self.password_entry.pack()

        ttk.Button(login_frame, text="Login", bootstyle="primary", command=self.authenticate).pack(pady=10, fill=X)
        ttk.Button(login_frame, text="Signup", bootstyle="success", command=self.signup).pack(fill=X)

    def authenticate(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if username in USER_DATABASE and USER_DATABASE[username]["password"] == password:
            self.user = username
            self.role = USER_DATABASE[username]["role"]
            self.create_main_ui()
        else:
            messagebox.showerror("Login Failed", "Invalid credentials!")

    def signup(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            messagebox.showerror("Signup Failed", "Username and password cannot be empty!")
            return

        if username in USER_DATABASE:
            messagebox.showerror("Signup Failed", "Username already exists!")
            return

        USER_DATABASE[username] = {"password": password, "role": "user"}
        messagebox.showinfo("Signup Successful", "Account created! You can now login.")

    def create_main_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        nav = ttk.Frame(self.root, padding=10, bootstyle="info")
        nav.pack(fill=X)

        ttk.Button(nav, text="🖥️ Fullscreen", bootstyle="outline-light", command=self.toggle_fullscreen).pack(side=RIGHT, padx=5)
        ttk.Label(nav, text=f"👤 Logged in as: {self.user} ({self.role.upper()})", font=("Helvetica", 12, "bold"), bootstyle="inverse-info").pack(side=LEFT, padx=10)
        ttk.Button(nav, text="🌙 Change Theme", bootstyle="outline-light", command=self.change_theme).pack(side=RIGHT, padx=10)
        ttk.Button(nav, text="🚪 Logout", bootstyle="danger", command=self.create_login_ui).pack(side=RIGHT, padx=5)

        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=BOTH, expand=True)

        sidebar = ttk.Frame(main_frame, width=250, padding=10, bootstyle="secondary")
        sidebar.pack(side=LEFT, fill=Y)

        ttk.Label(sidebar, text="📜 Commands", font=("Helvetica", 14, "bold"), bootstyle="light").pack(pady=10)

        for cmd in (ADMIN_COMMANDS if self.role == "admin" else USER_COMMANDS):
            ttk.Button(sidebar, text=cmd, bootstyle="outline-light", command=lambda c=cmd: self.insert_command(c)).pack(fill=X, pady=2)

        content = ttk.Frame(main_frame, padding=20)
        content.pack(expand=True, fill=BOTH)

        self.command_entry = ttk.Entry(content, width=80, font=("Courier", 12))
        self.command_entry.pack(pady=5)
        self.command_entry.bind("<Return>", lambda e: self.execute_command())
        self.command_entry.bind("<Up>", self.prev_command)
        self.command_entry.bind("<Down>", self.next_command)

        ttk.Button(content, text="▶️ Execute", bootstyle="success", command=self.execute_command).pack(pady=5)

        self.output_box = scrolledtext.ScrolledText(
            content, width=100, height=20, font=("Courier", 10), bg="#111", fg="lime", insertbackground="white"
        )
        self.output_box.pack(pady=10)

        self.status_bar = ttk.Label(self.root, text=f"Ready - {datetime.now().strftime('%H:%M:%S')}", bootstyle=SECONDARY, anchor=W)
        self.status_bar.pack(fill=X, side=BOTTOM)

    def change_theme(self):
        self.theme_idx = (self.theme_idx + 1) % len(themes)
        new_theme = themes[self.theme_idx]
        self.root.style.theme_use(new_theme)

    def toggle_fullscreen(self):
        is_fullscreen = self.root.attributes("-fullscreen")
        self.root.attributes("-fullscreen", not is_fullscreen)

    def insert_command(self, cmd):
        self.command_entry.delete(0, END)
        self.command_entry.insert(END, cmd + " ")

    def prev_command(self, event):
        if self.command_history:
            self.history_index = max(0, self.history_index - 1)
            self.command_entry.delete(0, END)
            self.command_entry.insert(0, self.command_history[self.history_index])

    def next_command(self, event):
        if self.command_history:
            self.history_index = min(len(self.command_history) - 1, self.history_index + 1)
            self.command_entry.delete(0, END)
            self.command_entry.insert(0, self.command_history[self.history_index])

    def execute_command(self):
        command = self.command_entry.get().strip().split()
        if not command:
            self.output_box.insert(END, "❌ No command entered.\n")
            return

        self.command_history.append(" ".join(command))
        self.history_index = len(self.command_history)

        cmd_name = command[0]
        allowed = ADMIN_COMMANDS if self.role == "admin" else USER_COMMANDS
        if cmd_name not in allowed:
            self.output_box.insert(END, "❌ Unauthorized command!\n")
            return

        try:
            if cmd_name == "cd":
                new_path = command[1] if len(command) > 1 else os.getcwd()
                os.chdir(new_path)
                self.output_box.insert(END, f"✅ Changed directory to {os.getcwd()}\n")
                return

            if cmd_name == "mkdir" and len(command) > 1:
                os.mkdir(command[1])
                self.output_box.insert(END, f"✅ Directory created: {command[1]}\n")
                return

            if cmd_name == "touch" and len(command) > 1:
                with open(command[1], "w") as f:
                    pass
                self.output_box.insert(END, f"✅ File created: {command[1]}\n")
                return

            if cmd_name == "cat" and len(command) >= 3 and command[1] == ">>":
                filename = command[2]

                def save_text():
                    with open(filename, "a") as f:
                        f.write(text_box.get("1.0", "end-1c") + "\n")
                    self.output_box.insert(END, f"✅ Appended to {filename}\n")
                    popup.destroy()

                popup = Toplevel(self.root)
                popup.geometry("500x300")
                Label(popup, text="Enter text to append").pack()
                text_box = Text(popup)
                text_box.pack(expand=True, fill=BOTH)
                Button(popup, text="Save", command=save_text).pack()
                popup.grab_set()
                return

            if cmd_name == "rm" and len(command) > 1:
                os.remove(command[1])
                self.output_box.insert(END, f"✅ File removed: {command[1]}\n")
                return

            if cmd_name == "rmdir" and len(command) > 1:
                import shutil
                shutil.rmtree(command[1])
                self.output_box.insert(END, f"✅ Directory removed: {command[1]}\n")
                return

            if cmd_name == "log":
                try:
                    with open("system_call_log.txt", "r") as f:
                        log_content = f.read()
                    self.output_box.insert(END, f"📘 System Call Log:\n{log_content}\n")
                except FileNotFoundError:
                    self.output_box.insert(END, "❌ Log file not found.\n")
                return

            full_cmd = COMMAND_MAP.get(cmd_name, cmd_name) + " " + " ".join(command[1:])
            result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True)
            if result.stdout:
                self.output_box.insert(END, result.stdout + "\n")
            if result.stderr:
                self.output_box.insert(END, "❌ Error:\n" + result.stderr + "\n")

            logging.info(f"User: {self.user}, Role: {self.role}, Command: {' '.join(command)}")
            self.status_bar.config(text=f"Last run: {datetime.now().strftime('%H:%M:%S')}")

        except Exception as e:
            self.output_box.insert(END, f"❌ Exception: {str(e)}\n")
            self.status_bar.config(text="Execution failed.")

if __name__ == "__main__":
    root = ttk.Window(themename="darkly")
    app = SecureSystemGUI(root)
    root.mainloop()