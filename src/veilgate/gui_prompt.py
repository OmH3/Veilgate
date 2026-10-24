"""Cross-platform native GUI approval modal for Veilgate HITL authorization.

Runs in an isolated main-thread interpreter process so tkinter works reliably
on Windows, macOS, and Linux without conflicting with asyncio event loops.
"""

import ctypes
import json
import sys
import tkinter as tk


def _force_foreground_windows(root: tk.Tk) -> None:
    """Override Windows STARTUPINFO SW_HIDE inheritance from headless MCP hosts."""
    if sys.platform != "win32":
        return
    try:
        root.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id()) or root.winfo_id()
        ctypes.windll.user32.ShowWindow(hwnd, 5)  # SW_SHOW
        ctypes.windll.user32.ShowWindow(hwnd, 9)  # SW_RESTORE
        ctypes.windll.user32.SetForegroundWindow(hwnd)
    except Exception:
        pass


def show_approval_dialog(tool_name: str, server_id: str, reason: str, args_json: str) -> str:
    """Render an always-on-top dark-mode authorization popup and return '1', '2', or '3'."""
    decision = {"choice": "3"}

    root = tk.Tk()
    # Explicitly withdraw and deiconify to bypass parent STARTUPINFO SW_HIDE on Windows
    root.withdraw()
    root.title("Veilgate Zero-Trust Firewall — Authorization Required")
    root.configure(bg="#0f172a")
    root.resizable(False, False)

    # Center window on screen
    width = 560
    height = 380
    screen_w = root.winfo_screenwidth()
    screen_h = root.winfo_screenheight()
    x = max(0, (screen_w - width) // 2)
    y = max(0, (screen_h - height) // 3)
    root.geometry(f"{width}x{height}+{x}+{y}")

    def choose(val: str) -> None:
        decision["choice"] = val
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", lambda: choose("3"))
    root.bind("1", lambda _e: choose("1"))
    root.bind("2", lambda _e: choose("2"))
    root.bind("3", lambda _e: choose("3"))
    root.bind("<Escape>", lambda _e: choose("3"))

    # Header banner
    header = tk.Frame(root, bg="#1e293b", padx=20, pady=14)
    header.pack(fill=tk.X)

    badge = tk.Label(
        header,
        text="🛡 VEILGATE ZERO-TRUST MCP FIREWALL",
        bg="#1e293b",
        fg="#38bdf8",
        font=("Segoe UI", 11, "bold"),
        anchor="w",
    )
    badge.pack(fill=tk.X)

    subtitle = tk.Label(
        header,
        text="An AI agent is requesting permission to execute a guarded MCP tool.",
        bg="#1e293b",
        fg="#94a3b8",
        font=("Segoe UI", 9),
        anchor="w",
    )
    subtitle.pack(fill=tk.X, pady=(2, 0))

    # Details body
    body = tk.Frame(root, bg="#0f172a", padx=20, pady=14)
    body.pack(fill=tk.BOTH, expand=True)

    meta_text = f"Tool:    {tool_name}   (Server: {server_id})\nReason:  {reason}"
    meta_lbl = tk.Label(
        body,
        text=meta_text,
        bg="#0f172a",
        fg="#f8fafc",
        font=("Consolas", 10, "bold"),
        justify=tk.LEFT,
        anchor="w",
    )
    meta_lbl.pack(fill=tk.X, pady=(0, 8))

    args_lbl = tk.Label(
        body,
        text="Arguments:",
        bg="#0f172a",
        fg="#94a3b8",
        font=("Segoe UI", 9, "bold"),
        anchor="w",
    )
    args_lbl.pack(fill=tk.X)

    args_box = tk.Text(
        body,
        height=6,
        bg="#1e293b",
        fg="#e2e8f0",
        font=("Consolas", 9),
        relief=tk.FLAT,
        padx=10,
        pady=8,
        wrap=tk.WORD,
    )
    try:
        parsed = json.loads(args_json)
        formatted_args = json.dumps(parsed, indent=2, ensure_ascii=False)
    except Exception:
        formatted_args = args_json
    args_box.insert("1.0", formatted_args[:600])
    args_box.configure(state=tk.DISABLED)
    args_box.pack(fill=tk.BOTH, expand=True, pady=(4, 10))

    # Action buttons
    btn_frame = tk.Frame(root, bg="#0f172a", padx=20, pady=14)
    btn_frame.pack(fill=tk.X, side=tk.BOTTOM)

    btn_once = tk.Button(
        btn_frame,
        text="[1] Allow Once",
        command=lambda: choose("1"),
        bg="#0284c7",
        fg="#ffffff",
        activebackground="#0369a1",
        activeforeground="#ffffff",
        font=("Segoe UI", 10, "bold"),
        relief=tk.FLAT,
        padx=14,
        pady=8,
        cursor="hand2",
    )
    btn_once.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 6))

    btn_always = tk.Button(
        btn_frame,
        text="[2] Allow Always",
        command=lambda: choose("2"),
        bg="#16a34a",
        fg="#ffffff",
        activebackground="#15803d",
        activeforeground="#ffffff",
        font=("Segoe UI", 10, "bold"),
        relief=tk.FLAT,
        padx=14,
        pady=8,
        cursor="hand2",
    )
    btn_always.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=6)

    btn_deny = tk.Button(
        btn_frame,
        text="[3] Deny",
        command=lambda: choose("3"),
        bg="#dc2626",
        fg="#ffffff",
        activebackground="#b91c1c",
        activeforeground="#ffffff",
        font=("Segoe UI", 10, "bold"),
        relief=tk.FLAT,
        padx=14,
        pady=8,
        cursor="hand2",
    )
    btn_deny.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(6, 0))

    root.deiconify()
    root.attributes("-topmost", True)
    root.lift()
    root.focus_force()
    root.after(50, lambda: _force_foreground_windows(root))

    root.mainloop()
    return decision["choice"]


def main() -> None:
    """CLI entrypoint for internal popup subprocess."""
    if len(sys.argv) < 5:
        sys.stdout.write("3\n")
        sys.stdout.flush()
        return

    tool_name = sys.argv[1]
    server_id = sys.argv[2]
    reason = sys.argv[3]
    args_json = sys.argv[4]
    choice = show_approval_dialog(tool_name, server_id, reason, args_json)
    sys.stdout.write(f"{choice}\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
