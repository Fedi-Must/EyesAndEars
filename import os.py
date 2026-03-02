import base64
import csv
import ctypes
import io
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import warnings
from ctypes import wintypes
from pathlib import Path
from threading import Event, Lock, Thread
import tkinter as tk

import keyboard
import PIL.Image
import PIL.ImageDraw
import PIL.ImageGrab
import pyperclip
import requests

try:
    import pystray
except Exception:
    pystray = None

APP_NAME = "EyesAndEars"
APP_VERSION = "2.1.0"
CONFIG_FILE_NAME = "config.json"
DEFAULT_SERVER_URL = os.environ.get("EAE_SERVER_URL", "http://localhost:8000").strip().rstrip("/")
DEFAULT_MODEL_NAME = os.environ.get("EAE_MODEL_NAME", "gemini-2.5-flash").strip()
DEFAULT_WINGET_PACKAGE_ID = os.environ.get("EYESANDEARS_WINGET_ID", "").strip()
SELF_UNINSTALL_DELAY_SECONDS = 2
API_KEY_ENV_FALLBACK = ("EYESANDEARS_API_KEY", "EAE_API_KEY")
SW_HIDE = 0
CRYPTPROTECT_UI_FORBIDDEN = 0x01

PROMPT_TEXT = (
    "Analyze the image provided. Your goal is to provide the direct answer/solution and NOTHING else.\n\n"
    "RULES:\n"
    "1. If it is a Multiple Choice Question: Output ONLY the correct letter (e.g., 'A', 'B'). Do not write the text of the option.\n"
    "2. If it is a coding error/task: Output ONLY the corrected code block. Do not use Markdown formatting (no python ... ). Just the raw code ready to run.\n"
    "3. If it is a general question: Output ONLY the direct answer.\n"
    "4. ABSOLUTELY NO conversational filler, no 'Here is the answer', no explanations, no markdown backticks.\n"
    "5. If unclear, find the most likely question on screen and answer it."
)

current_answer = ""
current_index = 0
last_answer = ""
is_processing = False
is_paused = False
pause_pending = False
typing_hook = None
write_lock = Lock()
hotkey_block_until = {
    "primary": 0.0,
    "indicator": 0.0,
    "clear_ctx": 0.0,
    "paste_all": 0.0,
    "repeat_prev": 0.0,
    "exit": 0.0,
}

auth_mode = "license"
server_url = DEFAULT_SERVER_URL
license_code = ""
api_key = ""
model_name = DEFAULT_MODEL_NAME
device_id = ""

session_lock = Lock()
session_id = ""
session_token = ""
session_status_text = "Not authenticated"
session_active = False
user_email = ""
license_hint = ""
heartbeat_interval_seconds = 20
heartbeat_timeout_seconds = 90

local_model = None
local_chat_session = None
api_backend_name = "none"

heartbeat_stop_event = Event()
heartbeat_thread = None

tray_icon = None
indicator = None
privacy_guard_thread = None
privacy_guard_stop_event = Event()
privacy_forced_hidden = False
indicator_manual_hidden = False
indicator_capture_protected = False

INDICATOR_VISIBLE_BY_DEFAULT = os.environ.get("EAE_SHOW_INDICATOR", "").strip().lower() not in {"0", "false", "no", "off"}
HIDE_INDICATOR_FROM_CAPTURE = os.environ.get("EAE_HIDE_INDICATOR_FROM_CAPTURE", "").strip().lower() not in {"0", "false", "no", "off"}
STRICT_PRIVACY_FALLBACK = os.environ.get("EAE_STRICT_PRIVACY_FALLBACK", "").strip().lower() in {"1", "true", "yes", "on"}
PRIVACY_GUARD_INTERVAL_SECONDS = 2.0
PRIVACY_GUARD_PROCESSES = {
    "discord.exe",
    "obs64.exe",
    "obs32.exe",
    "teams.exe",
    "ms-teams.exe",
    "zoom.exe",
    "webexmta.exe",
    "slack.exe",
}
PRIVACY_MEET_BROWSERS = {
    "chrome.exe",
    "msedge.exe",
    "brave.exe",
    "opera.exe",
    "firefox.exe",
}
PRIVACY_MEET_WINDOW_KEYWORDS = ("google meet", " meet", "meet ")

UI_BG = "#E6EDF8"
UI_CARD_BG = "#F4F8FF"
UI_PANEL_BG = "#FFFFFF"
UI_FIELD_BG = "#F9FBFF"
UI_TEXT = "#102A56"
UI_MUTED = "#4C6082"
UI_BORDER = "#C7D7F2"
UI_SOFT = "#DEE9FF"
UI_PRIMARY = "#1459D9"
UI_PRIMARY_ACTIVE = "#0F46AD"
UI_PRIMARY_SOFT = "#9FBBF5"
UI_GHOST_BG = "#EDF3FF"
UI_GHOST_ACTIVE = "#DFEAFE"
UI_DANGER = "#BA1A1A"
UI_ACCENT = "#1C77FF"
UI_FONT = "Segoe UI Variable Text"


def resolve_install_root():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def resolve_data_dir(install_root):
    portable_data_dir = install_root / ".eyesandears"
    try:
        portable_data_dir.mkdir(parents=True, exist_ok=True)
        probe = portable_data_dir / ".write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return portable_data_dir
    except Exception:
        fallback_data_dir = Path(os.environ.get("APPDATA", ".")) / APP_NAME
        fallback_data_dir.mkdir(parents=True, exist_ok=True)
        return fallback_data_dir


APP_INSTALL_ROOT = resolve_install_root()
APP_DATA_DIR = resolve_data_dir(APP_INSTALL_ROOT)
CONFIG_FILE = APP_DATA_DIR / CONFIG_FILE_NAME

if os.name == "nt":
    HRESULT = getattr(wintypes, "HRESULT", ctypes.c_long)
    WDA_NONE = 0x0
    WDA_MONITOR = 0x1
    WDA_EXCLUDEFROMCAPTURE = 0x11
    GA_ROOT = 2
    DWMWA_USE_IMMERSIVE_DARK_MODE = 20
    DWMWA_WINDOW_CORNER_PREFERENCE = 33
    DWMWA_SYSTEMBACKDROP_TYPE = 38
    DWMWCP_ROUND = 2
    DWMSBT_MAINWINDOW = 2

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_byte)),
        ]

    _crypt32 = ctypes.windll.crypt32
    _kernel32 = ctypes.windll.kernel32
    _user32 = ctypes.windll.user32
    _dwmapi = ctypes.windll.dwmapi
    _gdi32 = ctypes.windll.gdi32
    _crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        wintypes.LPCWSTR,
        ctypes.POINTER(DATA_BLOB),
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB),
    ]
    _crypt32.CryptProtectData.restype = wintypes.BOOL
    _crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(DATA_BLOB),
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB),
    ]
    _crypt32.CryptUnprotectData.restype = wintypes.BOOL
    _kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    _kernel32.LocalFree.restype = wintypes.HLOCAL
    _user32.SetWindowDisplayAffinity.argtypes = [wintypes.HWND, wintypes.DWORD]
    _user32.SetWindowDisplayAffinity.restype = wintypes.BOOL
    _user32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
    _user32.GetAncestor.restype = wintypes.HWND
    _user32.GetForegroundWindow.argtypes = []
    _user32.GetForegroundWindow.restype = wintypes.HWND
    _user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    _user32.GetWindowTextW.restype = ctypes.c_int
    _user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    _user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    _user32.SetWindowRgn.argtypes = [wintypes.HWND, wintypes.HANDLE, wintypes.BOOL]
    _user32.SetWindowRgn.restype = ctypes.c_int
    _dwmapi.DwmSetWindowAttribute.argtypes = [
        wintypes.HWND,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    _dwmapi.DwmSetWindowAttribute.restype = HRESULT
    _gdi32.CreateRoundRectRgn.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
    ]
    _gdi32.CreateRoundRectRgn.restype = wintypes.HANDLE
    _gdi32.DeleteObject.argtypes = [wintypes.HANDLE]
    _gdi32.DeleteObject.restype = wintypes.BOOL


def hide_console_window():
    if os.name != "nt":
        return
    try:
        console_window = ctypes.windll.kernel32.GetConsoleWindow()
        if console_window:
            ctypes.windll.user32.ShowWindow(console_window, SW_HIDE)
    except Exception:
        pass


def set_window_capture_excluded(hwnd, enabled=True):
    if os.name != "nt":
        return False
    try:
        normalized = int(hwnd or 0)
        if not normalized:
            return False
        top_level = int(_user32.GetAncestor(wintypes.HWND(normalized), GA_ROOT) or 0)
        if top_level:
            normalized = top_level
        if not enabled:
            return bool(_user32.SetWindowDisplayAffinity(wintypes.HWND(normalized), WDA_NONE))
        # Preferred (Win10 2004+): completely exclude from capture.
        if _user32.SetWindowDisplayAffinity(wintypes.HWND(normalized), WDA_EXCLUDEFROMCAPTURE):
            return True
        # Fallback: capture sees a blank/black window while user still sees it locally.
        return bool(_user32.SetWindowDisplayAffinity(wintypes.HWND(normalized), WDA_MONITOR))
    except Exception:
        return False


def apply_capture_privacy_to_window(window, enabled=True):
    if os.name != "nt" or window is None:
        return False
    try:
        if not window.winfo_exists():
            return False
        window.update_idletasks()
        return set_window_capture_excluded(window.winfo_id(), enabled=enabled)
    except Exception:
        return False


def schedule_window_privacy_refresh(window, refresh_ms=1800):
    if os.name != "nt" or not HIDE_INDICATOR_FROM_CAPTURE or window is None:
        return
    if getattr(window, "_eae_privacy_refresh_enabled", False):
        return
    window._eae_privacy_refresh_enabled = True

    def _tick():
        try:
            if not window.winfo_exists():
                return
            apply_capture_privacy_to_window(window, enabled=True)
            window.after(refresh_ms, _tick)
        except Exception:
            pass

    try:
        window.after(80, _tick)
    except Exception:
        pass


def configure_private_window(window, *, dark=False, refresh_ms=1800):
    apply_win11_window_style(window, dark=dark)
    if HIDE_INDICATOR_FROM_CAPTURE:
        apply_capture_privacy_to_window(window, enabled=True)
        schedule_window_privacy_refresh(window, refresh_ms=refresh_ms)


def apply_window_corner_region(window, radius):
    if os.name != "nt" or window is None:
        return False
    try:
        if not window.winfo_exists():
            return False
        window.update_idletasks()
        width = int(max(1, window.winfo_width()))
        height = int(max(1, window.winfo_height()))
        radius = int(max(2, min(radius, width // 2, height // 2)))
        region = _gdi32.CreateRoundRectRgn(0, 0, width + 1, height + 1, radius * 2, radius * 2)
        if not region:
            return False
        hwnd = wintypes.HWND(window.winfo_id())
        applied = bool(_user32.SetWindowRgn(hwnd, region, True))
        if not applied:
            _gdi32.DeleteObject(region)
        return applied
    except Exception:
        return False


def draw_rounded_canvas_rect(canvas, x1, y1, x2, y2, radius, **kwargs):
    radius = int(max(0, min(radius, (x2 - x1) // 2, (y2 - y1) // 2)))
    if radius <= 0:
        return canvas.create_rectangle(x1, y1, x2, y2, **kwargs)
    points = [
        x1 + radius, y1,
        x1 + radius, y1,
        x2 - radius, y1,
        x2 - radius, y1,
        x2, y1,
        x2, y1 + radius,
        x2, y1 + radius,
        x2, y2 - radius,
        x2, y2 - radius,
        x2, y2,
        x2 - radius, y2,
        x2 - radius, y2,
        x1 + radius, y2,
        x1 + radius, y2,
        x1, y2,
        x1, y2 - radius,
        x1, y2 - radius,
        x1, y1 + radius,
        x1, y1 + radius,
        x1, y1,
    ]
    return canvas.create_polygon(points, smooth=True, splinesteps=24, **kwargs)


def apply_win11_window_style(window, dark=False):
    if os.name != "nt":
        return
    try:
        window.update_idletasks()
        hwnd = wintypes.HWND(window.winfo_id())
        rounded = ctypes.c_int(DWMWCP_ROUND)
        backdrop = ctypes.c_int(DWMSBT_MAINWINDOW)
        dark_mode = ctypes.c_int(1 if dark else 0)
        _dwmapi.DwmSetWindowAttribute(
            hwnd,
            DWMWA_WINDOW_CORNER_PREFERENCE,
            ctypes.byref(rounded),
            ctypes.sizeof(rounded),
        )
        _dwmapi.DwmSetWindowAttribute(
            hwnd,
            DWMWA_SYSTEMBACKDROP_TYPE,
            ctypes.byref(backdrop),
            ctypes.sizeof(backdrop),
        )
        _dwmapi.DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE,
            ctypes.byref(dark_mode),
            ctypes.sizeof(dark_mode),
        )
    except Exception:
        pass


def bytes_to_blob(raw_bytes):
    if not raw_bytes:
        return DATA_BLOB(0, None), None
    raw_buffer = (ctypes.c_byte * len(raw_bytes)).from_buffer_copy(raw_bytes)
    blob = DATA_BLOB(len(raw_bytes), ctypes.cast(raw_buffer, ctypes.POINTER(ctypes.c_byte)))
    return blob, raw_buffer


def blob_to_bytes(blob):
    if not blob.cbData:
        return b""
    return ctypes.string_at(blob.pbData, blob.cbData)


def encrypt_with_dpapi(plain_text):
    if os.name != "nt":
        return ""
    plain_bytes = plain_text.encode("utf-8")
    in_blob, _ = bytes_to_blob(plain_bytes)
    out_blob = DATA_BLOB()
    if not _crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        "EyesAndEars Secret",
        None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    ):
        return ""
    try:
        protected_bytes = blob_to_bytes(out_blob)
        return base64.b64encode(protected_bytes).decode("ascii")
    finally:
        _kernel32.LocalFree(out_blob.pbData)


def decrypt_with_dpapi(cipher_b64):
    if os.name != "nt":
        return ""
    try:
        cipher_bytes = base64.b64decode(cipher_b64)
    except Exception:
        return ""
    in_blob, _ = bytes_to_blob(cipher_bytes)
    out_blob = DATA_BLOB()
    description = wintypes.LPWSTR()
    if not _crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        ctypes.byref(description),
        None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    ):
        return ""
    try:
        plain_bytes = blob_to_bytes(out_blob)
        return plain_bytes.decode("utf-8")
    except Exception:
        return ""
    finally:
        if description:
            _kernel32.LocalFree(description)
        _kernel32.LocalFree(out_blob.pbData)


def load_config_record():
    if not CONFIG_FILE.exists():
        return {}
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def save_config_record(record):
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(record, indent=2), encoding="utf-8")


def load_saved_secret(record, plain_key, encrypted_key):
    encrypted = str(record.get(encrypted_key, "")).strip()
    if encrypted:
        decrypted = decrypt_with_dpapi(encrypted)
        if decrypted:
            return decrypted
    legacy = str(record.get(plain_key, "")).strip()
    if legacy:
        encrypted = encrypt_with_dpapi(legacy)
        if encrypted:
            record[encrypted_key] = encrypted
            record.pop(plain_key, None)
            save_config_record(record)
        return legacy
    return ""


def save_secret(record, plain_key, encrypted_key, value):
    encrypted = encrypt_with_dpapi(value)
    record.pop(plain_key, None)
    if encrypted:
        record[encrypted_key] = encrypted
    elif os.name != "nt":
        record[plain_key] = value
    else:
        return False
    save_config_record(record)
    return True


def find_env_api_key():
    for env_name in API_KEY_ENV_FALLBACK:
        value = os.environ.get(env_name, "").strip()
        if value:
            return value
    return ""


def center_window(window, width, height):
    window.update_idletasks()
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = max(0, (screen_width - width) // 2)
    y = max(0, (screen_height - height) // 2)
    window.geometry(f"{width}x{height}+{x}+{y}")


def fit_window_to_content(window, min_width=0, min_height=0, max_width=0, max_height=0):
    try:
        window.update_idletasks()
        target_width = max(int(min_width), int(window.winfo_width()), int(window.winfo_reqwidth()))
        target_height = max(int(min_height), int(window.winfo_height()), int(window.winfo_reqheight()))
        if max_width:
            target_width = min(target_width, int(max_width))
        if max_height:
            target_height = min(target_height, int(max_height))
        center_window(window, target_width, target_height)
    except Exception:
        pass


def make_dialog_shell(title, width, height, parent=None):
    root = tk.Toplevel(parent) if parent else tk.Tk()
    root.title(title)
    root.configure(bg=UI_BG)
    root.resizable(False, False)
    center_window(root, width, height)
    configure_private_window(root, dark=False)
    if parent:
        try:
            root.transient(parent)
        except Exception:
            pass
    root.lift()
    try:
        root.attributes("-topmost", True)
        root.after(250, lambda: root.attributes("-topmost", False))
    except Exception:
        pass

    shell = tk.Frame(root, bg=UI_BG, bd=0)
    shell.pack(fill="both", expand=True, padx=18, pady=16)

    accent = tk.Frame(shell, bg=UI_ACCENT, height=5, bd=0)
    accent.pack(fill="x", pady=(0, 10))

    card = tk.Frame(
        shell,
        bg=UI_CARD_BG,
        highlightbackground=UI_BORDER,
        highlightthickness=1,
        bd=0,
    )
    card.pack(fill="both", expand=True)
    return root, card


def style_button(widget, *, primary=False, active=False):
    if primary:
        widget.configure(
            bg=UI_PRIMARY,
            fg="white",
            activebackground=UI_PRIMARY_ACTIVE,
            activeforeground="white",
            highlightbackground=UI_PRIMARY,
            highlightcolor=UI_PRIMARY,
        )
        return
    if active:
        widget.configure(
            bg=UI_SOFT,
            fg=UI_TEXT,
            activebackground=UI_SOFT,
            activeforeground=UI_TEXT,
            highlightbackground=UI_SOFT,
            highlightcolor=UI_SOFT,
        )
        return
    widget.configure(
        bg=UI_GHOST_BG,
        fg=UI_TEXT,
        activebackground=UI_GHOST_ACTIVE,
        activeforeground=UI_TEXT,
        highlightbackground=UI_BORDER,
        highlightcolor=UI_BORDER,
    )


def show_styled_message(title, message, is_error=False, ask_retry=False, parent=None):
    result = {"value": False}
    message_text = str(message or "")
    base_height = 350 if ask_retry else 330
    line_count = message_text.count("\n") + 1
    estimated_height = min(600, base_height + max(0, line_count - 6) * 14 + max(0, len(message_text) - 260) // 20)
    root, card = make_dialog_shell(title, 620, estimated_height, parent=parent)

    heading = "Connection issue" if ask_retry else ("Error" if is_error else "Information")
    heading_color = UI_DANGER if is_error else UI_TEXT

    header = tk.Frame(card, bg=UI_CARD_BG, bd=0)
    header.pack(fill="x", padx=28, pady=(24, 10))
    tk.Label(header, text=heading, bg=UI_CARD_BG, fg=heading_color, font=(UI_FONT, 20, "bold")).pack(anchor="w")

    content = tk.Frame(card, bg=UI_PANEL_BG, highlightbackground=UI_BORDER, highlightthickness=1, bd=0)
    content.pack(fill="both", expand=True, padx=28, pady=(0, 12))
    tk.Label(
        content,
        text=message_text,
        bg=UI_PANEL_BG,
        fg=UI_TEXT,
        font=(UI_FONT, 11),
        justify="left",
        wraplength=530,
    ).pack(anchor="w", padx=16, pady=16)

    button_bar = tk.Frame(card, bg=UI_CARD_BG, bd=0)
    button_bar.pack(fill="x", padx=28, pady=(0, 22))

    def close_with(value=False):
        result["value"] = value
        root.destroy()

    if ask_retry:
        exit_btn = tk.Button(
            button_bar,
            text="Exit",
            command=lambda: close_with(False),
            relief="flat",
            bd=0,
            padx=18,
            pady=10,
            font=(UI_FONT, 10, "bold"),
            cursor="hand2",
        )
        style_button(exit_btn, primary=False)
        exit_btn.pack(side="right")

        retry_btn = tk.Button(
            button_bar,
            text="Retry Login",
            command=lambda: close_with(True),
            relief="flat",
            bd=0,
            padx=18,
            pady=10,
            font=(UI_FONT, 10, "bold"),
            cursor="hand2",
        )
        style_button(retry_btn, primary=True)
        retry_btn.pack(side="right", padx=(0, 10))
    else:
        close_btn = tk.Button(
            button_bar,
            text="OK",
            command=root.destroy,
            relief="flat",
            bd=0,
            padx=20,
            pady=10,
            font=(UI_FONT, 10, "bold"),
            cursor="hand2",
        )
        style_button(close_btn, primary=True)
        close_btn.pack(side="right")

    fit_window_to_content(root, min_width=620, min_height=estimated_height, max_width=820, max_height=620)
    root.protocol("WM_DELETE_WINDOW", root.destroy if not ask_retry else lambda: close_with(False))
    root.bind("<Escape>", lambda _event: root.destroy() if not ask_retry else close_with(False))
    if parent:
        try:
            root.grab_set()
            parent.wait_window(root)
        except Exception:
            pass
    else:
        root.mainloop()
    return bool(result["value"])


def prompt_startup_auth(initial_server_url, initial_license, initial_api_key):
    result = {"value": None}
    root, card = make_dialog_shell(f"{APP_NAME} Sign In", 780, 620)

    mode_var = tk.StringVar(value="license")
    server_var = tk.StringVar(value=(initial_server_url or DEFAULT_SERVER_URL or "http://localhost:8000"))
    license_var = tk.StringVar(value=initial_license or "")
    api_var = tk.StringVar(value=initial_api_key or "")
    show_api_var = tk.BooleanVar(value=False)
    error_var = tk.StringVar(value="")

    if not initial_license and initial_api_key:
        mode_var.set("api")

    header = tk.Frame(card, bg=UI_CARD_BG, bd=0)
    header.pack(fill="x", padx=30, pady=(24, 10))
    tk.Label(header, text="Eyes & Ears", bg=UI_CARD_BG, fg=UI_TEXT, font=(UI_FONT, 31, "bold")).pack(anchor="w", pady=(0, 2))
    tk.Label(
        header,
        text="Private startup authentication",
        bg=UI_CARD_BG,
        fg=UI_MUTED,
        font=(UI_FONT, 12),
    ).pack(anchor="w")
    tk.Label(
        header,
        text="Numpad 1 capture  |  Numpad 0 indicator  |  Numpad 9 quit",
        bg=UI_CARD_BG,
        fg=UI_MUTED,
        font=(UI_FONT, 9),
    ).pack(anchor="w", pady=(6, 0))

    switch_shell = tk.Frame(card, bg=UI_SOFT, highlightbackground=UI_BORDER, highlightthickness=1, bd=0)
    switch_shell.pack(fill="x", padx=30, pady=(0, 12))
    mode_license_btn = tk.Button(
        switch_shell,
        text="Use Subscription Code",
        relief="flat",
        bd=0,
        padx=16,
        pady=11,
        font=(UI_FONT, 11, "bold"),
        cursor="hand2",
        command=lambda: set_mode("license"),
    )
    mode_api_btn = tk.Button(
        switch_shell,
        text="Use My API Key",
        relief="flat",
        bd=0,
        padx=16,
        pady=11,
        font=(UI_FONT, 11, "bold"),
        cursor="hand2",
        command=lambda: set_mode("api"),
    )
    mode_license_btn.pack(side="left", fill="x", expand=True, padx=(6, 3), pady=6)
    mode_api_btn.pack(side="left", fill="x", expand=True, padx=(3, 6), pady=6)

    form_panel = tk.Frame(card, bg=UI_PANEL_BG, highlightbackground=UI_BORDER, highlightthickness=1, bd=0)
    form_panel.pack(fill="both", expand=True, padx=30, pady=(0, 12))
    form_content = tk.Frame(form_panel, bg=UI_PANEL_BG, bd=0)
    form_content.pack(fill="both", expand=True, padx=18, pady=16)

    license_frame = tk.Frame(form_content, bg=UI_PANEL_BG, bd=0)
    api_frame = tk.Frame(form_content, bg=UI_PANEL_BG, bd=0)

    def make_labeled_entry(parent, label_text, var, *, show=None):
        tk.Label(parent, text=label_text, bg=UI_PANEL_BG, fg=UI_TEXT, font=(UI_FONT, 10, "bold")).pack(anchor="w", pady=(0, 6))
        field = tk.Frame(parent, bg=UI_FIELD_BG, highlightbackground=UI_BORDER, highlightthickness=1, bd=0)
        field.pack(fill="x")
        entry = tk.Entry(
            field,
            textvariable=var,
            show=show if show else "",
            bg=UI_FIELD_BG,
            fg=UI_TEXT,
            relief="flat",
            bd=0,
            insertbackground=UI_TEXT,
            font=(UI_FONT, 11),
        )
        entry.pack(fill="x", padx=12, pady=10)
        return entry

    server_entry = make_labeled_entry(license_frame, "Server URL", server_var)
    tk.Label(
        license_frame,
        text="Your subscription server endpoint",
        bg=UI_PANEL_BG,
        fg=UI_MUTED,
        font=(UI_FONT, 9),
    ).pack(anchor="w", pady=(4, 12))

    license_entry = make_labeled_entry(license_frame, "Subscription code (name + 6 digits)", license_var)
    tk.Label(
        license_frame,
        text="Example: FEDI123456",
        bg=UI_PANEL_BG,
        fg=UI_MUTED,
        font=(UI_FONT, 9),
    ).pack(anchor="w", pady=(4, 0))

    api_entry = make_labeled_entry(api_frame, "Gemini API key", api_var, show="*")
    api_options = tk.Frame(api_frame, bg=UI_PANEL_BG, bd=0)
    api_options.pack(fill="x", pady=(8, 0))

    def toggle_show_api():
        show_api = not show_api_var.get()
        show_api_var.set(show_api)
        api_entry.configure(show="" if show_api else "*")
        show_api_btn.configure(text="Hide API key" if show_api else "Show API key")

    show_api_btn = tk.Button(
        api_options,
        text="Show API key",
        command=toggle_show_api,
        relief="flat",
        bd=0,
        padx=12,
        pady=6,
        font=(UI_FONT, 9, "bold"),
        cursor="hand2",
    )
    style_button(show_api_btn, primary=False)
    show_api_btn.pack(side="left")

    tk.Label(
        api_frame,
        text="Stored locally with Windows data protection (DPAPI).",
        bg=UI_PANEL_BG,
        fg=UI_MUTED,
        font=(UI_FONT, 9),
    ).pack(anchor="w", pady=(10, 0))

    info_row = tk.Frame(card, bg=UI_CARD_BG, bd=0)
    info_row.pack(fill="x", padx=30, pady=(0, 2))
    tk.Label(
        info_row,
        text="DPAPI-protected local secrets and capture-privacy window mode enabled",
        bg=UI_CARD_BG,
        fg=UI_MUTED,
        font=(UI_FONT, 9),
    ).pack(anchor="w")

    tk.Label(card, textvariable=error_var, bg=UI_CARD_BG, fg=UI_DANGER, font=(UI_FONT, 10, "bold")).pack(
        fill="x", anchor="w", padx=30, pady=(2, 4)
    )

    button_bar = tk.Frame(card, bg=UI_CARD_BG, bd=0)
    button_bar.pack(fill="x", padx=30, pady=(0, 24))

    def on_cancel():
        result["value"] = None
        root.destroy()

    def on_continue():
        error_var.set("")
        selected_mode = mode_var.get().strip()
        if selected_mode == "license":
            entered_server = server_var.get().strip().rstrip("/")
            if not entered_server:
                entered_server = (initial_server_url or DEFAULT_SERVER_URL or "http://localhost:8000").strip().rstrip("/")
            entered_license = license_var.get().strip()
            if not entered_license:
                error_var.set("Please enter your subscription code.")
                license_entry.focus_set()
                return
            result["value"] = {
                "mode": "license",
                "server_url": entered_server,
                "license_code": entered_license,
            }
        else:
            entered_api_key = api_var.get().strip()
            if not entered_api_key:
                error_var.set("Please enter your Gemini API key.")
                api_entry.focus_set()
                return
            result["value"] = {"mode": "api", "api_key": entered_api_key}
        root.destroy()

    cancel_btn = tk.Button(
        button_bar,
        text="Cancel",
        command=on_cancel,
        relief="flat",
        bd=0,
        padx=20,
        pady=10,
        font=(UI_FONT, 10, "bold"),
        cursor="hand2",
    )
    style_button(cancel_btn, primary=False)
    cancel_btn.pack(side="right")

    continue_btn = tk.Button(
        button_bar,
        text="Continue",
        command=on_continue,
        relief="flat",
        bd=0,
        padx=22,
        pady=10,
        font=(UI_FONT, 10, "bold"),
        cursor="hand2",
    )
    style_button(continue_btn, primary=True)
    continue_btn.pack(side="right", padx=(0, 10))

    def set_mode(next_mode):
        mode_var.set(next_mode)
        update_mode_ui()

    def update_mode_ui():
        is_license = mode_var.get() == "license"
        style_button(mode_license_btn, active=not is_license, primary=is_license)
        style_button(mode_api_btn, active=is_license, primary=not is_license)
        if is_license:
            api_frame.pack_forget()
            license_frame.pack(fill="x", pady=(0, 8))
            license_entry.focus_set()
        else:
            license_frame.pack_forget()
            api_frame.pack(fill="x", pady=(0, 8))
            api_entry.focus_set()

    root.protocol("WM_DELETE_WINDOW", on_cancel)
    root.bind("<Escape>", lambda _event: on_cancel())
    root.bind("<Return>", lambda _event: on_continue())
    update_mode_ui()
    fit_window_to_content(root, min_width=780, min_height=620, max_width=940, max_height=760)
    root.mainloop()
    return result["value"]


def gui_ask_retry_license(message):
    parent = indicator.root if indicator and indicator.root.winfo_exists() else None
    return show_styled_message(APP_NAME, f"{message}\n\nRetry code login?", ask_retry=True, parent=parent)


def gui_show_error(message):
    parent = indicator.root if indicator and indicator.root.winfo_exists() else None
    show_styled_message(APP_NAME, message, is_error=True, parent=parent)


def set_session_status(text, active=None):
    global session_status_text, session_active
    with session_lock:
        session_status_text = text
        if active is not None:
            session_active = bool(active)
    update_tray_menu()


def update_tray_menu():
    global tray_icon
    try:
        if tray_icon:
            tray_icon.update_menu()
    except Exception:
        pass


def resolve_auth_settings():
    global auth_mode, server_url, license_code, api_key, device_id
    record = load_config_record()
    env_server = os.environ.get("EAE_SERVER_URL", "").strip().rstrip("/")
    env_license = os.environ.get("EAE_LICENSE_CODE", "").strip()
    env_api_key = find_env_api_key()
    saved_server = str(record.get("server_url", "")).strip().rstrip("/")
    saved_license = load_saved_secret(record, "license_code", "license_code_dpapi")
    saved_api_key = load_saved_secret(record, "api_key", "api_key_dpapi")
    saved_device_id = str(record.get("device_id", "")).strip()
    if not saved_device_id:
        saved_device_id = secrets.token_hex(16)
        record["device_id"] = saved_device_id

    selected = prompt_startup_auth(
        initial_server_url=env_server or saved_server or DEFAULT_SERVER_URL or "http://localhost:8000",
        initial_license=env_license or saved_license,
        initial_api_key=env_api_key or saved_api_key,
    )
    if not selected:
        return False

    selected_mode = selected["mode"]
    if selected_mode == "license":
        selected_server = selected["server_url"]
        selected_license = selected["license_code"]
        record["auth_mode"] = "license"
        record["server_url"] = selected_server
        if not save_secret(record, "license_code", "license_code_dpapi", selected_license):
            gui_show_error("Could not securely save your code on this machine.")
            return False
        auth_mode = "license"
        server_url = selected_server
        license_code = selected_license
        api_key = ""
    else:
        selected_api_key = selected["api_key"]
        record["auth_mode"] = "api"
        if not save_secret(record, "api_key", "api_key_dpapi", selected_api_key):
            gui_show_error("Could not securely save your API key on this machine.")
            return False
        auth_mode = "api"
        api_key = selected_api_key
        license_code = ""

    record["device_id"] = saved_device_id
    save_config_record(record)
    device_id = saved_device_id
    return True


def request_json(method, path, token="", json_payload=None, files=None, timeout=30):
    url = f"{server_url}{path}"
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return requests.request(
        method=method,
        url=url,
        headers=headers,
        json=json_payload,
        files=files,
        timeout=timeout,
    )


def authenticate_license_session():
    global session_id, session_token, user_email, license_hint
    global heartbeat_interval_seconds, heartbeat_timeout_seconds
    payload = {
        "license_code": license_code,
        "device_id": device_id,
        "device_name": os.environ.get("COMPUTERNAME", os.environ.get("HOSTNAME", "Windows")),
        "app_version": APP_VERSION,
    }
    try:
        response = request_json("POST", "/api/v1/client/authenticate", json_payload=payload, timeout=20)
    except Exception as exc:
        return False, f"Could not connect to server.\n{exc}"

    try:
        data = response.json()
    except Exception:
        return False, f"Server returned non-JSON response ({response.status_code})."
    if not response.ok:
        message = data.get("detail") if isinstance(data, dict) else ""
        return False, f"Authentication request failed ({response.status_code}). {message}"
    if not data.get("success"):
        return False, data.get("message", "Authentication denied.")

    with session_lock:
        session_id = data.get("session_id", "")
        session_token = data.get("session_token", "")
        user_email = data.get("user_email", "")
        license_hint = data.get("license_hint", "")
        heartbeat_interval_seconds = int(data.get("heartbeat_interval_seconds", 20))
        heartbeat_timeout_seconds = int(data.get("heartbeat_timeout_seconds", 90))
    set_session_status("Code mode active / Session active", active=True)
    return True, "Authenticated"


def ensure_license_mode_ready():
    global server_url, license_code
    while True:
        ok, message = authenticate_license_session()
        if ok:
            return True
        set_session_status(f"Code mode disconnected: {message}", active=False)
        if not gui_ask_retry_license(f"Login failed: {message}"):
            return False
        selected = prompt_startup_auth(server_url, license_code, "")
        if not selected or selected.get("mode") != "license":
            return False
        server_url = selected["server_url"]
        license_code = selected["license_code"]
        record = load_config_record()
        record["auth_mode"] = "license"
        record["server_url"] = server_url
        if not save_secret(record, "license_code", "license_code_dpapi", license_code):
            gui_show_error("Could not securely save the code.")
            return False


class _SimpleApiResponse:
    def __init__(self, text):
        self.text = str(text or "")


class ModernGenAiSession:
    def __init__(self, module, local_api_key, local_model_name):
        self.module = module
        self.client = module.Client(api_key=local_api_key)
        self.model_name = local_model_name

    def reset(self):
        return

    def _coerce_payload(self, payload):
        parts = []
        for item in payload:
            if isinstance(item, PIL.Image.Image):
                stream = io.BytesIO()
                item.save(stream, format="PNG")
                image_bytes = stream.getvalue()
                part_type = getattr(getattr(self.module, "types", None), "Part", None)
                if part_type and hasattr(part_type, "from_bytes"):
                    parts.append(part_type.from_bytes(data=image_bytes, mime_type="image/png"))
                else:
                    parts.append({"mime_type": "image/png", "data": image_bytes})
            else:
                parts.append(str(item))
        return parts

    def send_message(self, payload):
        contents = self._coerce_payload(payload)
        response = self.client.models.generate_content(model=self.model_name, contents=contents)
        return _SimpleApiResponse(extract_text_from_genai_response(response))


def extract_text_from_genai_response(response):
    direct_text = getattr(response, "text", "") or ""
    if str(direct_text).strip():
        return str(direct_text).strip()

    collected = []
    candidates = getattr(response, "candidates", None) or []
    for candidate in candidates:
        content = getattr(candidate, "content", None)
        if not content:
            continue
        parts = getattr(content, "parts", None) or []
        for part in parts:
            text = getattr(part, "text", None)
            if text:
                collected.append(str(text))
    return "\n".join(collected).strip()


def resolve_genai_backend():
    try:
        from google import genai as modern_genai

        return "google.genai", modern_genai, ""
    except Exception as modern_exc:
        modern_error = str(modern_exc)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FutureWarning)
            import google.generativeai as legacy_genai

        return "google.generativeai", legacy_genai, ""
    except Exception as legacy_exc:
        return "", None, f"google.genai unavailable ({modern_error}); google.generativeai unavailable ({legacy_exc})"


def ensure_api_mode_ready():
    global local_model, local_chat_session, api_backend_name
    if not api_key:
        gui_show_error("API key is empty.")
        return False
    try:
        backend_name, backend_module, backend_error = resolve_genai_backend()
        if not backend_module:
            raise RuntimeError(backend_error or "No Gemini SDK available.")

        if backend_name == "google.genai":
            local_model = None
            local_chat_session = ModernGenAiSession(backend_module, api_key, model_name)
        else:
            backend_module.configure(api_key=api_key)
            generation_config = {"temperature": 0.0, "top_p": 1.0, "top_k": 1}
            local_model = backend_module.GenerativeModel(model_name, generation_config=generation_config)
            local_chat_session = local_model.start_chat(history=[])
        api_backend_name = backend_name
    except Exception as exc:
        gui_show_error(f"Could not initialize API mode.\n{exc}")
        return False
    set_session_status(f"API mode active ({api_backend_name})", active=True)
    return True


def initialize_auth_mode():
    if auth_mode == "license":
        return ensure_license_mode_ready()
    return ensure_api_mode_ready()


def end_remote_session():
    local_session_id = ""
    local_session_token = ""
    with session_lock:
        local_session_id = session_id
        local_session_token = session_token
    if not local_session_token:
        return
    try:
        request_json(
            "POST",
            "/api/v1/client/end-session",
            token=local_session_token,
            json_payload={"session_id": local_session_id},
            timeout=12,
        )
    except Exception:
        pass


def heartbeat_loop():
    while not heartbeat_stop_event.wait(max(8, heartbeat_interval_seconds)):
        if auth_mode != "license":
            continue
        with session_lock:
            local_active = session_active
            local_session_id = session_id
            local_session_token = session_token
        if not local_active or not local_session_token:
            continue
        try:
            response = request_json(
                "POST",
                "/api/v1/client/heartbeat",
                token=local_session_token,
                json_payload={"session_id": local_session_id},
                timeout=15,
            )
            if not response.ok:
                set_session_status("Code mode session lost (heartbeat failed)", active=False)
                disable_typing_mode()
                indicator_set_idle()
        except Exception:
            set_session_status("Code mode disconnected (network error)", active=False)
            disable_typing_mode()
            indicator_set_idle()


def start_heartbeat():
    global heartbeat_thread
    heartbeat_stop_event.clear()
    heartbeat_thread = Thread(target=heartbeat_loop, daemon=True)
    heartbeat_thread.start()


def list_running_process_snapshot():
    running_names = set()
    pid_to_name = {}
    if os.name != "nt":
        return running_names, pid_to_name
    try:
        completed = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=4,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception:
        return running_names, pid_to_name

    if completed.returncode != 0:
        return running_names, pid_to_name

    for row in csv.reader(io.StringIO(completed.stdout)):
        if len(row) < 2:
            continue
        name = str(row[0]).strip().lower()
        if not name:
            continue
        running_names.add(name)
        try:
            pid_to_name[int(str(row[1]).strip())] = name
        except Exception:
            pass
    return running_names, pid_to_name


def is_google_meet_window_active(pid_to_name):
    if os.name != "nt":
        return False
    try:
        hwnd = _user32.GetForegroundWindow()
        if not hwnd:
            return False
        title_buffer = ctypes.create_unicode_buffer(512)
        if _user32.GetWindowTextW(hwnd, title_buffer, len(title_buffer)) <= 0:
            return False
        title = str(title_buffer.value or "").strip().lower()
        if not title or not any(keyword in title for keyword in PRIVACY_MEET_WINDOW_KEYWORDS):
            return False
        process_id = wintypes.DWORD(0)
        _user32.GetWindowThreadProcessId(hwnd, ctypes.byref(process_id))
        return pid_to_name.get(int(process_id.value), "") in PRIVACY_MEET_BROWSERS
    except Exception:
        return False


def privacy_guard_loop():
    global privacy_forced_hidden
    while not privacy_guard_stop_event.is_set():
        should_force_hide = False
        if STRICT_PRIVACY_FALLBACK:
            running, pid_to_name = list_running_process_snapshot()
            capture_process_active = bool(running.intersection(PRIVACY_GUARD_PROCESSES)) or is_google_meet_window_active(pid_to_name)
            if capture_process_active and not indicator_capture_protected:
                should_force_hide = True

        if should_force_hide != privacy_forced_hidden:
            privacy_forced_hidden = should_force_hide
            if privacy_forced_hidden:
                indicator_hide()
            else:
                if not indicator_manual_hidden:
                    indicator_show()

        if privacy_guard_stop_event.wait(PRIVACY_GUARD_INTERVAL_SECONDS):
            break


def start_privacy_guard():
    global privacy_guard_thread
    if os.name != "nt" or not STRICT_PRIVACY_FALLBACK:
        return
    privacy_guard_stop_event.clear()
    privacy_guard_thread = Thread(target=privacy_guard_loop, daemon=True)
    privacy_guard_thread.start()


class StatusIndicator:
    def __init__(self):
        self.root = tk.Tk()
        self.root.overrideredirect(True)
        self.root.attributes("-topmost", True)
        try:
            self.root.attributes("-toolwindow", True)
        except Exception:
            pass
        self.hidden = False
        self.current_char = ""
        self.current_color = "#404040"
        self.answer_preview = ""
        self.base_size = 20
        self.collapsed_width = self.base_size
        self.collapsed_height = self.base_size
        self.expanded_width = 400
        self.expanded_height = 132
        self.panel_corner_radius = 14
        self.square_corner_radius = 6
        self.control_hint_text = (
            "Controls\n"
            "Numpad 1: Capture / Pause / Resume\n"
            "Numpad 0: Toggle Indicator\n"
            "Numpad 2: Clear Pending\n"
            "Numpad 3: Paste All\n"
            "Numpad 4: Repeat Last\n"
            "Numpad 9: Exit"
        )
        self.current_width = self.collapsed_width
        self.current_height = self.collapsed_height
        self.target_width = self.collapsed_width
        self.target_height = self.collapsed_height
        self.animation_after_id = None
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = screen_width - self.current_width - 10
        y = screen_height - self.current_height - 50
        self.root.geometry(f"{self.current_width}x{self.current_height}+{x}+{y}")
        self.canvas = tk.Canvas(
            self.root,
            width=self.current_width,
            height=self.current_height,
            highlightthickness=0,
            bd=0,
            bg="#081224",
        )
        self.canvas.pack()
        self.canvas.bind("<Enter>", self._on_hover_enter)
        self.canvas.bind("<Leave>", self._on_hover_leave)
        self.canvas.bind("<Button-1>", self._on_click_toggle)
        configure_private_window(self.root, dark=True, refresh_ms=1200)
        self._apply_window_rounding()
        self._apply_capture_privacy()
        self.set_idle()

    def _apply_capture_privacy(self):
        global indicator_capture_protected
        if not HIDE_INDICATOR_FROM_CAPTURE:
            indicator_capture_protected = False
            return
        try:
            indicator_capture_protected = bool(apply_capture_privacy_to_window(self.root, enabled=True))
        except Exception:
            indicator_capture_protected = False

    def _apply_window_rounding(self):
        if os.name != "nt":
            return
        radius = 8 if self.current_width <= self.collapsed_width + 2 else self.panel_corner_radius
        apply_window_corner_region(self.root, radius)

    def _is_idle_state(self):
        return self.current_color == "#404040"

    def _can_expand(self):
        return bool(self.answer_preview) or self._is_idle_state()

    def set_idle(self):
        self.current_char = ""
        self.current_color = "#404040"
        if not self.hidden and not self.answer_preview and self.current_width <= self.collapsed_width + 2:
            self._animate_to(self.expanded_width, self.expanded_height)
        self._redraw()

    def set_processing(self):
        self.current_char = ""
        self.current_color = "#FFA500"
        if self.current_width > self.collapsed_width and not self.answer_preview:
            self._collapse_now()
        self._redraw()

    def set_ready(self):
        self.current_char = ""
        self.current_color = "#00FF00"
        if self.current_width > self.collapsed_width and not self.answer_preview:
            self._collapse_now()
        self._redraw()

    def set_paused(self):
        self.current_char = ""
        self.current_color = "#1E90FF"
        if self.current_width > self.collapsed_width and not self.answer_preview:
            self._collapse_now()
        self._redraw()

    def show_answer_char(self, value):
        char = (value or "").strip()[:1]
        self.current_char = char
        self.current_color = "#00A34B"
        self._redraw()

    def set_answer_preview(self, value):
        self.answer_preview = str(value or "").strip()
        self._redraw()

    def _on_hover_enter(self, _event):
        if self.hidden:
            return
        if self._can_expand():
            self._animate_to(self.expanded_width, self.expanded_height)

    def _on_hover_leave(self, _event):
        if self.hidden:
            return
        self._collapse_now()

    def _on_click_toggle(self, _event):
        if self.hidden or not self._can_expand():
            return
        expanded = self.current_width >= self.expanded_width - 6
        if expanded:
            self._animate_to(self.collapsed_width, self.collapsed_height)
        else:
            self._animate_to(self.expanded_width, self.expanded_height)

    def _collapse_now(self):
        self.target_width = self.collapsed_width
        self.target_height = self.collapsed_height
        if self.animation_after_id is not None:
            try:
                self.root.after_cancel(self.animation_after_id)
            except Exception:
                pass
            self.animation_after_id = None
        self._set_geometry(self.collapsed_width, self.collapsed_height)
        self._redraw()

    def _set_geometry(self, width, height):
        self.current_width = width
        self.current_height = height
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = screen_width - width - 10
        y = screen_height - height - 50
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        self.canvas.configure(width=width, height=height)
        self._apply_window_rounding()
        self._apply_capture_privacy()

    def _animate_to(self, target_width, target_height):
        self.target_width = target_width
        self.target_height = target_height

        if self.animation_after_id is not None:
            return

        def _step():
            self.animation_after_id = None

            def _next(current, target):
                if current == target:
                    return current
                delta = target - current
                step = max(1, abs(delta) // 4)
                if delta < 0:
                    step = -step
                candidate = current + step
                if (delta > 0 and candidate > target) or (delta < 0 and candidate < target):
                    return target
                return candidate

            next_width = _next(self.current_width, self.target_width)
            next_height = _next(self.current_height, self.target_height)
            self._set_geometry(next_width, next_height)
            self._redraw()

            if next_width != self.target_width or next_height != self.target_height:
                self.animation_after_id = self.root.after(16, _step)

        _step()

    def _redraw(self):
        width = self.current_width
        height = self.current_height
        self.canvas.delete("all")

        if width > self.collapsed_width or height > self.collapsed_height:
            draw_rounded_canvas_rect(
                self.canvas,
                0,
                0,
                width - 1,
                height - 1,
                self.panel_corner_radius,
                fill="#081224",
                outline="#1F3458",
            )

        square_x1 = max(0, width - self.base_size)
        square_y1 = max(0, height - self.base_size)
        draw_rounded_canvas_rect(
            self.canvas,
            square_x1,
            square_y1,
            width - 1,
            height - 1,
            self.square_corner_radius,
            fill=self.current_color,
            outline="",
        )

        if self.current_char:
            self.canvas.create_text(
                square_x1 + self.base_size // 2,
                square_y1 + self.base_size // 2,
                text=self.current_char.upper(),
                fill="white",
                font=(UI_FONT, 8, "bold"),
            )

        expanded = width >= self.expanded_width - 6 and height >= self.expanded_height - 6
        if expanded and self.answer_preview:
            self.canvas.create_text(
                10,
                10,
                text=self.answer_preview,
                fill="#EAF2FF",
                font=(UI_FONT, 9),
                anchor="nw",
                justify="left",
                width=max(50, width - 34),
            )
        elif expanded and self._is_idle_state():
            self.canvas.create_text(
                12,
                10,
                text=self.control_hint_text,
                fill="#CFDFFF",
                font=(UI_FONT, 9),
                anchor="nw",
                justify="left",
                width=max(70, width - 30),
            )

    def hide(self):
        if not self.hidden:
            self.root.withdraw()
            self.hidden = True

    def show(self):
        if self.hidden:
            self.root.deiconify()
            self.root.attributes("-topmost", True)
            self._apply_window_rounding()
            self._apply_capture_privacy()
            self.hidden = False
            self._redraw()

    def run(self):
        self.root.mainloop()


def init_indicator():
    global indicator
    indicator = StatusIndicator()
    indicator.run()


def indicator_call(func):
    if not indicator:
        return
    try:
        indicator.root.after(0, func)
    except Exception:
        pass


def indicator_set_idle():
    indicator_call(indicator.set_idle)


def indicator_set_processing():
    indicator_call(indicator.set_processing)


def indicator_set_ready():
    indicator_call(indicator.set_ready)


def indicator_set_paused():
    indicator_call(indicator.set_paused)


def indicator_show_answer_char(value):
    indicator_call(lambda: indicator.show_answer_char(value))


def indicator_set_answer_preview(value):
    indicator_call(lambda: indicator.set_answer_preview(value))


def indicator_hide():
    indicator_call(indicator.hide)


def indicator_show():
    if privacy_forced_hidden:
        return
    indicator_call(indicator.show)


def set_indicator_manual_visibility(hidden):
    global indicator_manual_hidden
    indicator_manual_hidden = bool(hidden)
    if hidden:
        indicator_hide()
    else:
        indicator_show()


def get_status_text():
    with session_lock:
        return session_status_text


def show_status_ui():
    status = get_status_text()
    if auth_mode == "license":
        details = (
            f"Mode: Subscription Code\n"
            f"Status: {status}\n"
            f"Server: {server_url}\n"
            f"User: {user_email or '-'}\n"
            f"Code: {license_hint or '-'}"
        )
    else:
        masked = f"***{api_key[-4:]}" if api_key else "-"
        details = (
            f"Mode: API Key\n"
            f"Status: {status}\n"
            f"Backend: {api_backend_name}\n"
            f"Model: {model_name}\n"
            f"API Key: {masked}"
        )

    def _display():
        parent = indicator.root if indicator and indicator.root.winfo_exists() else None
        show_styled_message(f"{APP_NAME} Status", details, is_error=False, parent=parent)

    try:
        if indicator and indicator.root.winfo_exists():
            indicator.root.after(0, _display)
        else:
            _display()
    except Exception:
        pass


def build_tray_image():
    image = PIL.Image.new("RGB", (64, 64), "#1F2937")
    draw = PIL.ImageDraw.Draw(image)
    draw.ellipse((14, 14, 50, 50), fill="#22C55E")
    draw.ellipse((24, 24, 40, 40), fill="#111827")
    return image


def tray_status_label(_):
    return f"Status: {get_status_text()}"


def tray_open_ui(icon, item):
    show_status_ui()


def tray_toggle_indicator(icon, item):
    if not indicator:
        return
    toggle_indicator_visibility()


def tray_exit(icon, item):
    exit_program(trigger_uninstall=False)


def run_tray_icon():
    global tray_icon
    if pystray is None:
        return
    tray_icon = pystray.Icon(
        "EyesAndEars",
        build_tray_image(),
        "EyesAndEars",
        pystray.Menu(
            pystray.MenuItem("Open/Show UI", tray_open_ui),
            pystray.MenuItem(tray_status_label, None, enabled=False),
            pystray.MenuItem("Toggle Indicator", tray_toggle_indicator),
            pystray.MenuItem("Quit", tray_exit),
        ),
    )
    tray_icon.run()


def block_hotkey(action, seconds=0.25):
    hotkey_block_until[action] = time.monotonic() + seconds


def hotkey_blocked(action):
    return time.monotonic() < hotkey_block_until[action]


def enable_typing_mode():
    global typing_hook
    if typing_hook is None:
        typing_hook = keyboard.on_press(on_smart_type, suppress=True)


def disable_typing_mode():
    global typing_hook
    if typing_hook:
        keyboard.unhook(typing_hook)
        typing_hook = None


def has_pending_answer():
    return bool(current_answer) and current_index < len(current_answer)


def clear_answer_state():
    global current_answer, current_index, is_paused, pause_pending
    current_answer = ""
    current_index = 0
    is_paused = False
    pause_pending = False


def reset_api_context():
    global local_chat_session
    if local_chat_session is None:
        return
    try:
        if hasattr(local_chat_session, "reset"):
            local_chat_session.reset()
            return
        if local_model is not None:
            local_chat_session = local_model.start_chat(history=[])
    except Exception:
        pass


def get_numpad_action(event):
    name = (event.name or "").strip().lower()
    named_actions = {
        "num 1": "primary",
        "numpad 1": "primary",
        "num 0": "indicator",
        "numpad 0": "indicator",
        "num 2": "clear_ctx",
        "numpad 2": "clear_ctx",
        "num 3": "paste_all",
        "numpad 3": "paste_all",
        "num 4": "repeat_prev",
        "numpad 4": "repeat_prev",
        "num 9": "exit",
        "numpad 9": "exit",
    }
    if name in named_actions:
        return named_actions[name]

    if bool(getattr(event, "is_keypad", False)):
        keypad_aliases = {
            "1": "primary",
            "0": "indicator",
            "2": "clear_ctx",
            "3": "paste_all",
            "4": "repeat_prev",
            "9": "exit",
            "end": "primary",
            "insert": "indicator",
            "down": "clear_ctx",
            "page down": "paste_all",
            "pagedown": "paste_all",
            "left": "repeat_prev",
            "page up": "exit",
            "pageup": "exit",
        }
        return keypad_aliases.get(name, "")
    return ""


def toggle_pause_pending():
    global pause_pending
    pause_pending = not pause_pending


def toggle_pause():
    global is_paused
    if not has_pending_answer():
        return
    is_paused = not is_paused
    if is_paused:
        disable_typing_mode()
        indicator_set_paused()
    else:
        indicator_set_ready()
        enable_typing_mode()


def handle_primary_action():
    if is_processing:
        toggle_pause_pending()
        return
    if has_pending_answer():
        toggle_pause()
        return
    Thread(target=process_screenshot, daemon=True).start()


def toggle_indicator_visibility():
    if not indicator:
        return
    if indicator.hidden:
        set_indicator_manual_visibility(False)
    else:
        set_indicator_manual_visibility(True)


def handle_primary_hotkey():
    if hotkey_blocked("primary"):
        return
    handle_primary_action()


def handle_indicator_hotkey():
    if hotkey_blocked("indicator"):
        return
    toggle_indicator_visibility()


def handle_clear_ctx_hotkey():
    if hotkey_blocked("clear_ctx"):
        return
    run_clear_ctx_action()


def run_clear_ctx_action():
    clear_answer_state()
    if auth_mode == "api":
        reset_api_context()
    disable_typing_mode()
    indicator_set_idle()


def handle_paste_all_hotkey():
    if hotkey_blocked("paste_all"):
        return
    run_paste_all_action()


def run_paste_all_action():
    global current_index
    if not current_answer or current_index >= len(current_answer):
        return
    remaining = current_answer[current_index:]
    disable_typing_mode()
    with write_lock:
        keyboard.write(remaining)
        current_index = len(current_answer)
    indicator_set_idle()
    clear_answer_state()


def handle_repeat_prev_hotkey():
    if hotkey_blocked("repeat_prev"):
        return
    run_repeat_prev_action()


def run_repeat_prev_action():
    global current_answer, current_index, is_paused, pause_pending
    if not last_answer:
        return
    disable_typing_mode()
    indicator_set_answer_preview(last_answer)
    current_answer = last_answer
    current_index = 0
    is_paused = False
    pause_pending = False
    indicator_set_ready()
    enable_typing_mode()


def handle_exit_hotkey():
    if hotkey_blocked("exit"):
        return
    exit_program(trigger_uninstall=True)


def clean_response_text(text):
    import re

    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = text.replace("```", "").strip()
    lines = [line.strip() for line in text.split("\n")]
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()

    code_prefixes = (
        "def ", "class ", "import ", "from ", "if ", "elif ", "else:", "for ", "while ",
        "try:", "except", "finally:", "return ", "let ", "const ", "var ", "function ",
        "public ", "private ", "protected ", "#include", "using ", "SELECT ", "INSERT ",
        "UPDATE ", "DELETE ", "<!doctype", "<html", "{", "}",
    )

    looks_like_code = any(
        line and (
            line.startswith(code_prefixes)
            or line.endswith("{")
            or line.endswith("}")
            or (";" in line and any(ch in line for ch in "{}()"))
        )
        for line in lines
    )

    if not lines:
        return ""

    if looks_like_code:
        compact = []
        blank_streak = 0
        for line in lines:
            if not line:
                blank_streak += 1
                if blank_streak > 1:
                    continue
            else:
                blank_streak = 0
            compact.append(line)
        return "\n".join(compact).strip()

    flattened = " ".join(line for line in lines if line)
    flattened = re.sub(r"\s+", " ", flattened).strip()
    return flattened


def infer_via_license_server(image_bytes, local_token):
    files = {"file": ("capture.png", image_bytes, "image/png")}
    response = request_json("POST", "/api/v1/client/infer", token=local_token, files=files, timeout=80)
    if response.status_code == 401:
        set_session_status("Code mode session expired. Restart app.", active=False)
        raise RuntimeError("Session expired or invalid.")
    response.raise_for_status()
    return str(response.json().get("text", ""))


def infer_via_api_key(screenshot):
    if local_chat_session is None:
        raise RuntimeError("API mode not initialized.")
    response = local_chat_session.send_message([PROMPT_TEXT, screenshot])
    text = getattr(response, "text", "") or ""
    if not text.strip():
        raise RuntimeError("No response text from model.")
    return text


def process_screenshot():
    global current_answer, current_index, last_answer, is_processing, is_paused, pause_pending
    if is_processing:
        return

    if auth_mode == "license":
        with session_lock:
            local_active = session_active
            local_token = session_token
        if not local_active or not local_token:
            set_session_status("Code mode inactive - re-login required", active=False)
            gui_show_error("Session inactive. Restart app and login with code.")
            return
    else:
        local_token = ""

    is_processing = True
    is_paused = False
    disable_typing_mode()
    indicator_set_processing()
    try:
        screenshot = PIL.ImageGrab.grab()
        stream = io.BytesIO()
        screenshot.save(stream, format="PNG")
        image_bytes = stream.getvalue()

        raw_text = infer_via_license_server(image_bytes, local_token) if auth_mode == "license" else infer_via_api_key(screenshot)
        final_text = clean_response_text(raw_text)
        if not final_text:
            raise RuntimeError("No response text returned.")

        last_answer = final_text
        indicator_set_answer_preview(final_text)
        current_answer = final_text
        current_index = 0
        pyperclip.copy(final_text)
        if len(final_text) == 1:
            disable_typing_mode()
            indicator_show_answer_char(final_text)
            clear_answer_state()
            return
        if pause_pending:
            pause_pending = False
            is_paused = True
            indicator_set_paused()
        else:
            indicator_set_ready()
            enable_typing_mode()
    except Exception as exc:
        print(f"Inference error: {exc}")
        indicator_set_idle()
        clear_answer_state()
    finally:
        is_processing = False


def detect_winget_package_id_from_path():
    executable_path = Path(sys.executable if getattr(sys, "frozen", False) else __file__).resolve()
    parts = executable_path.parts
    for index, part in enumerate(parts):
        if part.lower() == "packages" and index + 1 < len(parts):
            package_folder = parts[index + 1]
            return package_folder.split("_", 1)[0]
    return ""


def sanitize_package_id(raw_value):
    import re

    candidate = str(raw_value).strip()
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{1,127}", candidate):
        return candidate
    return ""


def resolve_winget_package_id():
    if DEFAULT_WINGET_PACKAGE_ID:
        return sanitize_package_id(DEFAULT_WINGET_PACKAGE_ID)
    return sanitize_package_id(detect_winget_package_id_from_path())


def schedule_self_uninstall():
    package_id = resolve_winget_package_id()
    if not package_id:
        return False
    uninstall_script = Path(tempfile.gettempdir()) / f"eyesandears-self-uninstall-{secrets.token_hex(8)}.cmd"
    script_text = (
        "@echo off\n"
        f"timeout /t {SELF_UNINSTALL_DELAY_SECONDS} /nobreak >nul\n"
        f"winget uninstall --id \"{package_id}\" --exact --purge --silent\n"
        "del /f /q \"%~f0\"\n"
    )
    uninstall_script.write_text(script_text, encoding="utf-8")
    subprocess.Popen(
        ["cmd", "/c", str(uninstall_script)],
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        close_fds=True,
    )
    return True


def exit_program(trigger_uninstall=False):
    global tray_icon
    heartbeat_stop_event.set()
    privacy_guard_stop_event.set()
    if auth_mode == "license":
        end_remote_session()
    set_session_status("Stopped", active=False)
    disable_typing_mode()
    clear_answer_state()
    try:
        pyperclip.copy("")
    except Exception:
        pass
    try:
        keyboard.clear_all_hotkeys()
    except Exception:
        pass
    if tray_icon:
        try:
            tray_icon.stop()
        except Exception:
            pass
    if trigger_uninstall:
        schedule_self_uninstall()
    os._exit(0)


def on_smart_type(event):
    global current_index
    action = get_numpad_action(event)
    if action and event.event_type == "down":
        block_hotkey(action)
        if action == "primary":
            handle_primary_action()
        elif action == "indicator":
            toggle_indicator_visibility()
        elif action == "clear_ctx":
            run_clear_ctx_action()
        elif action == "paste_all":
            run_paste_all_action()
        elif action == "repeat_prev":
            run_repeat_prev_action()
        elif action == "exit":
            exit_program(trigger_uninstall=True)
        return
    if len(event.name) > 1 and event.name != "space":
        return
    if keyboard.is_pressed("ctrl") or keyboard.is_pressed("alt") or keyboard.is_pressed("win"):
        return
    if write_lock.locked():
        return
    if event.event_type == "down":
        if current_answer and current_index < len(current_answer):
            with write_lock:
                char = current_answer[current_index]
                keyboard.write(char)
                current_index += 1
            if current_index >= len(current_answer):
                disable_typing_mode()
                indicator_set_idle()
                clear_answer_state()


def main():
    global indicator_manual_hidden
    hide_console_window()
    if not resolve_auth_settings():
        return
    if not initialize_auth_mode():
        return
    if auth_mode == "license":
        start_heartbeat()

    indicator_thread = Thread(target=init_indicator, daemon=True)
    indicator_thread.start()
    time.sleep(0.35)
    start_privacy_guard()
    indicator_manual_hidden = not INDICATOR_VISIBLE_BY_DEFAULT
    set_indicator_manual_visibility(indicator_manual_hidden)
    if pystray is not None:
        tray_thread = Thread(target=run_tray_icon, daemon=True)
        tray_thread.start()

    keyboard.add_hotkey("num 1", handle_primary_hotkey)
    keyboard.add_hotkey("num 0", handle_indicator_hotkey)
    keyboard.add_hotkey("num 2", handle_clear_ctx_hotkey)
    keyboard.add_hotkey("num 3", handle_paste_all_hotkey)
    keyboard.add_hotkey("num 4", handle_repeat_prev_hotkey)
    keyboard.add_hotkey("num 9", handle_exit_hotkey)
    keyboard.wait()


if __name__ == "__main__":
    main()
