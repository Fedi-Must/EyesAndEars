import os
import time
import json
import hmac
import getpass
import hashlib
import secrets
import sys
import tempfile
import subprocess
import base64
import ctypes
import google.generativeai as genai
import PIL.ImageGrab
import PIL.Image
import PIL.ImageDraw
import pyperclip
import keyboard
from ctypes import wintypes
from pathlib import Path
from threading import Thread, Lock
import tkinter as tk

try:
    import pystray
except Exception:
    pystray = None

# === SILENCE ALTS WARNINGS ===
os.environ["GRPC_VERBOSITY"] = "ERROR"
os.environ["GLOG_minloglevel"] = "2"

# === CONFIGURATION ===
APP_NAME = "EyesAndEars"
PASSWORD_MIN_LENGTH = 6
MAX_PASSWORD_ATTEMPTS = 3


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
        return portable_data_dir, False
    except Exception:
        fallback_data_dir = Path(os.environ.get("APPDATA", ".")) / APP_NAME
        fallback_data_dir.mkdir(parents=True, exist_ok=True)
        return fallback_data_dir, True


APP_INSTALL_ROOT = resolve_install_root()
APP_DATA_DIR, USING_FALLBACK_DATA_DIR = resolve_data_dir(APP_INSTALL_ROOT)
AUTH_FILE = APP_DATA_DIR / "auth.json"
CONFIG_FILE = APP_DATA_DIR / "config.json"

API_KEY_ENV_VAR = "EYESANDEARS_API_KEY"
runtime_api_key = ""
DEFAULT_WINGET_PACKAGE_ID = os.environ.get("EYESANDEARS_WINGET_ID", "").strip()
SELF_UNINSTALL_DELAY_SECONDS = 2
CRYPTPROTECT_UI_FORBIDDEN = 0x01
SW_HIDE = 0

if os.name == "nt":
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_byte)),
        ]

    _crypt32 = ctypes.windll.crypt32
    _kernel32 = ctypes.windll.kernel32
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

# Smartest Gemini model (per Gemini models doc)
MODEL_NAME = "gemini-2.5-flash"  # you can swap to "gemini-2.5-flash" for cheaper/faster :contentReference[oaicite:2]{index=2}

# Keep the SAME prompt you provided (unchanged):
PROMPT_TEXT = (
    "Analyze the image provided. Your goal is to provide the direct answer/solution and NOTHING else.\n\n"
    "RULES:\n"
    "1. If it is a Multiple Choice Question: Output ONLY the correct letter (e.g., 'A', 'B'). Do not write the text of the option.\n"
    "2. If it is a coding error/task: Output ONLY the corrected code block. Do not use Markdown formatting (no python ... ). Just the raw code ready to run.\n"
    "3. If it is a general question: Output ONLY the direct answer.\n"
    "4. ABSOLUTELY NO conversational filler, no 'Here is the answer', no explanations, no markdown backticks.\n"
    "5. If unclear, find the most likely question on screen and answer it."
)

# === GLOBAL VARIABLES ===
current_answer = ""
current_index = 0
is_processing = False
is_paused = False
pause_pending = False
typing_hook = None
write_lock = Lock()
hotkey_block_until = {"primary": 0.0, "indicator": 0.0, "exit": 0.0, "clear_ctx": 0.0}

# Per-launch context objects
model = None
chat_session = None
tray_icon = None

# === STATUS INDICATOR ===
class StatusIndicator:
    def __init__(self):
        self.root = tk.Tk()
        self.root.overrideredirect(True)
        self.root.attributes("-topmost", True)
        self.root.attributes("-alpha", 1.0)
        self.hidden = False

        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        size = 10
        x = screen_width - size - 10
        y = screen_height - size - 50

        self.root.geometry(f"{size}x{size}+{x}+{y}")

        self.canvas = tk.Canvas(self.root, width=size, height=size, highlightthickness=0, bg="black")
        self.canvas.pack()

        self.set_idle()

    def set_idle(self):
        self.canvas.configure(bg="#404040")

    def set_processing(self):
        self.canvas.configure(bg="#FFA500")

    def set_ready(self):
        self.canvas.configure(bg="#00FF00")

    def set_paused(self):
        self.canvas.configure(bg="#1E90FF")

    def hide(self):
        if not self.hidden:
            self.root.withdraw()
            self.hidden = True

    def show(self):
        if self.hidden:
            self.root.deiconify()
            self.root.attributes("-topmost", True)
            self.hidden = False

    def run(self):
        self.root.mainloop()


indicator = None

def init_indicator():
    global indicator
    indicator = StatusIndicator()
    indicator.run()


# === INDICATOR HELPERS ===
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

def indicator_hide():
    indicator_call(indicator.hide)

def indicator_show():
    indicator_call(indicator.show)


def hide_console_window():
    if os.name != "nt":
        return
    try:
        console_window = ctypes.windll.kernel32.GetConsoleWindow()
        if console_window:
            ctypes.windll.user32.ShowWindow(console_window, SW_HIDE)
    except Exception:
        pass


def build_tray_image():
    image = PIL.Image.new("RGB", (64, 64), "#1F2937")
    draw = PIL.ImageDraw.Draw(image)
    draw.ellipse((14, 14, 50, 50), fill="#22C55E")
    draw.ellipse((24, 24, 40, 40), fill="#111827")
    return image


def tray_toggle_indicator(icon, item):
    if not indicator:
        return
    if indicator.hidden:
        indicator_show()
    else:
        indicator_hide()


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
            pystray.MenuItem("Toggle Indicator", tray_toggle_indicator),
            pystray.MenuItem("Exit", tray_exit),
        ),
    )
    tray_icon.run()


# === PASSWORD GATE ===
def prompt_secret(prompt_text):
    try:
        return getpass.getpass(prompt_text)
    except Exception:
        return input(prompt_text)


def password_hash(password, salt_hex):
    salt = bytes.fromhex(salt_hex)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 250000)
    return digest.hex()


def load_auth_record():
    if not AUTH_FILE.exists():
        return None
    try:
        record = json.loads(AUTH_FILE.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(record, dict):
        return None
    if "salt" not in record or "hash" not in record:
        return None
    return record


def save_auth_record(salt_hex, hash_hex):
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    record = {"salt": salt_hex, "hash": hash_hex}
    AUTH_FILE.write_text(json.dumps(record), encoding="utf-8")


def setup_password():
    print("\nFirst run setup: create a password to unlock this app.")
    while True:
        first = prompt_secret("New password: ").strip()
        second = prompt_secret("Confirm password: ").strip()

        if len(first) < PASSWORD_MIN_LENGTH:
            print(f"Password must be at least {PASSWORD_MIN_LENGTH} characters.")
            continue
        if first != second:
            print("Passwords do not match. Try again.")
            continue

        salt_hex = secrets.token_hex(16)
        hash_hex = password_hash(first, salt_hex)
        save_auth_record(salt_hex, hash_hex)
        print("Password saved.")
        return True


def verify_password(record):
    for attempt in range(1, MAX_PASSWORD_ATTEMPTS + 1):
        entered = prompt_secret("Enter app password: ")
        entered_hash = password_hash(entered, record["salt"])
        if hmac.compare_digest(entered_hash, record["hash"]):
            print("Access granted.")
            return True
        print(f"Invalid password ({attempt}/{MAX_PASSWORD_ATTEMPTS}).")
    return False


def enforce_password_gate():
    record = load_auth_record()
    if record is None:
        if AUTH_FILE.exists():
            print("Auth record is invalid. Remove auth.json to reset password.")
            return False
        return setup_password()
    print("\nPassword required.")
    if verify_password(record):
        return True
    print("Too many failed attempts. Exiting.")
    return False


# === APP CONFIG ===
def load_config_record():
    if not CONFIG_FILE.exists():
        return {}
    try:
        record = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(record, dict):
        return {}
    return record


def save_config_record(record):
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(record), encoding="utf-8")


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
    in_blob, in_buf = bytes_to_blob(plain_bytes)
    out_blob = DATA_BLOB()
    if not _crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        "EyesAndEars API Key",
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

    in_blob, in_buf = bytes_to_blob(cipher_bytes)
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


def load_saved_api_key(record):
    encrypted_key = str(record.get("api_key_dpapi", "")).strip()
    if encrypted_key:
        decrypted_key = decrypt_with_dpapi(encrypted_key)
        if decrypted_key:
            return decrypted_key

    # Legacy fallback: migrate plaintext key to DPAPI.
    legacy_key = str(record.get("api_key", "")).strip()
    if legacy_key:
        encrypted_key = encrypt_with_dpapi(legacy_key)
        if encrypted_key:
            record.pop("api_key", None)
            record["api_key_dpapi"] = encrypted_key
            save_config_record(record)
            return legacy_key

        # Do not continue using plaintext on Windows if migration fails.
        if os.name == "nt":
            print("Stored API key is plaintext and could not be secured. Re-enter key.")
            record.pop("api_key", None)
            save_config_record(record)
            return ""

        return legacy_key
    return ""


def prompt_api_key_cmd():
    print("Paste your Gemini API key in this CMD window, then press Enter.")
    try:
        return input("Gemini API key: ").strip()
    except EOFError:
        return ""


def resolve_api_key():
    env_key = os.environ.get(API_KEY_ENV_VAR, "").strip()
    if env_key:
        return env_key

    record = load_config_record()
    saved_key = load_saved_api_key(record)
    if saved_key:
        return saved_key

    print("\nFirst run setup: API key required.")
    for _ in range(3):
        entered_key = prompt_api_key_cmd()
        if entered_key:
            encrypted_key = encrypt_with_dpapi(entered_key)
            record.pop("api_key", None)
            if encrypted_key:
                record["api_key_dpapi"] = encrypted_key
            elif os.name != "nt":
                record["api_key"] = entered_key
            else:
                print("Could not securely store API key. Try again.")
                continue
            save_config_record(record)
            print("API key saved for future runs.")
            return entered_key
        print("API key cannot be empty.")
    return ""


# === HOTKEY / STATE HELPERS ===
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

def is_keypad_event(event):
    return bool(getattr(event, "is_keypad", False))

NUMPAD_PRIMARY_NAMES = {"num 1", "1", "end"}
NUMPAD_INDICATOR_NAMES = {"num 0", "0", "insert"}
NUMPAD_EXIT_NAMES = {"num 9", "9", "page up"}
NUMPAD_CLEAR_CTX_NAMES = {"num 2", "2", "down"}  # added


def get_numpad_action(event):
    if not is_keypad_event(event):
        return None
    if event.name in NUMPAD_PRIMARY_NAMES:
        return "primary"
    if event.name in NUMPAD_INDICATOR_NAMES:
        return "indicator"
    if event.name in NUMPAD_CLEAR_CTX_NAMES:
        return "clear_ctx"
    if event.name in NUMPAD_EXIT_NAMES:
        return "exit"
    return None


def toggle_pause_pending():
    global pause_pending
    pause_pending = not pause_pending
    if pause_pending:
        print("\n[PAUSE QUEUED] Will pause when answer arrives.")
    else:
        print("\n[PAUSE UNQUEUED] Will auto-type when ready.")


def toggle_pause():
    global is_paused
    if not has_pending_answer():
        return
    is_paused = not is_paused
    if is_paused:
        disable_typing_mode()
        indicator_set_paused()
        print("\n[PAUSED] Press Numpad 1 to resume.")
    else:
        indicator_set_ready()
        enable_typing_mode()
        print("\n[RESUMED] Type to output the answer.")


def handle_primary_action():
    if is_processing:
        toggle_pause_pending()
        return
    if has_pending_answer():
        toggle_pause()
        return
    Thread(target=process_screenshot).start()


def toggle_indicator_visibility():
    if not indicator:
        return
    if indicator.hidden:
        indicator_show()
        print("\nIndicator shown.")
    else:
        indicator_hide()
        print("\nIndicator hidden.")


def handle_primary_hotkey():
    if hotkey_blocked("primary"):
        return
    handle_primary_action()


def handle_indicator_hotkey():
    if hotkey_blocked("indicator"):
        return
    toggle_indicator_visibility()


def handle_exit_hotkey():
    if hotkey_blocked("exit"):
        return
    exit_program(trigger_uninstall=True)


def clean_response_text(text):
    """Clean and normalize the response text"""
    import re
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in text.split("\n")]
    text = "\n".join(lines).strip()
    if "\n" not in text:
        text = re.sub(r"\s+", " ", text)
    return text


# === GEMINI CONTEXT (PER LAUNCH) ===
def reset_chat_context():
    """Clears per-launch context by creating a fresh chat session."""
    global chat_session, model
    if model is None:
        return
    chat_session = model.start_chat(history=[])
    print("\n[CONTEXT CLEARED] Next capture starts fresh.")


def handle_clear_ctx_hotkey():
    if hotkey_blocked("clear_ctx"):
        return
    reset_chat_context()


# === CORE LOGIC ===
def process_screenshot():
    global current_answer, current_index, is_processing, is_paused, pause_pending
    global chat_session

    if is_processing:
        return
    is_processing = True
    is_paused = False

    disable_typing_mode()
    indicator_set_processing()
    print("\n[1/3] Capturing screenshot...")

    try:
        screenshot = PIL.ImageGrab.grab()
        print(f"[2/3] Sending to {MODEL_NAME} (Gemini chat w/ context)...")

        # Use chat_session for per-launch memory
        # Keep your exact prompt; send prompt + image as parts
        response = chat_session.send_message([PROMPT_TEXT, screenshot])

        if response and hasattr(response, "text"):
            final_text = response.text.strip()
        else:
            final_text = "Error: No response received from model"

        final_text = clean_response_text(final_text)

        current_answer = final_text
        current_index = 0

        pyperclip.copy(final_text)

        print(f"[3/3] Ready! Answer: {final_text[:100]}...")
        print(f"Length: {len(final_text)} chars.")

        if pause_pending:
            pause_pending = False
            is_paused = True
            indicator_set_paused()
            print("[READY - PAUSED] Press Numpad 1 to resume.")
        else:
            print("Start typing...")
            indicator_set_ready()
            enable_typing_mode()

    except Exception as e:
        print(f"\nError: {str(e)}")

        msg = str(e).lower()
        if "model" in msg and "not found" in msg:
            print(f"\n!!! MODEL ERROR !!!")
            print(f"Model '{MODEL_NAME}' might not exist or you don't have access.")
            print("Try using: 'gemini-2.5-flash' or check your Google AI Studio model access.")
        elif "429" in msg:
            print("\n!!! RATE LIMIT ERROR !!! Wait and try again.")
        elif "quota" in msg:
            print("\n!!! QUOTA EXCEEDED !!! Check your Gemini / AI Studio quota.")
        elif "api key" in msg or "permission" in msg or "unauthorized" in msg:
            print("\n!!! AUTH ERROR !!! Check your API key.")
        else:
            print("\nGeneral error occurred. Check API key and internet connection.")

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


def can_self_uninstall():
    return bool(resolve_winget_package_id())


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
    print("\nExiting and clearing runtime-sensitive data...")
    global tray_icon
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
        if schedule_self_uninstall():
            print("Winget uninstall scheduled.")
        else:
            print("Winget uninstall skipped (package ID unavailable).")
    os._exit(0)


def on_smart_type(event):
    global current_index

    action = get_numpad_action(event)
    if action:
        if event.event_type == "down":
            block_hotkey(action)
            if action == "primary":
                handle_primary_action()
            elif action == "indicator":
                toggle_indicator_visibility()
            elif action == "clear_ctx":
                reset_chat_context()
            else:
                exit_program(trigger_uninstall=True)
        return

    # Ignore special keys
    if len(event.name) > 1 and event.name != "space":
        return

    # Ignore if holding modifiers
    if keyboard.is_pressed("ctrl") or keyboard.is_pressed("alt") or keyboard.is_pressed("win"):
        return

    # Recursion protection
    if write_lock.locked():
        return

    # Type the chunk
    if event.event_type == "down":
        if current_answer and current_index < len(current_answer):
            with write_lock:
                char = current_answer[current_index]
                keyboard.write(char)
                current_index += 1

            if current_index >= len(current_answer):
                print("\nFinished typing answer. Keyboard restored.")
                disable_typing_mode()
                indicator_set_idle()
                clear_answer_state()


def configure_genai():
    global model, chat_session, runtime_api_key
    runtime_api_key = resolve_api_key()
    if not runtime_api_key:
        print(f"Set {API_KEY_ENV_VAR} or enter your key on first run.")
        return False

    genai.configure(api_key=runtime_api_key)

    # You can lock it down to be less “chatty”
    generation_config = {
        "temperature": 0.0,
        "top_p": 1.0,
        "top_k": 1,
    }

    model = genai.GenerativeModel(
        MODEL_NAME,
        generation_config=generation_config,
    )

    # Per-launch context starts here
    chat_session = model.start_chat(history=[])
    return True


def main():
    if not enforce_password_gate():
        return

    if not configure_genai():
        return

    indicator_thread = Thread(target=init_indicator, daemon=True)
    indicator_thread.start()
    time.sleep(0.5)

    if pystray is not None:
        tray_thread = Thread(target=run_tray_icon, daemon=True)
        tray_thread.start()
        hide_console_window()
    else:
        print("Tray icon unavailable. Keeping CMD visible for control.")

    keyboard.add_hotkey("num 1", handle_primary_hotkey)
    keyboard.add_hotkey("num 0", handle_indicator_hotkey)
    keyboard.add_hotkey("num 2", handle_clear_ctx_hotkey)
    keyboard.add_hotkey("num 9", handle_exit_hotkey)

    keyboard.wait()


if __name__ == "__main__":
    main()
