import base64
import ctypes
import html
import importlib
import ipaddress
import io
import json
import logging
import math
import os
import queue
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import webbrowser
import atexit
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from ctypes import wintypes
from datetime import datetime, timezone
from pathlib import Path
from threading import Event, Lock, Thread
from urllib.parse import urlparse

AUTH_SHELL_SUBPROCESS_FLAG = "--auth-shell-dialog"
STARTUP_SPLASH_SUBPROCESS_FLAG = "--startup-splash-dialog"

if len(sys.argv) >= 3 and sys.argv[1] == STARTUP_SPLASH_SUBPROCESS_FLAG:
    PROCESS_ROLE = "startup_splash"
elif len(sys.argv) >= 4 and sys.argv[1] == AUTH_SHELL_SUBPROCESS_FLAG:
    PROCESS_ROLE = "auth_shell"
else:
    PROCESS_ROLE = "main"

IS_STARTUP_SPLASH_SUBPROCESS = PROCESS_ROLE == "startup_splash"
IS_AUTH_SHELL_SUBPROCESS = PROCESS_ROLE == "auth_shell"


class _LazyModule:
    def __init__(self, module_name, optional=False):
        self._module_name = str(module_name or "").strip()
        self._optional = bool(optional)
        self._attempted = False
        self._module = None

    def _load(self):
        if not self._attempted:
            self._attempted = True
            try:
                self._module = importlib.import_module(self._module_name)
            except Exception:
                if not self._optional:
                    raise
                self._module = None
        return self._module

    def __getattr__(self, name):
        module = self._load()
        if module is None:
            raise AttributeError(name)
        return getattr(module, name)

    def __bool__(self):
        return self._load() is not None


class _LazyPILNamespace:
    _SUPPORTED = {"Image", "ImageDraw", "ImageFont", "ImageGrab"}

    def __init__(self):
        self._cache = {}

    def __getattr__(self, name):
        if name not in self._SUPPORTED:
            raise AttributeError(name)
        module = self._cache.get(name)
        if module is None:
            module = importlib.import_module(f"PIL.{name}")
            self._cache[name] = module
        return module

keyboard = _LazyModule("keyboard")
pyperclip = _LazyModule("pyperclip")
PIL = _LazyPILNamespace()
_pystray_module = _LazyModule("pystray", optional=True)
_psutil_module = _LazyModule("psutil", optional=True)
_winreg_module = _LazyModule("winreg", optional=True)


def get_pystray_module():
    return _pystray_module._load()


def get_psutil_module():
    return _psutil_module._load()


def get_winreg_module():
    return _winreg_module._load()

webview = None
_webview_import_attempted = False
_requests_module = None
_requests_import_attempted = False
_requests_runtime_configured = False
_crypto_primitives = None
_modern_genai_module = None
_modern_genai_import_attempted = False


def get_webview_module():
    global webview, _webview_import_attempted
    if _webview_import_attempted:
        return webview
    _webview_import_attempted = True
    try:
        with profile_suspend_calls():
            import webview as webview_module
    except Exception:
        webview = None
    else:
        webview = webview_module
    return webview


def get_requests_module():
    global _requests_module, _requests_import_attempted
    if _requests_import_attempted:
        return _requests_module
    _requests_import_attempted = True
    try:
        with profile_span("runtime.import_requests"):
            with profile_suspend_calls():
                import requests as requests_module
    except Exception:
        _requests_module = None
        raise
    _requests_module = requests_module
    configure_requests_runtime()
    return _requests_module


def configure_requests_runtime():
    global _requests_runtime_configured
    if _requests_runtime_configured:
        return
    _requests_runtime_configured = True
    if os.name != "nt":
        return
    try:
        from urllib3.util import connection as urllib3_connection

        urllib3_connection.allowed_gai_family = lambda: socket.AF_INET
    except Exception:
        logger.debug("Could not force IPv4 for requests runtime.", exc_info=True)


def get_http_session():
    global HTTP_SESSION
    if HTTP_SESSION is None:
        session = get_requests_module().Session()
        session.trust_env = False
        HTTP_SESSION = session
    return HTTP_SESSION


def get_crypto_primitives():
    global _crypto_primitives
    if _crypto_primitives is None:
        with profile_span("runtime.import_crypto"):
            with profile_suspend_calls():
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
                from cryptography.hazmat.primitives.hashes import SHA256 as _SHA256
                from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC as _PBKDF2HMAC

        _crypto_primitives = (_SHA256, _PBKDF2HMAC, _AESGCM)
    return _crypto_primitives


def has_pywebview_support():
    webview_module = get_webview_module()
    return bool(
        webview_module is not None
        and callable(getattr(webview_module, "create_window", None))
        and callable(getattr(webview_module, "start", None))
    )


def resolve_pywebview_start_kwargs():
    gui_override = str(os.environ.get("EAE_PYWEBVIEW_GUI", "") or "").strip().lower()
    start_kwargs = {"private_mode": True}
    if gui_override:
        start_kwargs["gui"] = gui_override
    return start_kwargs

APP_NAME = "EyesAndEars"
APP_VERSION = "2.7"
STARTUP_SPLASH_READY_FILE_NAME = "ready.flag"
STARTUP_SPLASH_READY_TIMEOUT_SECONDS = 8.0
STARTUP_SPLASH_READY_POLL_SECONDS = 0.10
STARTUP_SPLASH_MIN_VISIBLE_SECONDS = 0.0
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s [%(name)s] %(message)s")
logger = logging.getLogger(APP_NAME)

INDICATOR_DEBUG_LOG_FILE_NAME = "indicator-debug.log"
indicator_debug_path = None
indicator_debug_lock = Lock()
indicator_debug_run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')}-{os.getpid()}"


def _indicator_debug_candidate_dirs():
    dirs = []
    if getattr(sys, "frozen", False):
        try:
            dirs.append(Path(sys.executable).resolve().parent)
        except Exception:
            pass
    try:
        dirs.append(Path(__file__).resolve().parent)
    except Exception:
        pass
    local_appdata = str(os.environ.get("LOCALAPPDATA", "") or "").strip()
    if local_appdata:
        dirs.append(Path(local_appdata) / APP_NAME)
    dirs.append(Path.cwd())
    return dirs


def resolve_indicator_debug_path():
    global indicator_debug_path
    if indicator_debug_path:
        return indicator_debug_path
    for directory in _indicator_debug_candidate_dirs():
        try:
            directory.mkdir(parents=True, exist_ok=True)
            candidate = directory / INDICATOR_DEBUG_LOG_FILE_NAME
            with open(candidate, "a", encoding="utf-8"):
                pass
            indicator_debug_path = candidate
            return indicator_debug_path
        except Exception:
            continue
    indicator_debug_path = Path(INDICATOR_DEBUG_LOG_FILE_NAME)
    return indicator_debug_path


def indicator_debug(event_name, **meta):
    try:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "pid": os.getpid(),
            "role": PROCESS_ROLE,
            "run_id": indicator_debug_run_id,
            "event": str(event_name or ""),
            "meta": {k: (v if isinstance(v, (str, int, float, bool)) or v is None else str(v)) for k, v in meta.items()},
        }
        log_path = resolve_indicator_debug_path()
        with indicator_debug_lock:
            with open(log_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=True) + "\n")
    except Exception:
        pass

CONFIG_FILE_NAME = "config.json"
CONFIG_SAVE_RETRY_COUNT = 5
CONFIG_SAVE_RETRY_DELAY_SECONDS = 0.01
HARDCODED_SERVER_URL = os.environ.get(
    "EAE_SERVER_URL",
    "https://eyesandears-platform-vercel.vercel.app",
).strip()
DEFAULT_SERVER_URL = HARDCODED_SERVER_URL.strip().rstrip("/")
DEFAULT_WEBSITE_URL = os.environ.get("EAE_WEBSITE_URL", DEFAULT_SERVER_URL).strip().rstrip("/") or DEFAULT_SERVER_URL
FREE_MODEL_NAME = "gemini-2.5-flash"
DEFAULT_MODEL_NAME = FREE_MODEL_NAME
GENAI_TRANSIENT_STATUS_CODES = {500, 502, 503, 504}
GENAI_TRANSIENT_ERROR_MARKERS = (
    "503 unavailable",
    "currently experiencing high demand",
    "high demand",
    "service unavailable",
    "temporarily unavailable",
    "try again later",
    "backend error",
    "deadline exceeded",
    "connection reset",
    "connection aborted",
)
GENAI_TRANSIENT_RETRY_ATTEMPTS = 3
GENAI_TRANSIENT_RETRY_BASE_DELAY_SECONDS = 0.85
GENAI_TRANSIENT_RETRY_MAX_DELAY_SECONDS = 3.5
DEFAULT_WINGET_PACKAGE_ID = os.environ.get("EYESANDEARS_WINGET_ID", "FediMust.EyesAndEars").strip()
DEFAULT_RELEASE_REPO = os.environ.get("EYESANDEARS_RELEASE_REPO", "Fedi-Must/EyesAndEars").strip() or "Fedi-Must/EyesAndEars"
DEFAULT_RELEASES_API_URL = os.environ.get(
    "EYESANDEARS_RELEASES_API_URL",
    f"https://api.github.com/repos/{DEFAULT_RELEASE_REPO}/releases/latest",
).strip()
DEFAULT_RELEASES_PAGE_URL = os.environ.get(
    "EYESANDEARS_RELEASES_PAGE_URL",
    f"https://github.com/{DEFAULT_RELEASE_REPO}/releases/latest",
).strip()
AUTO_UPDATE_ENABLED = os.environ.get("EYESANDEARS_AUTO_UPDATE", "1").strip().lower() not in {"0", "false", "no", "off"}
SELF_UNINSTALL_DELAY_SECONDS = 2
API_KEY_ENV_FALLBACK = ("EYESANDEARS_API_KEY", "EAE_API_KEY")
PRO_MODELS_ENV = "EAE_PRO_MODELS_JSON"
TRUSTED_TIME_URLS_ENV = "EAE_TRUSTED_TIME_URLS"
HTTP_SESSION = None
DEFAULT_TRUSTED_TIME_URLS = (
    "https://worldtimeapi.org/api/timezone/Etc/UTC",
    "https://timeapi.io/api/Time/current/zone?timeZone=UTC",
)
TRUSTED_TIME_URLS = tuple(
    url
    for url in (
        part.strip()
        for part in str(os.environ.get(TRUSTED_TIME_URLS_ENV, "") or "").split(",")
    )
    if url
) or DEFAULT_TRUSTED_TIME_URLS

SW_HIDE = 0
HWND_TOPMOST = -1
CRYPTPROTECT_UI_FORBIDDEN = 0x01
SWP_NOSIZE = 0x0001
SWP_NOACTIVATE = 0x0010
SWP_SHOWWINDOW = 0x0040
FAST_UPLOAD_JPEG_QUALITY = 82
FAST_UPLOAD_MAX_EDGE = 1800
ANSWER_PREVIEW_RETENTION_SECONDS = 5.0
TRUSTED_TIME_TIMEOUT_SECONDS = 8
PRO_AUTH_FAILURE_WINDOW_SECONDS = 30 * 60
PRO_AUTH_LOCKOUT_BASE_SECONDS = 30
PRO_AUTH_FIRST_LOCKOUT_FAILURE = 3
PRO_AUTH_HARD_LOCKOUT_FAILURE = 9
PRO_AUTH_HARD_LOCKOUT_SECONDS = 24 * 60 * 60
UPDATE_METADATA_CACHE_TTL_SECONDS = 300.0
PRO_AUTH_HIDDEN_DIR_NAME = ".runtime"
PRO_AUTH_HIDDEN_FILE_NAME = "session.idx"
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x2000
WM_NCLBUTTONDOWN = 0x00A1
WM_SYSCOMMAND = 0x0112
HTCAPTION = 2
SC_MOVE = 0xF010
HTLEFT = 10
HTRIGHT = 11
HTTOP = 12
HTTOPLEFT = 13
HTTOPRIGHT = 14
HTBOTTOM = 15
HTBOTTOMLEFT = 16
HTBOTTOMRIGHT = 17

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
processing_lock = Lock()
answer_epoch_lock = Lock()
answer_epoch = 0
hotkey_block_until = {
    "primary": 0.0,
    "indicator": 0.0,
    "clear_ctx": 0.0,
    "paste_all": 0.0,
    "repeat_prev": 0.0,
    "exit": 0.0,
}
NUMPAD_SCAN_TO_ACTION = {
    79: "primary",      # Numpad 1 / End
    82: "indicator",    # Numpad 0 / Insert
    80: "clear_ctx",    # Numpad 2 / Down
    81: "paste_all",    # Numpad 3 / PageDown
    75: "repeat_prev",  # Numpad 4 / Left
    73: "exit",         # Numpad 9 / PageUp
}
TOPROW_SCAN_TO_ACTION = {
    2: "primary",       # 1
    11: "indicator",    # 0
    3: "clear_ctx",     # 2
    4: "paste_all",     # 3
    5: "repeat_prev",   # 4
    10: "exit",         # 9
}
HOTKEY_ACTION_ORDER = (
    "primary",
    "indicator",
    "clear_ctx",
    "paste_all",
    "repeat_prev",
    "exit",
)
DEFAULT_COMMAND_HOTKEYS = {
    "numpad": {
        "primary": "numpad1",
        "indicator": "numpad0",
        "clear_ctx": "numpad2",
        "paste_all": "numpad3",
        "repeat_prev": "numpad4",
        "exit": "numpad9",
    },
    "toprow": {
        "primary": "digit1",
        "indicator": "digit0",
        "clear_ctx": "digit2",
        "paste_all": "digit3",
        "repeat_prev": "digit4",
        "exit": "digit9",
    },
}
ALLOWED_HOTKEY_BINDINGS = {
    "escape": {"scan_code": 1, "keypad": None, "label": "Esc"},
    "digit1": {"scan_code": 2, "keypad": False, "label": "1"},
    "digit2": {"scan_code": 3, "keypad": False, "label": "2"},
    "digit3": {"scan_code": 4, "keypad": False, "label": "3"},
    "digit4": {"scan_code": 5, "keypad": False, "label": "4"},
    "digit5": {"scan_code": 6, "keypad": False, "label": "5"},
    "digit6": {"scan_code": 7, "keypad": False, "label": "6"},
    "digit7": {"scan_code": 8, "keypad": False, "label": "7"},
    "digit8": {"scan_code": 9, "keypad": False, "label": "8"},
    "digit9": {"scan_code": 10, "keypad": False, "label": "9"},
    "digit0": {"scan_code": 11, "keypad": False, "label": "0"},
    "tab": {"scan_code": 15, "keypad": None, "label": "Tab"},
    "space": {"scan_code": 57, "keypad": None, "label": "Space"},
    "f1": {"scan_code": 59, "keypad": None, "label": "F1"},
    "f2": {"scan_code": 60, "keypad": None, "label": "F2"},
    "f3": {"scan_code": 61, "keypad": None, "label": "F3"},
    "f4": {"scan_code": 62, "keypad": None, "label": "F4"},
    "f5": {"scan_code": 63, "keypad": None, "label": "F5"},
    "f6": {"scan_code": 64, "keypad": None, "label": "F6"},
    "f7": {"scan_code": 65, "keypad": None, "label": "F7"},
    "f8": {"scan_code": 66, "keypad": None, "label": "F8"},
    "f9": {"scan_code": 67, "keypad": None, "label": "F9"},
    "f10": {"scan_code": 68, "keypad": None, "label": "F10"},
    "home": {"scan_code": 71, "keypad": False, "label": "Home"},
    "numpad7": {"scan_code": 71, "keypad": True, "label": "Num 7"},
    "arrowup": {"scan_code": 72, "keypad": False, "label": "Up"},
    "numpad8": {"scan_code": 72, "keypad": True, "label": "Num 8"},
    "pageup": {"scan_code": 73, "keypad": False, "label": "PgUp"},
    "numpad9": {"scan_code": 73, "keypad": True, "label": "Num 9"},
    "numpadsubtract": {"scan_code": 74, "keypad": True, "label": "Num -"},
    "arrowleft": {"scan_code": 75, "keypad": False, "label": "Left"},
    "numpad4": {"scan_code": 75, "keypad": True, "label": "Num 4"},
    "numpad5": {"scan_code": 76, "keypad": True, "label": "Num 5"},
    "arrowright": {"scan_code": 77, "keypad": False, "label": "Right"},
    "numpad6": {"scan_code": 77, "keypad": True, "label": "Num 6"},
    "numpadadd": {"scan_code": 78, "keypad": True, "label": "Num +"},
    "end": {"scan_code": 79, "keypad": False, "label": "End"},
    "numpad1": {"scan_code": 79, "keypad": True, "label": "Num 1"},
    "arrowdown": {"scan_code": 80, "keypad": False, "label": "Down"},
    "numpad2": {"scan_code": 80, "keypad": True, "label": "Num 2"},
    "pagedown": {"scan_code": 81, "keypad": False, "label": "PgDn"},
    "numpad3": {"scan_code": 81, "keypad": True, "label": "Num 3"},
    "insert": {"scan_code": 82, "keypad": False, "label": "Insert"},
    "numpad0": {"scan_code": 82, "keypad": True, "label": "Num 0"},
    "delete": {"scan_code": 83, "keypad": False, "label": "Delete"},
    "numpaddecimal": {"scan_code": 83, "keypad": True, "label": "Num ."},
    "numpadenter": {"scan_code": 28, "keypad": True, "label": "Num Enter"},
    "numpadmultiply": {"scan_code": 55, "keypad": True, "label": "Num *"},
    "numpaddivide": {"scan_code": 53, "keypad": True, "label": "Num /"},
    "f11": {"scan_code": 87, "keypad": None, "label": "F11"},
    "f12": {"scan_code": 88, "keypad": None, "label": "F12"},
}
RESERVED_SYSTEM_HOTKEY_BINDINGS = {"tab", "f4", "escape"}
DEFAULT_HOTKEY_MODE = "numpad"
POST_TYPE_GUARD_SECONDS = ANSWER_PREVIEW_RETENTION_SECONDS

command_key_mode = DEFAULT_HOTKEY_MODE
command_hotkeys = dict(DEFAULT_COMMAND_HOTKEYS[DEFAULT_HOTKEY_MODE])
command_hotkeys_customized = False
command_key_hooks = []
command_mode_probe_hook = None
command_probe_window_start = 0.0
command_probe_attempt_count = 0
command_probe_last_scan = -1
command_numpad_seen = False

post_type_guard_lock = Lock()
post_type_guard_hook = None
post_type_guard_active = False
post_type_guard_until = 0.0
post_type_guard_mouse = None
post_type_guard_stop = Event()
post_type_guard_thread = None
typing_pressed_scancodes = set()
typing_pressed_lock = Lock()
progress_ui_lock = Lock()
progress_ui_last_update = 0.0
progress_ui_last_index = -1
# Coalesce UI progress updates so typing stays responsive on long answers.
PROGRESS_UI_MIN_INTERVAL = 0.11
PROGRESS_UI_MIN_STEP = 12
indicator_progress_lock = Lock()
indicator_progress_pending_text = ""
indicator_progress_pending_index = 0
indicator_progress_dispatch_scheduled = False
indicator_dispatch_queue = queue.SimpleQueue()
indicator_state_lock = Lock()
PROCESS_SNAPSHOT_CACHE_SECONDS = 30.0

auth_mode = "account"
server_url = DEFAULT_SERVER_URL
api_key = ""
model_name = DEFAULT_MODEL_NAME
device_id = ""
ui_language = "en"
indicator_position_key = "bottom_right"
selected_pro_model_key = ""
ui_theme_preference = "system"

session_lock = Lock()
session_id = ""
session_token = ""
session_status_text = "Not authenticated"
session_active = False
user_email = ""
remember_me_enabled = False

local_model = None
local_chat_session = None
api_backend_name = "none"
update_state_lock = Lock()
update_check_started = False
update_in_progress = False
update_metadata_cache = None
update_metadata_cache_at = 0.0

tray_icon = None
indicator = None
indicator_ready_event = Event()
indicator_runtime_active = False
indicator_runtime_hidden = True
privacy_guard_thread = None
privacy_process_thread = None
privacy_guard_stop_event = Event()
privacy_process_state_lock = Lock()
privacy_required_by_process = False
privacy_forced_hidden = False
indicator_manual_hidden = False
indicator_capture_protected = False
startup_progress_window = None
startup_progress_lock = Lock()
settings_window_lock = Lock()
settings_window_open = False
config_file_lock = Lock()
config_record_cache = None
config_record_cache_mtime_ns = -1
config_record_cache_loaded = False
pro_auth_guard_lock = Lock()
process_snapshot_cache_lock = Lock()
process_snapshot_cache_at = 0.0
process_snapshot_cache_running = set()
process_snapshot_cache_pid = {}
indicator_blob_size_key = str(os.environ.get("EAE_BLOB_SIZE", "medium")).strip().lower().replace("-", "_").replace(" ", "_")
if indicator_blob_size_key not in {"very_small", "small", "medium", "large"}:
    indicator_blob_size_key = "medium"

INDICATOR_VISIBLE_BY_DEFAULT = os.environ.get("EAE_SHOW_INDICATOR", "").strip().lower() not in {"0", "false", "no", "off"}
startup_loading_screen_enabled = os.environ.get("EAE_SHOW_STARTUP_SCREEN", "").strip().lower() not in {"0", "false", "no", "off"}
# Temporary debug default: keep windows visible to screenshots.
HIDE_INDICATOR_FROM_CAPTURE = os.environ.get("EAE_HIDE_INDICATOR_FROM_CAPTURE", "1").strip().lower() not in {"0", "false", "no", "off"}
STRICT_PRIVACY_FALLBACK = os.environ.get("EAE_STRICT_PRIVACY_FALLBACK", "").strip().lower() in {"1", "true", "yes", "on"}
capture_privacy_enabled = bool(HIDE_INDICATOR_FROM_CAPTURE)
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
UI_GLASS = "#0C1730"
UI_GLASS_ALT = "#122344"
UI_SUCCESS = "#1BB56D"
UI_WARNING = "#E6B800"
UI_PAUSE = "#3C91FF"
UI_READY = "#00D25E"
UI_NEUTRAL = "#5F6980"
INDICATOR_BLOB_SIZES = {
    "very_small": 12,
    "small": 16,
    "medium": 20,
    "large": 26,
}
INDICATOR_BLOB_SIZE_LABELS = {
    "very_small": "Very Small",
    "small": "Small",
    "medium": "Medium",
    "large": "Large",
}
INDICATOR_POSITIONS = {
    "top_left": {"x": "left", "y": "top"},
    "top_center": {"x": "center", "y": "top"},
    "top_right": {"x": "right", "y": "top"},
    "left_center": {"x": "left", "y": "center"},
    "right_center": {"x": "right", "y": "center"},
    "bottom_left": {"x": "left", "y": "bottom"},
    "bottom_center": {"x": "center", "y": "bottom"},
    "bottom_right": {"x": "right", "y": "bottom"},
}
INDICATOR_PREVIEW_POINTS = {
    "top_left": {"x": 0.12, "y": 0.17},
    "top_center": {"x": 0.50, "y": 0.17},
    "top_right": {"x": 0.88, "y": 0.17},
    "left_center": {"x": 0.12, "y": 0.50},
    "right_center": {"x": 0.88, "y": 0.50},
    "bottom_left": {"x": 0.12, "y": 0.83},
    "bottom_center": {"x": 0.50, "y": 0.83},
    "bottom_right": {"x": 0.88, "y": 0.83},
}
INDICATOR_MARGIN_X = 10
INDICATOR_MARGIN_Y = 50
INDICATOR_PANEL_MAX_HEIGHT_RATIO = 0.72
INDICATOR_PANEL_SCROLL_LINES = 3
INDICATOR_TYPING_PANEL_RENDER_MIN_INTERVAL = 0.16
INDICATOR_TYPING_PANEL_RENDER_MIN_STEP = 24
INDICATOR_TYPING_HIGHLIGHT_MAX_CHARS = 420
INDICATOR_NATIVE_HEARTBEAT_MS = 6000
ui_crisp_mode_initialized = False
system_dark_theme_enabled = False


LIGHT_THEME = {
    "UI_BG": "#E6EDF8",
    "UI_CARD_BG": "#F4F8FF",
    "UI_PANEL_BG": "#FFFFFF",
    "UI_FIELD_BG": "#F9FBFF",
    "UI_TEXT": "#102A56",
    "UI_MUTED": "#4C6082",
    "UI_BORDER": "#C7D7F2",
    "UI_SOFT": "#DEE9FF",
    "UI_PRIMARY": "#1459D9",
    "UI_PRIMARY_ACTIVE": "#0F46AD",
    "UI_PRIMARY_SOFT": "#9FBBF5",
    "UI_GHOST_BG": "#EDF3FF",
    "UI_GHOST_ACTIVE": "#DFEAFE",
    "UI_DANGER": "#BA1A1A",
    "UI_ACCENT": "#1C77FF",
    "UI_GLASS": "#0C1730",
    "UI_GLASS_ALT": "#122344",
    "UI_SUCCESS": "#1BB56D",
    "UI_WARNING": "#E6B800",
    "UI_PAUSE": "#3C91FF",
    "UI_READY": "#00D25E",
    "UI_NEUTRAL": "#5F6980",
}


DARK_THEME = {
    "UI_BG": "#0A1220",
    "UI_CARD_BG": "#101C31",
    "UI_PANEL_BG": "#13233C",
    "UI_FIELD_BG": "#162840",
    "UI_TEXT": "#F2F7FF",
    "UI_MUTED": "#A8BCD9",
    "UI_BORDER": "#24395B",
    "UI_SOFT": "#193254",
    "UI_PRIMARY": "#4B9DFF",
    "UI_PRIMARY_ACTIVE": "#2E82E8",
    "UI_PRIMARY_SOFT": "#244775",
    "UI_GHOST_BG": "#15253D",
    "UI_GHOST_ACTIVE": "#1C3152",
    "UI_DANGER": "#FF8F8F",
    "UI_ACCENT": "#66AEFF",
    "UI_GLASS": "#081321",
    "UI_GLASS_ALT": "#0E1D34",
    "UI_SUCCESS": "#3DDB8A",
    "UI_WARNING": "#F4C95D",
    "UI_PAUSE": "#65A9FF",
    "UI_READY": "#41E17E",
    "UI_NEUTRAL": "#7A869B",
}

TRANSLATIONS = {
    "en": {
        "lang.en": "English",
        "lang.fr": "French",
        "dialog.heading.info": "Information",
        "dialog.heading.error": "Something needs attention",
        "dialog.heading.retry": "Connection issue",
        "dialog.ok": "OK",
        "dialog.retry": "Retry",
        "dialog.quit": "Quit",
        "dialog.retry_login": "Retry login",
        "dialog.cancel": "Cancel",
        "startup.title": "Starting EyesAndEars",
        "startup.subtitle": "Preparing your private desktop assistant",
        "startup.launching": "Launching",
        "startup.restoring": "Restoring your preferences",
        "startup.opening_setup": "Opening setup",
        "startup.checking_auth": "Checking your sign-in mode",
        "startup.connecting_pro": "Signing in",
        "startup.initializing_model": "Initializing AI backend",
        "startup.starting_indicator": "Starting indicator",
        "startup.ready": "Ready",
        "startup.detail.launching": "Loading interface",
        "startup.detail.restoring": "Restoring saved settings and secure secrets",
        "startup.detail.opening_setup": "Waiting for your setup choices",
        "startup.detail.checking_auth": "Validating the selected access mode",
        "startup.detail.connecting_pro": "Signing in to your account",
        "startup.detail.initializing_model": "Checking your API key and model runtime",
        "startup.detail.starting_indicator": "Starting the floating capture indicator",
        "startup.detail.ready": "EyesAndEars is ready",
        "auth.window_title": "EyesAndEars Setup",
        "auth.window_caption": "Setup",
        "auth.title": "Eyes & Ears",
        "auth.subtitle": "Modern desktop capture assistant with private local controls.",
        "auth.settings": "Settings",
        "auth.settings.copy": "Language, startup screen, indicator location, appearance, and hotkeys.",
        "auth.settings.done": "Done",
        "auth.open_site": "Open website",
        "auth.window.minimize": "Minimize",
        "auth.window.maximize": "Maximize",
        "auth.window.restore": "Restore",
        "auth.window.close": "Close",
        "auth.language": "Language",
        "auth.mode.free": "Free mode",
        "auth.mode.free.help": "Use your own Gemini API key",
        "auth.mode.pro": "Account mode",
        "auth.mode.pro.help": "Use your website account",
        "auth.section.startup": "Startup",
        "auth.startup_screen.label": "Loading screen",
        "auth.startup_screen.copy": "Disable this to launch directly without the animated splash screen.",
        "auth.startup_screen.enabled": "Enabled",
        "auth.startup_screen.disabled": "Disabled",
        "auth.section.appearance": "Appearance",
        "auth.section.theme": "Theme",
        "auth.theme.copy": "Pick whether the setup windows follow your system or stay in one mode.",
        "theme.system": "System",
        "theme.dark": "Dark",
        "theme.light": "Light",
        "auth.section.indicator_size": "Indicator size",
        "auth.section.indicator_position": "Indicator placement",
        "auth.section.free": "Use your own Gemini API key",
        "auth.section.pro": "Sign in with your account",
        "auth.section.hotkeys": "Hotkeys",
        "auth.hotkeys.copy": "Click an action, then press the replacement key. Letters are not allowed.",
        "auth.hotkeys.waiting": "Press a new key...",
        "auth.hotkeys.invalid": "Letters and unsupported keys are not allowed here.",
        "auth.hotkeys.duplicate": "That key is already assigned to another action.",
        "auth.hotkeys.reset": "Reset to default numpad",
        "auth.hotkeys.reset_done": "Default numpad controls restored.",
        "auth.hotkey.primary": "Capture / Pause / Resume",
        "auth.hotkey.indicator": "Toggle indicator",
        "auth.hotkey.clear_ctx": "Clear pending",
        "auth.hotkey.paste_all": "Paste remaining",
        "auth.hotkey.repeat_prev": "Repeat previous",
        "auth.hotkey.exit": "Quit",
        "auth.hotkey.settings": "Double-click Open settings",
        "auth.api.label": "Gemini API key",
        "auth.api.placeholder": "Paste your Gemini API key",
        "auth.api.paste": "Paste",
        "auth.api.show": "Show",
        "auth.api.hide": "Hide",
        "auth.api.link": "Don't have a key ? Get one here",
        "auth.api.note": "Stored locally with Windows data protection (DPAPI).",
        "auth.api.helper": "We verify your key by initializing Gemini. A local format check only blocks obvious garbage.",
        "auth.pro.label": "Account access",
        "auth.pro.placeholder": "Use the account sign-in window",
        "auth.pro.note": "Desktop access now uses your website email and password.",
        "auth.account.title": "Website account",
        "auth.account.copy": "Sign in with your website email and password. Your Gemini API key stays encrypted in the dashboard and is decrypted locally on this device.",
        "auth.account.email": "Email",
        "auth.account.email.placeholder": "name@example.com",
        "auth.account.password": "Password",
        "auth.account.password.placeholder": "Enter your website password",
        "auth.account.import": "Import user settings",
        "auth.account.import.loading": "Importing...",
        "auth.account.remember": "Remember me",
        "auth.account.dashboard": "Open dashboard",
        "auth.account.tutorial": "Open setup tutorial",
        "auth.account.tutorial.help": "Having trouble? Follow the website setup tutorial.",
        "auth.account.reset": "Reset password",
        "auth.account.helper": "Add or replace your Gemini API key from the dashboard whenever needed. You can leave the password blank when only changing local settings.",
        "auth.pro.model": "Preferred model",
        "auth.pro.model.note": "Current Gemini screenshot models that support direct text answers.",
        "auth.preview.title": "Indicator location",
        "auth.preview.copy": "The floating indicator stays native, smooth, and capture-protected.",
        "auth.security": "Windows privacy protections and secure local secret storage stay enabled.",
        "auth.continue": "Continue",
        "auth.continue.loading": "Checking...",
        "auth.cancel": "Cancel",
        "auth.validation.api.empty": "Enter your Gemini API key.",
        "auth.validation.api.short": "This key looks too short. Remove accidental truncation and try again.",
        "auth.validation.api.whitespace": "Remove spaces or line breaks from the API key and try again.",
        "auth.validation.api.shape": "This key still looks malformed. Check for extra characters and try again.",
        "auth.validation.pro.empty": "Complete sign-in in the account window.",
        "auth.validation.account.email.empty": "Enter your account email.",
        "auth.validation.account.email.invalid": "Enter a valid email address.",
        "auth.validation.account.password.empty": "Enter your password.",
        "auth.status.free": "Free mode checks your API key locally on this device.",
        "auth.status.pro": "Account mode signs you in through the website.",
        "auth.status.account": "Desktop access uses your website account and local Gemini decryption.",
        "auth.login.title": "Login to Eyes And Ears",
        "position.top_left": "Top left",
        "position.top_center": "Top center",
        "position.top_right": "Top right",
        "position.left_center": "Left center",
        "position.right_center": "Right center",
        "position.bottom_left": "Bottom left",
        "position.bottom_center": "Bottom center",
        "position.bottom_right": "Bottom right",
        "size.very_small": "Very small",
        "size.small": "Small",
        "size.medium": "Medium",
        "size.large": "Large",
        "status.window_title": "EyesAndEars Status",
        "status.mode": "Mode",
        "status.mode.free": "Free mode",
        "status.mode.pro": "Account mode",
        "status.status": "Status",
        "status.server": "Server",
        "status.user": "User",
        "status.code": "Code",
        "status.backend": "Backend",
        "status.model": "Model",
        "status.api_key": "API key",
        "status.pro_model": "Preferred model",
        "status.not_set": "-",
        "tray.open": "Open status",
        "tray.toggle": "Toggle indicator",
        "tray.capture_disable": "Allow screenshots for debugging",
        "tray.capture_enable": "Re-enable screenshot hiding",
        "tray.check_updates": "Check for updates",
        "tray.quit": "Quit",
        "tray.status": "Status: {status}",
        "update.current": "EyesAndEars is already up to date.",
        "update.available": "Updating to version {version}. EyesAndEars will restart.",
        "update.failed": "Update failed: {detail}",
        "error.save_code": "Could not securely save your code on this machine.",
        "error.save_api": "Could not securely save your API key on this machine.",
        "error.connect_server": "Could not connect to the server.\n{detail}",
        "error.server_non_json": "The server returned an unexpected response ({status_code}).",
        "error.network_connect": "Could not reach the EyesAndEars website. Check your internet connection, VPN, or firewall and try again.",
        "error.network_timeout": "The EyesAndEars website took too long to respond. Try again in a moment.",
        "error.network_secure": "A secure connection to the EyesAndEars website could not be established.",
        "error.auth_failed": "Authentication request failed ({status_code}). {detail}",
        "error.auth_denied": "Authentication denied.",
        "error.pro_lockout_wait": "Too many incorrect sign-in attempts. Try again in {seconds} seconds.",
        "error.pro_lockout_locked": "Too many incorrect sign-in attempts. This device is locked for {seconds} seconds.",
        "error.pro_time_unavailable": "Couldn't verify trusted online time. Check your connection and try again.",
        "error.api_empty": "API key is empty.",
        "error.no_sdk": "Could not initialize API mode.\n{detail}",
        "error.api_credits": "Your API key ran out of credits.\nAdd credits or enter a new key.",
        "error.api_invalid": "Your API key is invalid or expired.\nEnter a valid Gemini API key.",
        "error.api_init": "Could not initialize API mode.\n{detail}",
        "error.api_required": "API mode needs a valid Gemini API key.",
        "error.api_select_mode": "Select Free mode and enter a valid Gemini API key.",
        "error.session_inactive": "Session inactive. Restart the app and sign in again.",
        "error.license_retry": "Retry sign-in?",
        "status.code_active": "Account session active",
        "status.code_disconnected": "Account sign-in failed: {detail}",
        "status.code_session_lost": "Account session lost",
        "status.code_network_error": "Account connection lost",
        "status.code_expired": "Account session expired. Sign in again.",
        "status.code_inactive": "Account sign-in required",
        "status.api_active": "Local Gemini ready ({backend})",
        "status.api_invalid": "Gemini API key invalid - update it in the dashboard",
        "status.api_credits": "Gemini API key needs credits - update it in the dashboard",
        "status.api_required": "Gemini API key missing - add it in the dashboard",
        "status.stopped": "Stopped",
        "status.not_authenticated": "Not authenticated",
        "indicator.cooldown": "Typing finished. Controls unlock in {seconds}s.",
    },
    "fr": {
        "lang.en": "Anglais",
        "lang.fr": "Francais",
        "dialog.heading.info": "Information",
        "dialog.heading.error": "Une action est requise",
        "dialog.heading.retry": "Probleme de connexion",
        "dialog.ok": "OK",
        "dialog.retry": "Reessayer",
        "dialog.quit": "Quitter",
        "dialog.retry_login": "Reessayer",
        "dialog.cancel": "Annuler",
        "startup.title": "Demarrage de EyesAndEars",
        "startup.subtitle": "Preparation de votre assistant prive",
        "startup.launching": "Lancement",
        "startup.restoring": "Restauration de vos preferences",
        "startup.opening_setup": "Ouverture de la configuration",
        "startup.checking_auth": "Verification du mode de connexion",
        "startup.connecting_pro": "Connexion au compte",
        "startup.initializing_model": "Initialisation du moteur IA",
        "startup.starting_indicator": "Demarrage de l'indicateur",
        "startup.ready": "Pret",
        "startup.detail.launching": "Chargement de l'interface",
        "startup.detail.restoring": "Restauration des reglages et secrets securises",
        "startup.detail.opening_setup": "En attente de vos choix de configuration",
        "startup.detail.checking_auth": "Validation du mode d'acces selectionne",
        "startup.detail.connecting_pro": "Connexion a votre compte",
        "startup.detail.initializing_model": "Verification de votre cle API et du moteur",
        "startup.detail.starting_indicator": "Demarrage de l'indicateur flottant",
        "startup.detail.ready": "EyesAndEars est pret",
        "auth.window_title": "Configuration EyesAndEars",
        "auth.window_caption": "Configuration",
        "auth.title": "Eyes & Ears",
        "auth.subtitle": "Assistant moderne de capture avec controles locaux et prives.",
        "auth.settings": "Reglages",
        "auth.settings.copy": "Langue, ecran de demarrage, emplacement de l'indicateur, apparence et raccourcis.",
        "auth.settings.done": "Terminer",
        "auth.open_site": "Ouvrir le site",
        "auth.window.minimize": "Reduire",
        "auth.window.maximize": "Agrandir",
        "auth.window.restore": "Restaurer",
        "auth.window.close": "Fermer",
        "auth.language": "Langue",
        "auth.mode.free": "Mode gratuit",
        "auth.mode.free.help": "Utiliser votre propre cle Gemini",
        "auth.mode.pro": "Mode compte",
        "auth.mode.pro.help": "Utiliser votre compte du site",
        "auth.section.startup": "Demarrage",
        "auth.startup_screen.label": "Ecran de chargement",
        "auth.startup_screen.copy": "Desactivez ceci pour lancer directement l'application sans l'ecran anime.",
        "auth.startup_screen.enabled": "Active",
        "auth.startup_screen.disabled": "Desactive",
        "auth.section.appearance": "Apparence",
        "auth.section.theme": "Theme",
        "auth.theme.copy": "Choisissez si la configuration suit le systeme ou reste dans un mode fixe.",
        "theme.system": "Systeme",
        "theme.dark": "Sombre",
        "theme.light": "Clair",
        "auth.section.indicator_size": "Taille de l'indicateur",
        "auth.section.indicator_position": "Position de l'indicateur",
        "auth.section.free": "Utiliser votre propre cle Gemini",
        "auth.section.pro": "Connexion avec votre compte",
        "auth.section.hotkeys": "Raccourcis",
        "auth.hotkeys.copy": "Cliquez sur une action puis appuyez sur la nouvelle touche. Les lettres sont interdites.",
        "auth.hotkeys.waiting": "Appuyez sur une nouvelle touche...",
        "auth.hotkeys.invalid": "Les lettres et les touches non prises en charge sont interdites ici.",
        "auth.hotkeys.duplicate": "Cette touche est deja utilisee par une autre action.",
        "auth.hotkeys.reset": "Reinitialiser au pave numerique",
        "auth.hotkeys.reset_done": "Les controles numeriques par defaut ont ete restaures.",
        "auth.hotkey.primary": "Capturer / Pause / Reprendre",
        "auth.hotkey.indicator": "Afficher ou masquer l'indicateur",
        "auth.hotkey.clear_ctx": "Effacer l'attente",
        "auth.hotkey.paste_all": "Coller le reste",
        "auth.hotkey.repeat_prev": "Repeter la precedente",
        "auth.hotkey.exit": "Quitter",
        "auth.hotkey.settings": "Double-clic Ouvrir les reglages",
        "auth.api.label": "Cle API Gemini",
        "auth.api.placeholder": "Collez votre cle API Gemini",
        "auth.api.paste": "Coller",
        "auth.api.show": "Afficher",
        "auth.api.hide": "Masquer",
        "auth.api.link": "Pas de cle ? Obtenez-en une ici",
        "auth.api.note": "Stockee localement avec la protection Windows (DPAPI).",
        "auth.api.helper": "Nous verifions votre cle en initialisant Gemini. Le controle local ne bloque que les erreurs evidentes.",
        "auth.pro.label": "Acces au compte",
        "auth.pro.placeholder": "Utilisez la fenetre de connexion au compte",
        "auth.pro.note": "L'acces desktop utilise maintenant l'email et le mot de passe du site.",
        "auth.account.title": "Compte du site",
        "auth.account.copy": "Connectez-vous avec l'email et le mot de passe du site. Votre cle Gemini reste chiffree dans le tableau de bord et n'est dechiffree que localement sur cet appareil.",
        "auth.account.email": "Email",
        "auth.account.email.placeholder": "nom@exemple.com",
        "auth.account.password": "Mot de passe",
        "auth.account.password.placeholder": "Entrez le mot de passe du site",
        "auth.account.import": "Importer les reglages",
        "auth.account.import.loading": "Importation...",
        "auth.account.remember": "Se souvenir de moi",
        "auth.account.dashboard": "Ouvrir le tableau de bord",
        "auth.account.tutorial": "Ouvrir le tutoriel de configuration",
        "auth.account.tutorial.help": "Besoin d'aide ? Suivez le tutoriel de configuration du site.",
        "auth.account.reset": "Reinitialiser le mot de passe",
        "auth.account.helper": "Ajoutez ou remplacez votre cle Gemini depuis le tableau de bord si besoin. Vous pouvez laisser le mot de passe vide si vous modifiez seulement les reglages locaux.",
        "auth.pro.model": "Modele prefere",
        "auth.pro.model.note": "Modeles Gemini actuels pour les captures avec reponse texte directe.",
        "auth.preview.title": "Emplacement de l'indicateur",
        "auth.preview.copy": "L'indicateur flottant reste natif, fluide et protege des captures.",
        "auth.security": "Les protections de confidentialite Windows et le stockage local securise restent actifs.",
        "auth.continue": "Continuer",
        "auth.continue.loading": "Verification...",
        "auth.cancel": "Annuler",
        "auth.validation.api.empty": "Entrez votre cle API Gemini.",
        "auth.validation.api.short": "Cette cle semble trop courte. Verifiez si elle a ete tronquee.",
        "auth.validation.api.whitespace": "Supprimez les espaces ou retours a la ligne de la cle API.",
        "auth.validation.api.shape": "Cette cle semble mal formee. Verifiez les caracteres supplementaires.",
        "auth.validation.pro.empty": "Terminez la connexion dans la fenetre du compte.",
        "auth.validation.account.email.empty": "Entrez l'email du compte.",
        "auth.validation.account.email.invalid": "Entrez une adresse email valide.",
        "auth.validation.account.password.empty": "Entrez votre mot de passe.",
        "auth.status.free": "Le mode gratuit verifie votre cle API localement sur cet appareil.",
        "auth.status.pro": "Le mode compte ouvre votre session via le site.",
        "auth.status.account": "L'acces desktop utilise votre compte du site et le dechiffrement Gemini en local.",
        "auth.login.title": "Connexion a Eyes And Ears",
        "position.top_left": "Haut gauche",
        "position.top_center": "Haut centre",
        "position.top_right": "Haut droite",
        "position.left_center": "Centre gauche",
        "position.right_center": "Centre droite",
        "position.bottom_left": "Bas gauche",
        "position.bottom_center": "Bas centre",
        "position.bottom_right": "Bas droite",
        "size.very_small": "Tres petite",
        "size.small": "Petite",
        "size.medium": "Moyenne",
        "size.large": "Grande",
        "status.window_title": "Statut EyesAndEars",
        "status.mode": "Mode",
        "status.mode.free": "Mode gratuit",
        "status.mode.pro": "Mode compte",
        "status.status": "Statut",
        "status.server": "Serveur",
        "status.user": "Utilisateur",
        "status.code": "Code",
        "status.backend": "Moteur",
        "status.model": "Modele",
        "status.api_key": "Cle API",
        "status.pro_model": "Modele prefere",
        "status.not_set": "-",
        "tray.open": "Ouvrir le statut",
        "tray.toggle": "Afficher ou masquer l'indicateur",
        "tray.capture_disable": "Autoriser les captures pour le debug",
        "tray.capture_enable": "Reactiver le masquage des captures",
        "tray.check_updates": "Verifier les mises a jour",
        "tray.quit": "Quitter",
        "tray.status": "Statut : {status}",
        "update.current": "EyesAndEars est deja a jour.",
        "update.available": "Mise a jour vers la version {version}. EyesAndEars va redemarrer.",
        "update.failed": "La mise a jour a echoue : {detail}",
        "error.save_code": "Impossible d'enregistrer votre code de maniere securisee sur cette machine.",
        "error.save_api": "Impossible d'enregistrer votre cle API de maniere securisee sur cette machine.",
        "error.connect_server": "Impossible de se connecter au serveur.\n{detail}",
        "error.server_non_json": "Le serveur a renvoye une reponse inattendue ({status_code}).",
        "error.network_connect": "Impossible de joindre le site EyesAndEars. Verifiez votre connexion internet, votre VPN ou votre pare-feu puis reessayez.",
        "error.network_timeout": "Le site EyesAndEars met trop de temps a repondre. Reessayez dans un instant.",
        "error.network_secure": "Une connexion securisee au site EyesAndEars n'a pas pu etre etablie.",
        "error.auth_failed": "La demande d'authentification a echoue ({status_code}). {detail}",
        "error.auth_denied": "Authentification refusee.",
        "error.pro_lockout_wait": "Trop de tentatives de connexion incorrectes. Reessayez dans {seconds} secondes.",
        "error.pro_lockout_locked": "Trop de tentatives de connexion incorrectes. Cet appareil est bloque pour {seconds} secondes.",
        "error.pro_time_unavailable": "Impossible de verifier l'heure en ligne. Verifiez votre connexion puis reessayez.",
        "error.api_empty": "La cle API est vide.",
        "error.no_sdk": "Impossible d'initialiser le mode API.\n{detail}",
        "error.api_credits": "Votre cle API n'a plus de credits.\nAjoutez des credits ou entrez une nouvelle cle.",
        "error.api_invalid": "Votre cle API est invalide ou expiree.\nEntrez une cle Gemini valide.",
        "error.api_init": "Impossible d'initialiser le mode API.\n{detail}",
        "error.api_required": "Le mode gratuit a besoin d'une cle API Gemini valide.",
        "error.api_select_mode": "Selectionnez le mode gratuit et entrez une cle API Gemini valide.",
        "error.session_inactive": "Session inactive. Redemarrez l'application et reconnectez-vous.",
        "error.license_retry": "Reessayer la connexion ?",
        "status.code_active": "Session du compte active",
        "status.code_disconnected": "Echec de connexion au compte : {detail}",
        "status.code_session_lost": "Session du compte perdue",
        "status.code_network_error": "Connexion au compte perdue",
        "status.code_expired": "La session du compte a expire. Reconnectez-vous.",
        "status.code_inactive": "Connexion au compte requise",
        "status.api_active": "Gemini local pret ({backend})",
        "status.api_invalid": "Cle Gemini invalide - mettez-la a jour depuis le tableau de bord",
        "status.api_credits": "La cle Gemini n'a plus de credits - mettez-la a jour depuis le tableau de bord",
        "status.api_required": "Cle Gemini manquante - ajoutez-la depuis le tableau de bord",
        "status.stopped": "Arrete",
        "status.not_authenticated": "Non authentifie",
        "indicator.cooldown": "Saisie terminee. Les commandes reviennent dans {seconds}s.",
    },
}

DEFAULT_PRO_MODEL_OPTIONS = [
    {
        "id": "gemini-3-flash-preview",
        "label": "Gemini 3 Flash Preview",
        "description": "Current fastest Gemini 3 preview for lightweight local work.",
    },
    {
        "id": "gemini-3.1-flash-lite-preview",
        "label": "Gemini 3.1 Flash-Lite Preview",
        "description": "Lowest-latency Gemini 3.1 option for lightweight local work.",
    },
    {
        "id": "gemini-3.1-pro-preview",
        "label": "Gemini 3.1 Preview",
        "description": "Highest-quality Gemini 3.1 reasoning preview.",
    },
    {
        "id": "gemini-2.5-flash",
        "label": "Gemini 2.5 Flash",
        "description": "Faster replies with lower latency.",
    },
    {
        "id": "gemini-2.5-flash-preview-09-2025",
        "label": "Gemini 2.5 Flash Preview (09-2025)",
        "description": "Pinned Gemini 2.5 Flash preview build.",
    },
    {
        "id": "gemini-2.5-flash-lite",
        "label": "Gemini 2.5 Flash Lite",
        "description": "Cheaper Gemini 2.5 Flash Lite for lightweight prompts.",
    },
    {
        "id": "gemini-2.5-flash-lite-preview-09-2025",
        "label": "Gemini 2.5 Flash Lite Preview (09-2025)",
        "description": "Pinned Gemini 2.5 Flash Lite preview build.",
    },
    {
        "id": "gemini-2.5-pro",
        "label": "Gemini 2.5 Advanced",
        "description": "Highest reasoning quality when available.",
    },
]


def normalize_indicator_blob_size(value):
    normalized = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    if normalized in INDICATOR_BLOB_SIZES:
        return normalized
    return "medium"


def compute_indicator_chip_corner_radius(chip_size):
    size = int(max(1, chip_size))
    return max(4, min(int(round(size * 0.32)), max(4, (size // 2) - 2)))


def hex_to_rgba(color, alpha):
    candidate = str(color or "").strip().lstrip("#")
    if len(candidate) != 6:
        return color
    try:
        return (
            int(candidate[0:2], 16),
            int(candidate[2:4], 16),
            int(candidate[4:6], 16),
            int(max(0, min(255, alpha))),
        )
    except Exception:
        return color


def detect_system_dark_mode():
    if os.name != "nt":
        return False
    winreg_module = get_winreg_module()
    if winreg_module is None:
        return False
    try:
        with winreg_module.OpenKey(
            winreg_module.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
        ) as key:
            apps_use_light_theme, _ = winreg_module.QueryValueEx(key, "AppsUseLightTheme")
        return int(apps_use_light_theme) == 0
    except Exception:
        return False


def normalize_theme_preference(value):
    normalized = str(value or "").strip().lower()
    if normalized in {"dark", "light", "system"}:
        return normalized
    return "system"


def resolve_theme_dark(preference=None):
    selected = normalize_theme_preference(preference if preference is not None else ui_theme_preference)
    if selected == "dark":
        return True
    if selected == "light":
        return False
    return detect_system_dark_mode()


def apply_ui_theme(use_dark):
    global system_dark_theme_enabled
    system_dark_theme_enabled = bool(use_dark)
    palette = DARK_THEME if system_dark_theme_enabled else LIGHT_THEME
    globals().update(palette)


def apply_ui_theme_preference(preference=None):
    global ui_theme_preference
    ui_theme_preference = normalize_theme_preference(preference)
    apply_ui_theme(resolve_theme_dark(ui_theme_preference))

ui_theme_preference = normalize_theme_preference(os.environ.get("EAE_THEME", ui_theme_preference))


def normalize_language(value):
    normalized = str(value or "").strip().lower()
    if normalized in TRANSLATIONS:
        return normalized
    return "en"


def normalize_indicator_position(value):
    normalized = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    if normalized in INDICATOR_POSITIONS:
        return normalized
    return "bottom_right"


def normalize_startup_loading_screen_enabled(value):
    if isinstance(value, bool):
        return bool(value)
    text = str(value or "").strip().lower()
    if not text:
        return True
    return text not in {"0", "false", "no", "off"}


def load_pro_model_catalog():
    raw_value = str(os.environ.get(PRO_MODELS_ENV, "") or "").strip()
    if not raw_value:
        return [dict(item) for item in DEFAULT_PRO_MODEL_OPTIONS]
    try:
        parsed = json.loads(raw_value)
    except Exception:
        return [dict(item) for item in DEFAULT_PRO_MODEL_OPTIONS]
    if not isinstance(parsed, list):
        return [dict(item) for item in DEFAULT_PRO_MODEL_OPTIONS]
    catalog = []
    for item in parsed:
        if isinstance(item, str):
            candidate_id = str(item).strip()
            if candidate_id:
                catalog.append(
                    {
                        "id": candidate_id,
                        "label": candidate_id,
                        "description": "",
                    }
                )
            continue
        if not isinstance(item, dict):
            continue
        candidate_id = str(item.get("id", "") or "").strip()
        if not candidate_id:
            continue
        catalog.append(
            {
                "id": candidate_id,
                "label": str(item.get("label", "") or candidate_id).strip(),
                "description": str(item.get("description", "") or "").strip(),
            }
        )
    if not catalog:
        return [dict(item) for item in DEFAULT_PRO_MODEL_OPTIONS]
    return catalog


PRO_MODEL_OPTIONS = None


def get_pro_model_options():
    global PRO_MODEL_OPTIONS
    if PRO_MODEL_OPTIONS is None:
        PRO_MODEL_OPTIONS = load_pro_model_catalog()
    return PRO_MODEL_OPTIONS


def normalize_pro_model(value):
    candidate = str(value or "").strip()
    pro_model_options = get_pro_model_options()
    for item in pro_model_options:
        if candidate == item["id"]:
            return candidate
    for item in pro_model_options:
        if item["id"] == DEFAULT_MODEL_NAME:
            return item["id"]
    return str(pro_model_options[0]["id"])


def tr(key, language=None, **kwargs):
    lang = normalize_language(language or ui_language)
    table = TRANSLATIONS.get(lang, TRANSLATIONS["en"])
    text = table.get(key, TRANSLATIONS["en"].get(key, key))
    if kwargs:
        try:
            return str(text).format(**kwargs)
        except Exception:
            return str(text)
    return str(text)


def get_default_command_hotkeys(mode=None):
    local_mode = "toprow" if str(mode or command_key_mode).strip().lower() == "toprow" else "numpad"
    return dict(DEFAULT_COMMAND_HOTKEYS[local_mode])


def hotkey_action_label(action, language=None):
    return tr(f"auth.hotkey.{str(action or '').strip().lower()}", language=language)


def hotkey_binding_label(binding_key):
    meta = ALLOWED_HOTKEY_BINDINGS.get(str(binding_key or "").strip().lower(), {})
    return str(meta.get("label", "?"))


def is_reserved_system_hotkey_binding(binding_key):
    return str(binding_key or "").strip().lower() in RESERVED_SYSTEM_HOTKEY_BINDINGS


def set_indicator_runtime_state(*, active=None, hidden=None):
    global indicator_runtime_active, indicator_runtime_hidden
    with indicator_state_lock:
        if active is not None:
            indicator_runtime_active = bool(active)
        if hidden is not None:
            indicator_runtime_hidden = bool(hidden)


def indicator_runtime_snapshot():
    with indicator_state_lock:
        return bool(indicator_runtime_active), bool(indicator_runtime_hidden)


def indicator_is_hidden():
    active, hidden = indicator_runtime_snapshot()
    if active:
        return hidden
    return bool(indicator_manual_hidden or privacy_forced_hidden)


def canonicalize_hotkey_binding(binding_key, mode=None):
    candidate = str(binding_key or "").strip().lower()
    if not candidate:
        return ""
    if is_reserved_system_hotkey_binding(candidate):
        return ""
    if candidate in ALLOWED_HOTKEY_BINDINGS:
        return candidate

    local_mode = "toprow" if str(mode or command_key_mode).strip().lower() == "toprow" else "numpad"
    compact = candidate.replace("_", "").replace("-", "").replace(" ", "")

    if compact.isdigit() and len(compact) == 1:
        return f"digit{compact}" if local_mode == "toprow" else f"numpad{compact}"

    if compact.startswith("digit") and compact[5:].isdigit() and len(compact[5:]) == 1:
        return f"digit{compact[5:]}"

    if compact.startswith("numpad") and compact[6:].isdigit() and len(compact[6:]) == 1:
        return f"numpad{compact[6:]}"

    return ""


def infer_hotkey_mode_from_bindings(value, fallback=None):
    bindings = value if isinstance(value, dict) else {}
    fallback_mode = "toprow" if str(fallback or command_key_mode).strip().lower() == "toprow" else "numpad"
    if bindings == DEFAULT_COMMAND_HOTKEYS["toprow"]:
        return "toprow"
    if bindings == DEFAULT_COMMAND_HOTKEYS["numpad"]:
        return "numpad"
    keypad_flags = []
    for action in HOTKEY_ACTION_ORDER:
        meta = ALLOWED_HOTKEY_BINDINGS.get(str(bindings.get(action, "")).strip().lower(), {})
        keypad_flags.append(meta.get("keypad"))
    if keypad_flags and all(flag is True for flag in keypad_flags):
        return "numpad"
    if keypad_flags and all(flag is False for flag in keypad_flags):
        return "toprow"
    return fallback_mode


def normalize_command_hotkeys(value, mode=None):
    defaults = get_default_command_hotkeys(mode)
    source = value if isinstance(value, dict) else {}
    normalized = {}
    used = set()
    customized = False
    remaining = [
        key
        for key in ALLOWED_HOTKEY_BINDINGS
        if key not in defaults.values() and not is_reserved_system_hotkey_binding(key)
    ]
    for action in HOTKEY_ACTION_ORDER:
        candidate = canonicalize_hotkey_binding(source.get(action, ""), mode)
        if (
            candidate in ALLOWED_HOTKEY_BINDINGS
            and candidate not in used
            and not is_reserved_system_hotkey_binding(candidate)
        ):
            normalized[action] = candidate
            used.add(candidate)
            if candidate != defaults[action]:
                customized = True
            continue
        fallback = defaults[action]
        if fallback in used:
            fallback = next((key for key in remaining if key not in used), fallback)
        normalized[action] = fallback
        used.add(fallback)
        if fallback != defaults[action]:
            customized = True
    return normalized, customized


def resolve_command_hotkey_state(value, mode=None):
    fallback_mode = "toprow" if str(mode or command_key_mode).strip().lower() == "toprow" else "numpad"
    normalized, customized = normalize_command_hotkeys(value, fallback_mode)
    resolved_mode = infer_hotkey_mode_from_bindings(normalized, fallback_mode)
    if normalized == DEFAULT_COMMAND_HOTKEYS.get(resolved_mode, {}):
        customized = False
    return normalized, resolved_mode, customized


def hotkey_event_matches_binding(event, binding_key):
    meta = ALLOWED_HOTKEY_BINDINGS.get(str(binding_key or "").strip().lower())
    if not meta:
        return False
    if get_event_scan_code(event) != int(meta["scan_code"]):
        return False
    expected_keypad = meta.get("keypad")
    actual_keypad = getattr(event, "is_keypad", None)
    if expected_keypad is not None and actual_keypad is not None and bool(actual_keypad) != bool(expected_keypad):
        return False
    return True


def get_hotkey_action(event):
    for action in HOTKEY_ACTION_ORDER:
        binding_key = command_hotkeys.get(action, "")
        if binding_key and hotkey_event_matches_binding(event, binding_key):
            return action
    return ""


def soft_validate_api_key(value):
    cleaned = str(value or "").strip()
    if not cleaned:
        return "auth.validation.api.empty"
    if any(ch.isspace() for ch in cleaned):
        return "auth.validation.api.whitespace"
    if len(cleaned) < 12:
        return "auth.validation.api.short"
    if len(set(cleaned)) < 4:
        return "auth.validation.api.shape"
    if not re.search(r"[A-Za-z]", cleaned) or not re.search(r"[A-Za-z0-9]", cleaned):
        return "auth.validation.api.shape"
    return ""


def compute_indicator_origin(work_left, work_top, work_right, work_bottom, width, height, position_key):
    layout = INDICATOR_POSITIONS.get(normalize_indicator_position(position_key), INDICATOR_POSITIONS["bottom_right"])
    usable_width = max(1, work_right - work_left)
    usable_height = max(1, work_bottom - work_top)
    if layout["x"] == "left":
        x = work_left + INDICATOR_MARGIN_X
    elif layout["x"] == "center":
        x = work_left + (usable_width - width) // 2
    else:
        x = work_right - width - INDICATOR_MARGIN_X
    if layout["y"] == "top":
        y = work_top + INDICATOR_MARGIN_Y
    elif layout["y"] == "center":
        y = work_top + (usable_height - height) // 2
    else:
        y = work_bottom - height - INDICATOR_MARGIN_Y
    x = min(max(work_left, int(x)), max(work_left, work_right - width))
    y = min(max(work_top, int(y)), max(work_top, work_bottom - height))
    return x, y


def compute_preview_anchor_point(left, top, right, bottom, position_key):
    point = INDICATOR_PREVIEW_POINTS.get(
        normalize_indicator_position(position_key),
        INDICATOR_PREVIEW_POINTS["bottom_right"],
    )
    usable_width = max(1, int(right) - int(left))
    usable_height = max(1, int(bottom) - int(top))
    x = int(round(int(left) + (usable_width * float(point["x"]))))
    y = int(round(int(top) + (usable_height * float(point["y"]))))
    return x, y


def is_loopback_hostname(hostname):
    candidate = str(hostname or "").strip().strip("[]").lower()
    if not candidate:
        return False
    if candidate == "localhost":
        return True
    try:
        return bool(ipaddress.ip_address(candidate).is_loopback)
    except Exception:
        return False


def normalize_server_url(value):
    candidate = str(value or "").strip().rstrip("/")
    if not candidate:
        return DEFAULT_SERVER_URL
    try:
        parsed = urlparse(candidate)
    except Exception:
        return ""
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    if parsed.username or parsed.password:
        return ""
    hostname = str(parsed.hostname or "").strip()
    if parsed.scheme != "https" and not is_loopback_hostname(hostname):
        return ""
    normalized = f"{parsed.scheme}://{parsed.netloc}"
    path = str(parsed.path or "").strip()
    if path and path != "/":
        normalized = f"{normalized}{path.rstrip('/')}"
    return normalized


def describe_unexpected_json_response(response):
    content_type = str(getattr(response, "headers", {}).get("content-type", "") or "").strip().lower()
    try:
        snippet = str(getattr(response, "text", "") or "").strip()
    except Exception:
        snippet = ""
    snippet = " ".join(snippet.split())[:320]
    plain_text = " ".join(re.sub(r"<[^>]+>", " ", html.unescape(snippet)).split())
    if not plain_text:
        return f"content-type={content_type or 'unknown'}"
    missing_relation_match = re.search(r'relation\s+"([^"]+)"\s+does not exist', plain_text, flags=re.IGNORECASE)
    if missing_relation_match:
        return f"Server database is missing table '{missing_relation_match.group(1)}'."
    fatal_match = re.search(r"Fatal error:\s*(.+)", plain_text, flags=re.IGNORECASE)
    if fatal_match:
        return f"Server PHP fatal error: {fatal_match.group(1).strip()[:220]}"
    if "html" in content_type:
        return f"Server returned HTML: {plain_text[:220]}"
    return plain_text[:220]


def decode_json_response(response, context_label):
    try:
        return response.json()
    except Exception:
        content_type = str(response.headers.get("content-type", "") or "").strip().lower()
        try:
            snippet = str(response.text or "").strip()
        except Exception:
            snippet = ""
        snippet = " ".join(snippet.split())[:220]
        logger.warning(
            "%s returned non-JSON data (status %s, content-type=%s, body=%r).",
            context_label,
            getattr(response, "status_code", "?"),
            content_type or "unknown",
            snippet,
            exc_info=True,
        )
        return None


def open_default_website():
    target = str(DEFAULT_WEBSITE_URL or "").strip()
    if not target:
        return False
    try:
        parsed = urlparse(target)
    except Exception:
        return False
    if parsed.scheme not in {"http", "https"}:
        return False
    try:
        return bool(webbrowser.open(target, new=2))
    except Exception:
        return False


def open_dashboard_page(anchor="dashboard-app-access"):
    target = str(DEFAULT_WEBSITE_URL or DEFAULT_SERVER_URL).strip().rstrip("/")
    if not target:
        return False
    if not target.lower().endswith(".php") and not target.endswith("/dashboard.php"):
        target = f"{target}/dashboard.php"
    if anchor:
        target = f"{target}#{str(anchor).strip().lstrip('#')}"
    try:
        parsed = urlparse(target)
    except Exception:
        return False
    if parsed.scheme not in {"http", "https"}:
        return False
    try:
        return bool(webbrowser.open(target, new=2))
    except Exception:
        return False


def resolve_install_root():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def resolve_data_dir(install_root):
    portable_data_dir = install_root / ".eyesandears"
    try:
        if portable_data_dir.exists():
            if portable_data_dir.is_dir():
                return portable_data_dir
        elif os.access(str(install_root), os.W_OK):
            return portable_data_dir
    except Exception:
        pass
    return Path(os.environ.get("APPDATA", ".")) / APP_NAME


APP_INSTALL_ROOT = resolve_install_root()
APP_DATA_DIR = None
CONFIG_FILE = None
PRO_AUTH_RUNTIME_DIR = None
PRO_AUTH_LOCK_FILE = None


def get_app_data_dir():
    global APP_DATA_DIR
    if APP_DATA_DIR is None:
        APP_DATA_DIR = resolve_data_dir(APP_INSTALL_ROOT)
    return APP_DATA_DIR


def get_config_file():
    global CONFIG_FILE
    if CONFIG_FILE is None:
        CONFIG_FILE = get_app_data_dir() / CONFIG_FILE_NAME
    return CONFIG_FILE


def get_pro_auth_runtime_dir():
    global PRO_AUTH_RUNTIME_DIR
    if PRO_AUTH_RUNTIME_DIR is None:
        PRO_AUTH_RUNTIME_DIR = get_app_data_dir() / PRO_AUTH_HIDDEN_DIR_NAME
    return PRO_AUTH_RUNTIME_DIR


def get_pro_auth_lock_file():
    global PRO_AUTH_LOCK_FILE
    if PRO_AUTH_LOCK_FILE is None:
        PRO_AUTH_LOCK_FILE = get_pro_auth_runtime_dir() / PRO_AUTH_HIDDEN_FILE_NAME
    return PRO_AUTH_LOCK_FILE

PROFILE_RUNTIME_ENABLED = (
    PROCESS_ROLE == "main"
    and str(os.environ.get("EAE_PROFILE_RUNTIME", "") or "").strip().lower() in {"1", "true", "yes", "on"}
)
PROFILE_SESSION_DIR = str(os.environ.get("EAE_PROFILE_DIR", "") or "").strip()


class RuntimeProfiler:
    def __init__(self, session_dir, repo_root):
        self.enabled = bool(session_dir)
        self.repo_root = Path(repo_root).resolve()
        self.pid = os.getpid()
        self.ppid = os.getppid()
        self.process_kind = self._resolve_process_kind()
        self.trace_calls = self.process_kind == "main"
        self.session_dir = Path(session_dir).resolve() if session_dir else None
        self.events_path = None
        self.summary_path = None
        self._event_stream = None
        self._summary = {}
        self._stacks = {}
        self._lock = Lock()
        self._guard = threading.local()
        self._suspend_local = threading.local()
        self._origin_perf = time.perf_counter()
        self._started_at = datetime.now(timezone.utc)
        self._closed = False
        if not self.enabled:
            return
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.events_path = self.session_dir / f"events-{self.pid}.jsonl"
        self.summary_path = self.session_dir / f"summary-{self.pid}.json"
        self._event_stream = self.events_path.open("a", encoding="utf-8", buffering=1)
        self._write_session_file()
        atexit.register(self.close)
        self.mark(
            "process.start",
            process_kind=self.process_kind,
            argv=list(sys.argv),
            ppid=self.ppid,
        )
        if self.trace_calls:
            sys.setprofile(self._profile_callback)
            threading.setprofile(self._profile_callback)

    def _resolve_process_kind(self):
        return PROCESS_ROLE

    def _write_session_file(self):
        session_path = self.session_dir / "session.json"
        payload = {
            "started_at": self._started_at.isoformat(),
            "pid": self.pid,
            "ppid": self.ppid,
            "process_kind": self.process_kind,
            "trace_calls": bool(self.trace_calls),
            "argv": list(sys.argv),
            "python_version": sys.version,
            "cwd": os.getcwd(),
            "repo_root": str(self.repo_root),
        }
        try:
            with session_path.open("x", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=True, indent=2)
        except FileExistsError:
            return
        except Exception:
            logger.debug("Runtime profiler could not write session.json.", exc_info=True)

    def _relative_path(self, filename):
        try:
            resolved = Path(filename).resolve()
            relative = resolved.relative_to(self.repo_root)
            return str(relative).replace("\\", "/")
        except Exception:
            return ""

    def _now_ms(self):
        return round((time.perf_counter() - self._origin_perf) * 1000.0, 3)

    def _enter_guard(self):
        if getattr(self._guard, "active", False):
            return False
        self._guard.active = True
        return True

    def _leave_guard(self):
        self._guard.active = False

    def _write_event(self, payload):
        if not self.enabled or self._event_stream is None:
            return
        event = {
            "ts_ms": self._now_ms(),
            "pid": self.pid,
            "thread_id": threading.get_ident(),
            "thread_name": threading.current_thread().name,
        }
        event.update(payload)
        try:
            self._event_stream.write(json.dumps(event, ensure_ascii=True) + "\n")
        except Exception:
            logger.debug("Runtime profiler event write failed.", exc_info=True)

    def _update_summary(self, key, rel_path, func_name, line, duration_ms, self_ms):
        bucket = self._summary.get(key)
        if bucket is None:
            bucket = {
                "path": rel_path,
                "function": func_name,
                "line": int(line),
                "count": 0,
                "total_ms": 0.0,
                "self_ms": 0.0,
                "max_ms": 0.0,
            }
            self._summary[key] = bucket
        bucket["count"] += 1
        bucket["total_ms"] = round(bucket["total_ms"] + duration_ms, 3)
        bucket["self_ms"] = round(bucket["self_ms"] + self_ms, 3)
        bucket["max_ms"] = round(max(bucket["max_ms"], duration_ms), 3)

    def _should_trace_frame(self, frame):
        filename = str(getattr(getattr(frame, "f_code", None), "co_filename", "") or "")
        if not filename or not filename.endswith(".py"):
            return False
        return bool(self._relative_path(filename))

    def _calls_suspended(self):
        return int(getattr(self._suspend_local, "count", 0) or 0) > 0

    def _profile_callback(self, frame, event, arg):
        if not self.enabled or not self.trace_calls or self._calls_suspended() or event not in {"call", "return", "exception"}:
            return
        if not self._should_trace_frame(frame):
            return
        if not self._enter_guard():
            return
        try:
            code = frame.f_code
            filename = str(code.co_filename or "")
            rel_path = self._relative_path(filename)
            if not rel_path:
                return
            func_name = str(code.co_name or "<unknown>")
            line = int(code.co_firstlineno or frame.f_lineno or 0)
            thread_id = threading.get_ident()
            stack = self._stacks.setdefault(thread_id, [])
            if event == "call":
                depth = len(stack)
                stack.append(
                    {
                        "frame_id": id(frame),
                        "started_at": time.perf_counter(),
                        "child_time": 0.0,
                        "depth": depth,
                        "key": f"{rel_path}:{line}:{func_name}",
                        "path": rel_path,
                        "function": func_name,
                        "line": line,
                    }
                )
                self._write_event(
                    {
                        "type": "call",
                        "path": rel_path,
                        "function": func_name,
                        "line": line,
                        "depth": depth,
                    }
                )
                return

            record = None
            if stack and stack[-1]["frame_id"] == id(frame):
                record = stack.pop()
            else:
                for index in range(len(stack) - 1, -1, -1):
                    if stack[index]["frame_id"] == id(frame):
                        record = stack.pop(index)
                        break
            if record is None:
                return
            duration_ms = round((time.perf_counter() - record["started_at"]) * 1000.0, 3)
            self_ms = round(max(0.0, duration_ms - record["child_time"]), 3)
            if stack:
                stack[-1]["child_time"] += duration_ms
            self._update_summary(record["key"], record["path"], record["function"], record["line"], duration_ms, self_ms)
            self._write_event(
                {
                    "type": "exception" if event == "exception" else "return",
                    "path": record["path"],
                    "function": record["function"],
                    "line": record["line"],
                    "depth": record["depth"],
                    "duration_ms": duration_ms,
                    "self_ms": self_ms,
                }
            )
        finally:
            self._leave_guard()

    def mark(self, name, **meta):
        if not self.enabled:
            return
        if not self._enter_guard():
            return
        try:
            self._write_event({"type": "marker", "name": str(name or ""), "meta": dict(meta or {})})
        finally:
            self._leave_guard()

    @contextmanager
    def span(self, name, **meta):
        if not self.enabled:
            yield
            return
        started_at = time.perf_counter()
        error_text = ""
        try:
            yield
        except Exception as exc:
            error_text = str(exc)
            raise
        finally:
            if self._enter_guard():
                try:
                    duration_ms = round((time.perf_counter() - started_at) * 1000.0, 3)
                    payload = {
                        "type": "span",
                        "name": str(name or ""),
                        "duration_ms": duration_ms,
                        "meta": dict(meta or {}),
                    }
                    if error_text:
                        payload["error"] = error_text[:240]
                    self._write_event(payload)
                    self._update_summary(
                        f"__span__:{name}",
                        "__span__",
                        str(name or ""),
                        0,
                        duration_ms,
                        duration_ms,
                    )
                finally:
                    self._leave_guard()

    @contextmanager
    def suspend_calls(self):
        if not self.enabled or not self.trace_calls:
            yield
            return
        current = int(getattr(self._suspend_local, "count", 0) or 0)
        self._suspend_local.count = current + 1
        try:
            yield
        finally:
            remaining = int(getattr(self._suspend_local, "count", 1) or 1) - 1
            self._suspend_local.count = max(0, remaining)

    def close(self):
        if not self.enabled or self._closed:
            return
        self._closed = True
        try:
            self.mark("process.stop", process_kind=self.process_kind)
        except Exception:
            pass
        try:
            sys.setprofile(None)
        except Exception:
            pass
        try:
            threading.setprofile(None)
        except Exception:
            pass
        try:
            ordered = sorted(self._summary.values(), key=lambda item: (-float(item["total_ms"]), item["path"], item["function"]))
            with self.summary_path.open("w", encoding="utf-8") as handle:
                json.dump(ordered, handle, ensure_ascii=True, indent=2)
        except Exception:
            logger.debug("Runtime profiler summary write failed.", exc_info=True)
        try:
            if self._event_stream is not None:
                self._event_stream.close()
        except Exception:
            pass


RUNTIME_PROFILER = RuntimeProfiler(PROFILE_SESSION_DIR, APP_INSTALL_ROOT) if PROFILE_RUNTIME_ENABLED else None


def profile_mark(name, **meta):
    if RUNTIME_PROFILER is not None:
        RUNTIME_PROFILER.mark(name, **meta)


@contextmanager
def profile_span(name, **meta):
    if RUNTIME_PROFILER is None:
        yield
        return
    with RUNTIME_PROFILER.span(name, **meta):
        yield


@contextmanager
def profile_suspend_calls():
    if RUNTIME_PROFILER is None:
        yield
        return
    with RUNTIME_PROFILER.suspend_calls():
        yield

if os.name == "nt":
    HRESULT = getattr(wintypes, "HRESULT", ctypes.c_long)
    LRESULT = getattr(wintypes, "LRESULT", ctypes.c_ssize_t)
    LONG_PTR = getattr(wintypes, "LONG_PTR", ctypes.c_ssize_t)
    DWORD_PTR = ctypes.c_size_t
    HINSTANCE = getattr(wintypes, "HINSTANCE", wintypes.HANDLE)
    HICON = getattr(wintypes, "HICON", wintypes.HANDLE)
    HCURSOR = getattr(wintypes, "HCURSOR", wintypes.HANDLE)
    HBRUSH = getattr(wintypes, "HBRUSH", wintypes.HANDLE)
    HMENU = getattr(wintypes, "HMENU", wintypes.HANDLE)
    HDC = getattr(wintypes, "HDC", wintypes.HANDLE)
    HGDIOBJ = getattr(wintypes, "HGDIOBJ", wintypes.HANDLE)
    HBITMAP = getattr(wintypes, "HBITMAP", wintypes.HANDLE)
    UINT_PTR = getattr(wintypes, "UINT_PTR", wintypes.WPARAM)
    COLORREF = getattr(wintypes, "COLORREF", wintypes.DWORD)
    WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)
    WDA_NONE = 0x0
    WDA_MONITOR = 0x1
    WDA_EXCLUDEFROMCAPTURE = 0x11
    GA_ROOT = 2
    DWMWA_USE_IMMERSIVE_DARK_MODE = 20
    DWMWA_WINDOW_CORNER_PREFERENCE = 33
    DWMWA_SYSTEMBACKDROP_TYPE = 38
    DWMWA_MICA_EFFECT = 1029
    DWMWCP_ROUND = 2
    DWMSBT_MAINWINDOW = 2
    DWMSBT_TRANSIENTWINDOW = 3
    CS_HREDRAW = 0x0002
    CS_VREDRAW = 0x0001
    CS_DBLCLKS = 0x0008
    DIB_RGB_COLORS = 0
    BI_RGB = 0
    ULW_ALPHA = 0x00000002
    AC_SRC_OVER = 0x00
    AC_SRC_ALPHA = 0x01
    GWL_EXSTYLE = -20
    WS_EX_LAYERED = 0x00080000
    WS_EX_TOPMOST = 0x00000008
    WS_EX_TOOLWINDOW = 0x00000080
    WS_EX_NOACTIVATE = 0x08000000
    WS_POPUP = 0x80000000
    CW_USEDEFAULT = 0x80000000
    WM_DESTROY = 0x0002
    WM_GETTEXT = 0x000D
    WM_TIMER = 0x0113
    WM_MOUSEMOVE = 0x0200
    WM_MOUSELEAVE = 0x02A3
    WM_LBUTTONDOWN = 0x0201
    WM_LBUTTONDBLCLK = 0x0203
    WM_MOUSEACTIVATE = 0x0021
    WM_MOUSEWHEEL = 0x020A
    WM_DISPLAYCHANGE = 0x007E
    WM_SETTINGCHANGE = 0x001A
    WM_DPICHANGED = 0x02E0
    WM_APP = 0x8000
    WM_CLOSE = 0x0010
    SW_HIDE = 0
    SW_SHOWNOACTIVATE = 4
    MA_NOACTIVATE = 3
    HTCLIENT = 1
    IDC_ARROW = 32512
    TME_LEAVE = 0x00000002
    SRCCOPY = 0x00CC0020
    SMTO_ABORTIFHUNG = 0x0002
    MB_OK = 0x00000000
    MB_ICONERROR = 0x00000010
    MB_ICONINFORMATION = 0x00000040
    MB_TASKMODAL = 0x00002000
    MB_TOPMOST = 0x00040000
    MB_SETFOREGROUND = 0x00010000
    MB_RETRYCANCEL = 0x00000005
    IDOK = 1
    IDCANCEL = 2
    IDRETRY = 4
    TDCBF_OK_BUTTON = 0x0001
    TDCBF_YES_BUTTON = 0x0002
    TDCBF_NO_BUTTON = 0x0004
    TDCBF_CANCEL_BUTTON = 0x0008
    TDCBF_RETRY_BUTTON = 0x0010
    TDF_ALLOW_DIALOG_CANCELLATION = 0x0008
    TD_ERROR_ICON = ctypes.c_wchar_p(-1)
    TD_INFORMATION_ICON = ctypes.c_wchar_p(-3)
    HWND_TOPMOST = wintypes.HWND(-1)
    SWP_NOMOVE = 0x0002
    SWP_NOSIZE = 0x0001
    SWP_NOACTIVATE = 0x0010
    SWP_SHOWWINDOW = 0x0040
    SWP_NOOWNERZORDER = 0x0200
    SWP_NOSENDCHANGING = 0x0400
    SWP_NOZORDER = 0x0004
    THREAD_PRIORITY_BELOW_NORMAL = -1

    class WNDCLASSEXW(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.UINT),
            ("style", wintypes.UINT),
            ("lpfnWndProc", WNDPROC),
            ("cbClsExtra", ctypes.c_int),
            ("cbWndExtra", ctypes.c_int),
            ("hInstance", HINSTANCE),
            ("hIcon", HICON),
            ("hCursor", HCURSOR),
            ("hbrBackground", HBRUSH),
            ("lpszMenuName", wintypes.LPCWSTR),
            ("lpszClassName", wintypes.LPCWSTR),
            ("hIconSm", HICON),
        ]

    class MSG(ctypes.Structure):
        _fields_ = [
            ("hwnd", wintypes.HWND),
            ("message", wintypes.UINT),
            ("wParam", wintypes.WPARAM),
            ("lParam", wintypes.LPARAM),
            ("time", wintypes.DWORD),
            ("pt", wintypes.POINT),
            ("lPrivate", wintypes.DWORD),
        ]

    class SIZE(ctypes.Structure):
        _fields_ = [("cx", ctypes.c_long), ("cy", ctypes.c_long)]

    class BLENDFUNCTION(ctypes.Structure):
        _fields_ = [
            ("BlendOp", ctypes.c_byte),
            ("BlendFlags", ctypes.c_byte),
            ("SourceConstantAlpha", ctypes.c_byte),
            ("AlphaFormat", ctypes.c_byte),
        ]

    class TRACKMOUSEEVENT(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("hwndTrack", wintypes.HWND),
            ("dwHoverTime", wintypes.DWORD),
        ]

    class BITMAPINFOHEADER(ctypes.Structure):
        _fields_ = [
            ("biSize", wintypes.DWORD),
            ("biWidth", ctypes.c_long),
            ("biHeight", ctypes.c_long),
            ("biPlanes", wintypes.WORD),
            ("biBitCount", wintypes.WORD),
            ("biCompression", wintypes.DWORD),
            ("biSizeImage", wintypes.DWORD),
            ("biXPelsPerMeter", ctypes.c_long),
            ("biYPelsPerMeter", ctypes.c_long),
            ("biClrUsed", wintypes.DWORD),
            ("biClrImportant", wintypes.DWORD),
        ]

    class BITMAPINFO(ctypes.Structure):
        _fields_ = [
            ("bmiHeader", BITMAPINFOHEADER),
            ("bmiColors", wintypes.DWORD * 3),
        ]

    class TASKDIALOG_BUTTON(ctypes.Structure):
        _fields_ = [
            ("nButtonID", ctypes.c_int),
            ("pszButtonText", wintypes.LPCWSTR),
        ]

    PFTASKDIALOGCALLBACK = ctypes.WINFUNCTYPE(
        HRESULT,
        wintypes.HWND,
        wintypes.UINT,
        wintypes.WPARAM,
        wintypes.LPARAM,
        LONG_PTR,
    )

    class TASKDIALOGCONFIG(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.UINT),
            ("hwndParent", wintypes.HWND),
            ("hInstance", wintypes.HINSTANCE),
            ("dwFlags", wintypes.UINT),
            ("dwCommonButtons", wintypes.UINT),
            ("pszWindowTitle", wintypes.LPCWSTR),
            ("union1", wintypes.LPCWSTR),
            ("pszMainInstruction", wintypes.LPCWSTR),
            ("pszContent", wintypes.LPCWSTR),
            ("cButtons", wintypes.UINT),
            ("pButtons", ctypes.POINTER(TASKDIALOG_BUTTON)),
            ("nDefaultButton", ctypes.c_int),
            ("cRadioButtons", wintypes.UINT),
            ("pRadioButtons", ctypes.c_void_p),
            ("nDefaultRadioButton", ctypes.c_int),
            ("pszVerificationText", wintypes.LPCWSTR),
            ("pszExpandedInformation", wintypes.LPCWSTR),
            ("pszExpandedControlText", wintypes.LPCWSTR),
            ("pszCollapsedControlText", wintypes.LPCWSTR),
            ("union2", wintypes.LPCWSTR),
            ("pfCallback", PFTASKDIALOGCALLBACK),
            ("lpCallbackData", LONG_PTR),
            ("cxWidth", wintypes.UINT),
        ]

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
    _comctl32 = ctypes.WinDLL("comctl32", use_last_error=True)
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
    _kernel32.GetCurrentThread.argtypes = []
    _kernel32.GetCurrentThread.restype = wintypes.HANDLE
    _kernel32.SetThreadPriority.argtypes = [wintypes.HANDLE, ctypes.c_int]
    _kernel32.SetThreadPriority.restype = wintypes.BOOL
    _user32.SetWindowDisplayAffinity.argtypes = [wintypes.HWND, wintypes.DWORD]
    _user32.SetWindowDisplayAffinity.restype = wintypes.BOOL
    _user32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
    _user32.GetAncestor.restype = wintypes.HWND
    _user32.GetForegroundWindow.argtypes = []
    _user32.GetForegroundWindow.restype = wintypes.HWND
    _user32.GetAsyncKeyState.argtypes = [ctypes.c_int]
    _user32.GetAsyncKeyState.restype = ctypes.c_short
    _user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    _user32.GetWindowTextW.restype = ctypes.c_int
    _user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    _user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    _user32.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
    _user32.GetCursorPos.restype = wintypes.BOOL
    _user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
    _user32.FindWindowW.restype = wintypes.HWND
    _user32.EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
    _user32.EnumWindows.restype = wintypes.BOOL
    _user32.IsWindow.argtypes = [wintypes.HWND]
    _user32.IsWindow.restype = wintypes.BOOL
    _user32.IsWindowVisible.argtypes = [wintypes.HWND]
    _user32.IsWindowVisible.restype = wintypes.BOOL
    _user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    _user32.ShowWindow.restype = wintypes.BOOL
    _user32.SetForegroundWindow.argtypes = [wintypes.HWND]
    _user32.SetForegroundWindow.restype = wintypes.BOOL
    _user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    _user32.GetWindowRect.restype = wintypes.BOOL
    _user32.MoveWindow.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.BOOL]
    _user32.MoveWindow.restype = wintypes.BOOL
    _user32.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.UINT]
    _user32.SetWindowPos.restype = wintypes.BOOL
    _user32.ReleaseCapture.argtypes = []
    _user32.ReleaseCapture.restype = wintypes.BOOL
    _user32.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    _user32.SendMessageW.restype = wintypes.LPARAM
    _user32.SendMessageTimeoutW.argtypes = [
        wintypes.HWND,
        wintypes.UINT,
        wintypes.WPARAM,
        ctypes.c_void_p,
        wintypes.UINT,
        wintypes.UINT,
        ctypes.POINTER(DWORD_PTR),
    ]
    _user32.SendMessageTimeoutW.restype = DWORD_PTR
    _user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    _user32.PostMessageW.restype = wintypes.BOOL
    _user32.RegisterClassExW.argtypes = [ctypes.POINTER(WNDCLASSEXW)]
    _user32.RegisterClassExW.restype = wintypes.ATOM
    _user32.CreateWindowExW.argtypes = [
        wintypes.DWORD,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.HWND,
        HMENU,
        HINSTANCE,
        wintypes.LPVOID,
    ]
    _user32.CreateWindowExW.restype = wintypes.HWND
    _user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    _user32.DefWindowProcW.restype = LRESULT
    _user32.DestroyWindow.argtypes = [wintypes.HWND]
    _user32.DestroyWindow.restype = wintypes.BOOL
    _user32.GetMessageW.argtypes = [ctypes.POINTER(MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
    _user32.GetMessageW.restype = wintypes.BOOL
    _user32.TranslateMessage.argtypes = [ctypes.POINTER(MSG)]
    _user32.TranslateMessage.restype = wintypes.BOOL
    _user32.DispatchMessageW.argtypes = [ctypes.POINTER(MSG)]
    _user32.DispatchMessageW.restype = LRESULT
    _user32.PostQuitMessage.argtypes = [ctypes.c_int]
    _user32.PostQuitMessage.restype = None
    _user32.UpdateLayeredWindow.argtypes = [
        wintypes.HWND,
        HDC,
        ctypes.POINTER(wintypes.POINT),
        ctypes.POINTER(SIZE),
        HDC,
        ctypes.POINTER(wintypes.POINT),
        COLORREF,
        ctypes.POINTER(BLENDFUNCTION),
        wintypes.DWORD,
    ]
    _user32.UpdateLayeredWindow.restype = wintypes.BOOL
    _user32.GetDC.argtypes = [wintypes.HWND]
    _user32.GetDC.restype = HDC
    _user32.LoadCursorW.argtypes = [HINSTANCE, wintypes.LPCWSTR]
    _user32.LoadCursorW.restype = HCURSOR
    _user32.TrackMouseEvent.argtypes = [ctypes.POINTER(TRACKMOUSEEVENT)]
    _user32.TrackMouseEvent.restype = wintypes.BOOL
    _user32.SetTimer.argtypes = [wintypes.HWND, UINT_PTR, wintypes.UINT, ctypes.c_void_p]
    _user32.SetTimer.restype = UINT_PTR
    _user32.KillTimer.argtypes = [wintypes.HWND, UINT_PTR]
    _user32.KillTimer.restype = wintypes.BOOL
    _user32.GetDoubleClickTime.argtypes = []
    _user32.GetDoubleClickTime.restype = wintypes.UINT
    _user32.MessageBoxW.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.UINT]
    _user32.MessageBoxW.restype = ctypes.c_int
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
    _gdi32.CreateEllipticRgn.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
    ]
    _gdi32.CreateEllipticRgn.restype = wintypes.HANDLE
    _gdi32.CreateCompatibleDC.argtypes = [HDC]
    _gdi32.CreateCompatibleDC.restype = HDC
    _gdi32.DeleteDC.argtypes = [HDC]
    _gdi32.DeleteDC.restype = wintypes.BOOL
    _gdi32.SelectObject.argtypes = [HDC, HGDIOBJ]
    _gdi32.SelectObject.restype = HGDIOBJ
    _gdi32.CreateDIBSection.argtypes = [
        HDC,
        ctypes.POINTER(BITMAPINFO),
        wintypes.UINT,
        ctypes.POINTER(ctypes.c_void_p),
        wintypes.HANDLE,
        wintypes.DWORD,
    ]
    _gdi32.CreateDIBSection.restype = HBITMAP
    _gdi32.DeleteObject.argtypes = [wintypes.HANDLE]
    _gdi32.DeleteObject.restype = wintypes.BOOL
    _comctl32.TaskDialogIndirect.argtypes = [
        ctypes.POINTER(TASKDIALOGCONFIG),
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(wintypes.BOOL),
    ]
    _comctl32.TaskDialogIndirect.restype = HRESULT


def hide_console_window():
    if os.name != "nt":
        return
    try:
        console_window = ctypes.windll.kernel32.GetConsoleWindow()
        if console_window:
            ctypes.windll.user32.ShowWindow(console_window, SW_HIDE)
    except Exception:
        pass


def set_current_thread_low_priority():
    if os.name != "nt":
        return False
    try:
        return bool(
            _kernel32.SetThreadPriority(
                _kernel32.GetCurrentThread(),
                THREAD_PRIORITY_BELOW_NORMAL,
            )
        )
    except Exception:
        return False


def ensure_ui_crisp_mode():
    global ui_crisp_mode_initialized
    if ui_crisp_mode_initialized:
        return
    ui_crisp_mode_initialized = True
    if os.name != "nt":
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        pass
    try:
        dpi_context_v2 = ctypes.c_void_p(-4)  # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
        ctypes.windll.user32.SetProcessDpiAwarenessContext(dpi_context_v2)
    except Exception:
        pass
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


_image_font_cache = {}
_image_measure_cache = OrderedDict()
_image_measure_cache_lock = Lock()


def ordered_cache_get(cache, key, lock=None):
    if lock is None:
        value = cache.get(key)
        if value is not None and hasattr(cache, "move_to_end"):
            try:
                cache.move_to_end(key)
            except Exception:
                pass
        return value
    with lock:
        value = cache.get(key)
        if value is not None and hasattr(cache, "move_to_end"):
            try:
                cache.move_to_end(key)
            except Exception:
                pass
        return value


def ordered_cache_set(cache, key, value, max_items, lock=None):
    if lock is None:
        cache[key] = value
        if hasattr(cache, "move_to_end"):
            try:
                cache.move_to_end(key)
            except Exception:
                pass
        while len(cache) > int(max_items):
            try:
                if hasattr(cache, "popitem"):
                    cache.popitem(last=False)
                else:
                    cache.pop(next(iter(cache)))
            except Exception:
                break
        return value
    with lock:
        cache[key] = value
        if hasattr(cache, "move_to_end"):
            try:
                cache.move_to_end(key)
            except Exception:
                pass
        while len(cache) > int(max_items):
            try:
                if hasattr(cache, "popitem"):
                    cache.popitem(last=False)
                else:
                    cache.pop(next(iter(cache)))
            except Exception:
                break
    return value


def _safe_text(value):
    return str(value or "")


def resolve_dialog_owner_hwnd(parent=None):
    if os.name != "nt" or parent is None:
        return None
    candidates = [
        getattr(parent, "hwnd", None),
        getattr(parent, "_hwnd", None),
        getattr(parent, "handle", None),
    ]
    for candidate in candidates:
        try:
            normalized = int(candidate or 0)
        except Exception:
            normalized = 0
        if normalized:
            return wintypes.HWND(normalized)
    try:
        normalized = int(parent or 0)
    except Exception:
        normalized = 0
    return wintypes.HWND(normalized) if normalized else None


def _show_task_dialog(title, heading, message, is_error=False, ask_retry=False, parent=None):
    if os.name != "nt":
        return None
    try:
        owner = resolve_dialog_owner_hwnd(parent)
        config = TASKDIALOGCONFIG()
        config.cbSize = ctypes.sizeof(TASKDIALOGCONFIG)
        config.hwndParent = owner
        config.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION
        config.dwCommonButtons = 0
        config.pszWindowTitle = _safe_text(title) or APP_NAME
        config.pszMainInstruction = _safe_text(heading)
        config.pszContent = _safe_text(message)
        config.union1 = TD_ERROR_ICON if is_error else TD_INFORMATION_ICON
        button_storage = None
        if ask_retry:
            button_storage = (TASKDIALOG_BUTTON * 2)()
            button_storage[0] = TASKDIALOG_BUTTON(IDRETRY, tr("dialog.retry_login"))
            button_storage[1] = TASKDIALOG_BUTTON(IDCANCEL, tr("dialog.quit"))
            config.cButtons = 2
            config.pButtons = button_storage
            config.nDefaultButton = IDRETRY
        else:
            config.dwCommonButtons = TDCBF_OK_BUTTON
            config.nDefaultButton = IDOK
        selected = ctypes.c_int(0)
        verified = wintypes.BOOL(False)
        result = _comctl32.TaskDialogIndirect(
            ctypes.byref(config),
            ctypes.byref(selected),
            None,
            ctypes.byref(verified),
        )
        if int(result) < 0:
            return None
        return bool(int(selected.value) == IDRETRY) if ask_retry else False
    except Exception:
        return None


def show_native_dialog(title, message, is_error=False, ask_retry=False, parent=None):
    heading = tr("dialog.heading.retry") if ask_retry else (tr("dialog.heading.error") if is_error else tr("dialog.heading.info"))
    task_result = _show_task_dialog(title, heading, message, is_error=is_error, ask_retry=ask_retry, parent=parent)
    if task_result is not None:
        return bool(task_result)
    if os.name != "nt":
        return False
    flags = MB_TOPMOST | MB_TASKMODAL | MB_SETFOREGROUND
    flags |= MB_ICONERROR if is_error else MB_ICONINFORMATION
    if ask_retry:
        flags |= MB_RETRYCANCEL
        response = _user32.MessageBoxW(resolve_dialog_owner_hwnd(parent), _safe_text(message), _safe_text(title) or APP_NAME, flags)
        return int(response) == IDRETRY
    _user32.MessageBoxW(resolve_dialog_owner_hwnd(parent), _safe_text(message), _safe_text(title) or APP_NAME, flags | MB_OK)
    return False


def webview_required_message(context_label="this screen"):
    label = str(context_label or "this screen").strip() or "this screen"
    return f"Microsoft Edge WebView2 is required to open {label}. Install the WebView2 Runtime and try again."


def get_ui_image_font(size, bold=False):
    size_key = int(max(8, round(float(size or 10))))
    cache_key = (size_key, bool(bold))
    cached = _image_font_cache.get(cache_key)
    if cached is not None:
        return cached
    font = None
    if os.name == "nt":
        font_dir = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Fonts"
        candidates = ["segoeuib.ttf", "arialbd.ttf"] if bold else ["segoeui.ttf", "arial.ttf"]
        for filename in candidates:
            try:
                candidate_path = font_dir / filename
                if candidate_path.exists():
                    font = PIL.ImageFont.truetype(str(candidate_path), size=size_key)
                    break
            except Exception:
                continue
    if font is None:
        try:
            font = PIL.ImageFont.load_default()
        except Exception:
            font = None
    _image_font_cache[cache_key] = font
    return font


def image_font_line_height(font):
    if font is None:
        return 14
    try:
        ascent, descent = font.getmetrics()
        return max(12, int(ascent + descent + 2))
    except Exception:
        try:
            bbox = font.getbbox("Ag")
            return max(12, int(bbox[3] - bbox[1] + 2))
        except Exception:
            return 14


def measure_image_text_width(font, text):
    if not text:
        return 0
    cache_key = (id(font), str(text))
    cached = ordered_cache_get(_image_measure_cache, cache_key, lock=_image_measure_cache_lock)
    if cached is not None:
        return cached
    try:
        bbox = font.getbbox(str(text))
        width = max(0, int(bbox[2] - bbox[0]))
    except Exception:
        width = max(0, len(str(text)) * 8)
    ordered_cache_set(_image_measure_cache, cache_key, width, 4096, lock=_image_measure_cache_lock)
    return width


def layout_wrapped_text(text, font, max_width, spacing=4):
    value = str(text or "")
    normalized_width = max(80, int(max_width or 80))
    cache_key = (value, id(font), normalized_width, int(max(0, spacing)))
    cached = ordered_cache_get(_image_measure_cache, ("layout",) + cache_key, lock=_image_measure_cache_lock)
    if cached is not None:
        return cached

    line_height = image_font_line_height(font)
    lines = []
    cursor = 0
    paragraphs = value.split("\n")
    for paragraph_index, paragraph in enumerate(paragraphs):
        paragraph_start = cursor
        paragraph_end = paragraph_start + len(paragraph)
        if not paragraph:
            lines.append({"text": "", "start": paragraph_start, "end": paragraph_start, "width": 0})
        else:
            index = 0
            while index < len(paragraph):
                probe = index + 1
                best_end = index + 1
                last_break = -1
                while probe <= len(paragraph):
                    segment = paragraph[index:probe]
                    if measure_image_text_width(font, segment) <= normalized_width:
                        best_end = probe
                        if probe < len(paragraph) and paragraph[probe - 1].isspace():
                            last_break = probe
                        probe += 1
                        continue
                    break
                end = best_end
                if end < len(paragraph) and last_break > index:
                    end = last_break
                if end <= index:
                    end = index + 1
                line_text = paragraph[index:end].rstrip()
                line_start = paragraph_start + index
                line_end = paragraph_start + end
                lines.append(
                    {
                        "text": line_text,
                        "start": line_start,
                        "end": line_end,
                        "width": measure_image_text_width(font, line_text),
                    }
                )
                index = end
                while index < len(paragraph) and paragraph[index].isspace():
                    if paragraph[index] == "\n":
                        break
                    index += 1
        cursor = paragraph_end + (1 if paragraph_index < (len(paragraphs) - 1) else 0)
    if not lines:
        lines.append({"text": "", "start": 0, "end": 0, "width": 0})
    max_line_width = max((int(item["width"]) for item in lines), default=0)
    layout = {
        "lines": lines,
        "line_height": line_height,
        "spacing": int(max(0, spacing)),
        "width": int(max_line_width),
        "height": int((line_height * len(lines)) + (max(0, len(lines) - 1) * int(max(0, spacing)))),
    }
    ordered_cache_set(_image_measure_cache, ("layout",) + cache_key, layout, 4096, lock=_image_measure_cache_lock)
    return layout


def update_layered_window_image(hwnd, image, x, y):
    if os.name != "nt":
        return False
    try:
        normalized_hwnd = int(hwnd or 0)
        if not normalized_hwnd:
            return False
        rgba = image.convert("RGBA")
        width_px, height_px = rgba.size
        if width_px <= 0 or height_px <= 0:
            return False
        screen_dc = _user32.GetDC(None)
        if not screen_dc:
            return False
        mem_dc = _gdi32.CreateCompatibleDC(screen_dc)
        if not mem_dc:
            _user32.ReleaseDC(None, screen_dc)
            return False
        bmi = BITMAPINFO()
        bmi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
        bmi.bmiHeader.biWidth = int(width_px)
        bmi.bmiHeader.biHeight = -int(height_px)
        bmi.bmiHeader.biPlanes = 1
        bmi.bmiHeader.biBitCount = 32
        bmi.bmiHeader.biCompression = BI_RGB
        bmi.bmiHeader.biSizeImage = int(width_px * height_px * 4)
        pixel_buffer = ctypes.c_void_p()
        bitmap = _gdi32.CreateDIBSection(screen_dc, ctypes.byref(bmi), DIB_RGB_COLORS, ctypes.byref(pixel_buffer), None, 0)
        if not bitmap:
            _gdi32.DeleteDC(mem_dc)
            _user32.ReleaseDC(None, screen_dc)
            return False
        old_bitmap = _gdi32.SelectObject(mem_dc, bitmap)
        try:
            raw = rgba.tobytes("raw", "BGRA")
            ctypes.memmove(pixel_buffer, raw, len(raw))
            dst_point = wintypes.POINT(int(x), int(y))
            src_point = wintypes.POINT(0, 0)
            size = SIZE(int(width_px), int(height_px))
            blend = BLENDFUNCTION(AC_SRC_OVER, 0, 255, AC_SRC_ALPHA)
            return bool(
                _user32.UpdateLayeredWindow(
                    wintypes.HWND(normalized_hwnd),
                    screen_dc,
                    ctypes.byref(dst_point),
                    ctypes.byref(size),
                    mem_dc,
                    ctypes.byref(src_point),
                    0,
                    ctypes.byref(blend),
                    ULW_ALPHA,
                )
            )
        finally:
            if old_bitmap:
                _gdi32.SelectObject(mem_dc, old_bitmap)
            _gdi32.DeleteObject(bitmap)
            _gdi32.DeleteDC(mem_dc)
            _user32.ReleaseDC(None, screen_dc)
    except Exception:
        logger.debug("Layered window image update failed.", exc_info=True)
        return False


def apply_tk_scaling(window):
    return


def get_work_area_bounds(screen_width, screen_height):
    left = 0
    top = 0
    right = int(max(1, screen_width))
    bottom = int(max(1, screen_height))
    if os.name != "nt":
        return left, top, right, bottom
    try:
        rect = wintypes.RECT()
        SPI_GETWORKAREA = 0x0030
        if ctypes.windll.user32.SystemParametersInfoW(SPI_GETWORKAREA, 0, ctypes.byref(rect), 0):
            left = int(rect.left)
            top = int(rect.top)
            right = int(rect.right)
            bottom = int(rect.bottom)
    except Exception:
        pass
    if right <= left or bottom <= top:
        return 0, 0, int(max(1, screen_width)), int(max(1, screen_height))
    return left, top, right, bottom


def get_active_monitor_work_area(fallback_width=None, fallback_height=None):
    default_width = int(max(1, fallback_width or 1920))
    default_height = int(max(1, fallback_height or 1080))
    if os.name != "nt":
        return 0, 0, default_width, default_height
    try:
        class MONITORINFO(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("rcMonitor", wintypes.RECT),
                ("rcWork", wintypes.RECT),
                ("dwFlags", wintypes.DWORD),
            ]

        point = wintypes.POINT()
        if not ctypes.windll.user32.GetCursorPos(ctypes.byref(point)):
            raise RuntimeError("GetCursorPos failed")
        monitor = ctypes.windll.user32.MonitorFromPoint(point, 2)
        if not monitor:
            raise RuntimeError("MonitorFromPoint failed")
        monitor_info = MONITORINFO()
        monitor_info.cbSize = ctypes.sizeof(MONITORINFO)
        if not ctypes.windll.user32.GetMonitorInfoW(monitor, ctypes.byref(monitor_info)):
            raise RuntimeError("GetMonitorInfoW failed")
        rect = monitor_info.rcWork
        left = int(rect.left)
        top = int(rect.top)
        right = int(rect.right)
        bottom = int(rect.bottom)
        if right > left and bottom > top:
            return left, top, right, bottom
    except Exception:
        pass

    screen_width = default_width
    screen_height = default_height
    try:
        screen_width = int(ctypes.windll.user32.GetSystemMetrics(0))
        screen_height = int(ctypes.windll.user32.GetSystemMetrics(1))
    except Exception:
        pass
    return get_work_area_bounds(screen_width, screen_height)


def get_window_monitor_work_area(hwnd, fallback_width=None, fallback_height=None):
    default_width = int(max(1, fallback_width or 1920))
    default_height = int(max(1, fallback_height or 1080))
    if os.name != "nt":
        return get_work_area_bounds(default_width, default_height)
    try:
        normalized_hwnd = int(hwnd or 0)
    except Exception:
        normalized_hwnd = 0
    if normalized_hwnd:
        try:
            class MONITORINFO(ctypes.Structure):
                _fields_ = [
                    ("cbSize", wintypes.DWORD),
                    ("rcMonitor", wintypes.RECT),
                    ("rcWork", wintypes.RECT),
                    ("dwFlags", wintypes.DWORD),
                ]

            monitor = ctypes.windll.user32.MonitorFromWindow(wintypes.HWND(normalized_hwnd), 2)
            if monitor:
                monitor_info = MONITORINFO()
                monitor_info.cbSize = ctypes.sizeof(MONITORINFO)
                if ctypes.windll.user32.GetMonitorInfoW(monitor, ctypes.byref(monitor_info)):
                    rect = monitor_info.rcWork
                    left = int(rect.left)
                    top = int(rect.top)
                    right = int(rect.right)
                    bottom = int(rect.bottom)
                    if right > left and bottom > top:
                        return left, top, right, bottom
        except Exception:
            pass
    return get_active_monitor_work_area(default_width, default_height)


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
        logger.debug("Window capture privacy update failed.", exc_info=True)
        return False


def apply_capture_privacy_to_window(window, enabled=True):
    return False


def is_capture_privacy_active():
    return bool(capture_privacy_enabled)


def schedule_window_privacy_refresh(window, refresh_ms=1800):
    return


def configure_private_window(window, *, dark=False, translucent=False, refresh_ms=1800):
    return


def apply_window_corner_region(window, radius):
    return False


def apply_hwnd_corner_region(hwnd, width, height, radius):
    if os.name != "nt":
        return False
    try:
        normalized_hwnd = int(hwnd or 0)
        if not normalized_hwnd:
            return False
        top_level = int(_user32.GetAncestor(wintypes.HWND(normalized_hwnd), GA_ROOT) or 0)
        if top_level:
            normalized_hwnd = top_level
        width = int(max(1, width or 0))
        height = int(max(1, height or 0))
        rect = wintypes.RECT()
        # Use the real native window bounds so DPI scaling does not leave a square strip
        # outside the rounded HTML shell.
        if _user32.GetWindowRect(wintypes.HWND(normalized_hwnd), ctypes.byref(rect)):
            rect_width = int(max(1, rect.right - rect.left))
            rect_height = int(max(1, rect.bottom - rect.top))
            if rect_width > 1 and rect_height > 1:
                width = rect_width
                height = rect_height
        radius = int(max(0, radius or 0))
        if width <= 1 or height <= 1:
            return False
        if radius <= 1:
            return bool(_user32.SetWindowRgn(wintypes.HWND(normalized_hwnd), None, True))
        radius = int(min(radius, width // 2, height // 2))
        region = _gdi32.CreateRoundRectRgn(0, 0, width + 1, height + 1, radius * 2, radius * 2)
        if not region:
            return False
        applied = bool(_user32.SetWindowRgn(wintypes.HWND(normalized_hwnd), region, True))
        if not applied:
            _gdi32.DeleteObject(region)
        return applied
    except Exception:
        return False


def draw_canvas_ellipse(canvas, x1, y1, x2, y2, **kwargs):
    return []


def draw_rounded_canvas_rect(canvas, x1, y1, x2, y2, radius, **kwargs):
    return []


def apply_hwnd_win11_window_style(hwnd, dark=False, translucent=False):
    if os.name != "nt":
        return False
    try:
        normalized_hwnd = int(hwnd or 0)
        if not normalized_hwnd:
            return False
        top_level = int(_user32.GetAncestor(wintypes.HWND(normalized_hwnd), GA_ROOT) or 0)
        if top_level:
            normalized_hwnd = top_level
        hwnd_ref = wintypes.HWND(normalized_hwnd)
        rounded = ctypes.c_int(DWMWCP_ROUND)
        backdrop = ctypes.c_int(DWMSBT_TRANSIENTWINDOW if translucent else DWMSBT_MAINWINDOW)
        mica_enabled = ctypes.c_int(1 if translucent else 0)
        dark_mode = ctypes.c_int(1 if dark else 0)
        _dwmapi.DwmSetWindowAttribute(
            hwnd_ref,
            DWMWA_WINDOW_CORNER_PREFERENCE,
            ctypes.byref(rounded),
            ctypes.sizeof(rounded),
        )
        _dwmapi.DwmSetWindowAttribute(
            hwnd_ref,
            DWMWA_SYSTEMBACKDROP_TYPE,
            ctypes.byref(backdrop),
            ctypes.sizeof(backdrop),
        )
        _dwmapi.DwmSetWindowAttribute(
            hwnd_ref,
            DWMWA_MICA_EFFECT,
            ctypes.byref(mica_enabled),
            ctypes.sizeof(mica_enabled),
        )
        _dwmapi.DwmSetWindowAttribute(
            hwnd_ref,
            DWMWA_USE_IMMERSIVE_DARK_MODE,
            ctypes.byref(dark_mode),
            ctypes.sizeof(dark_mode),
        )
        return True
    except Exception:
        return False


def apply_win11_window_style(window, dark=False, translucent=False):
    if os.name != "nt":
        return
    try:
        window.update_idletasks()
        apply_hwnd_win11_window_style(window.winfo_id(), dark=dark, translucent=translucent)
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


def _normalize_config_record(record):
    return dict(record) if isinstance(record, dict) else {}


def _config_mtime_ns(path):
    try:
        return int(path.stat().st_mtime_ns)
    except Exception:
        return -1


def load_config_record():
    global config_record_cache, config_record_cache_mtime_ns, config_record_cache_loaded
    config_file = get_config_file()
    with config_file_lock:
        if not config_file.exists():
            config_record_cache = {}
            config_record_cache_mtime_ns = -1
            config_record_cache_loaded = True
            return {}
        current_mtime_ns = _config_mtime_ns(config_file)
        if (
            config_record_cache_loaded
            and config_record_cache is not None
            and current_mtime_ns == config_record_cache_mtime_ns
        ):
            return dict(config_record_cache)
        try:
            data = json.loads(config_file.read_text(encoding="utf-8"))
            normalized = _normalize_config_record(data)
            config_record_cache = dict(normalized)
            config_record_cache_mtime_ns = current_mtime_ns
            config_record_cache_loaded = True
            return normalized
        except Exception:
            config_record_cache = {}
            config_record_cache_mtime_ns = current_mtime_ns
            config_record_cache_loaded = True
    return {}


def save_config_record(record):
    global config_record_cache, config_record_cache_mtime_ns, config_record_cache_loaded
    normalized = _normalize_config_record(record)
    data_dir = get_app_data_dir()
    config_file = get_config_file()
    data_dir.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(normalized, indent=2)
    temp_path = data_dir / f"{CONFIG_FILE_NAME}.{secrets.token_hex(8)}.tmp"
    with config_file_lock:
        if config_record_cache_loaded and config_record_cache is not None and normalized == config_record_cache:
            return False
        temp_path.write_text(payload, encoding="utf-8")
        try:
            retry_delay = max(0.001, float(CONFIG_SAVE_RETRY_DELAY_SECONDS))
            for attempt in range(CONFIG_SAVE_RETRY_COUNT):
                try:
                    os.replace(temp_path, config_file)
                    break
                except OSError as exc:
                    winerror = int(getattr(exc, "winerror", 0) or 0)
                    if attempt >= (CONFIG_SAVE_RETRY_COUNT - 1) or winerror not in {5, 32}:
                        raise
                    time.sleep(retry_delay)
                    retry_delay = min(0.08, retry_delay * 2.0)
        finally:
            try:
                if temp_path.exists():
                    temp_path.unlink()
            except Exception:
                pass
        config_record_cache = dict(normalized)
        config_record_cache_mtime_ns = _config_mtime_ns(config_file)
        config_record_cache_loaded = True
    return True


def mutate_config_record(mutator):
    record = load_config_record()
    before = json.dumps(record, sort_keys=True, separators=(",", ":"))
    mutator(record)
    after = json.dumps(record, sort_keys=True, separators=(",", ":"))
    if before == after:
        return False, record
    save_config_record(record)
    return True, record


def mutate_saved_secret(record, plain_key, encrypted_key, value):
    encrypted = encrypt_with_dpapi(value)
    record.pop(plain_key, None)
    if encrypted:
        record[encrypted_key] = encrypted
        return True
    if os.name != "nt":
        record[plain_key] = value
        return True
    return False


def remove_saved_secret(record, plain_key, encrypted_key):
    record.pop(plain_key, None)
    record.pop(encrypted_key, None)


def load_saved_secret(record, plain_key, encrypted_key, persist_migration=True):
    encrypted = str(record.get(encrypted_key, "")).strip()
    if encrypted:
        decrypted = decrypt_with_dpapi(encrypted)
        if decrypted:
            return decrypted
    legacy = str(record.get(plain_key, "")).strip()
    if legacy:
        if mutate_saved_secret(record, plain_key, encrypted_key, legacy) and persist_migration:
            save_config_record(record)
        return legacy
    return ""


def normalize_remember_me_preference(value):
    if isinstance(value, bool):
        return bool(value)
    text = str(value or "").strip().lower()
    if not text:
        return False
    return text in {"1", "true", "yes", "on"}


def clear_persisted_account_auth(record=None, clear_email=False):
    target = dict(record) if isinstance(record, dict) else load_config_record()
    target["session_id"] = ""
    target["remember_me"] = False
    target.pop("session_token", None)
    target.pop("session_token_dpapi", None)
    target.pop("api_key", None)
    target.pop("api_key_dpapi", None)
    target.pop("remembered_password", None)
    target.pop("remembered_password_dpapi", None)
    if clear_email:
        target["user_email"] = ""
    save_config_record(target)
    return target


def normalize_account_email(value):
    candidate = str(value or "").strip().lower()
    if not candidate:
        return ""
    return candidate


def decode_account_api_key_bundle(bundle, password):
    if not isinstance(bundle, dict):
        raise RuntimeError("No encrypted API key was returned by the website.")
    if str(bundle.get("kdf_name", "")).strip().lower() not in {"", "pbkdf2-sha256"}:
        raise RuntimeError("The website returned an unsupported API-key format.")
    try:
        salt = base64.b64decode(str(bundle.get("salt", "") or ""))
        nonce = base64.b64decode(str(bundle.get("nonce", "") or ""))
        ciphertext = base64.b64decode(str(bundle.get("ciphertext", "") or ""))
    except Exception as exc:
        raise RuntimeError("The website returned a malformed encrypted API key.") from exc

    iterations = int(bundle.get("opslimit", 600000) or 600000)
    if iterations < 100000:
        iterations = 100000
    if len(salt) < 8 or len(nonce) < 12 or not ciphertext:
        raise RuntimeError("The website returned an incomplete encrypted API key.")

    password_bytes = str(password or "").encode("utf-8")
    if not password_bytes:
        raise RuntimeError("Password is required to unlock the encrypted API key.")

    try:
        SHA256, PBKDF2HMAC, AESGCM = get_crypto_primitives()
    except Exception as exc:
        raise RuntimeError("The desktop app could not load its local decryption support.") from exc

    try:
        kdf = PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt, iterations=iterations)
        aes_key = kdf.derive(password_bytes)
        plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise RuntimeError("Could not unlock the encrypted API key with that password.") from exc

    resolved = str(plaintext.decode("utf-8", errors="strict") or "").strip()
    if not resolved:
        raise RuntimeError("The decrypted API key was empty.")
    return resolved


def set_hidden_path_flag(path):
    if os.name != "nt":
        return False
    try:
        normalized = str(Path(path))
        get_attributes = getattr(ctypes.windll.kernel32, "GetFileAttributesW", None)
        set_attributes = getattr(ctypes.windll.kernel32, "SetFileAttributesW", None)
        if get_attributes is None or set_attributes is None:
            return False
        current_attributes = int(get_attributes(normalized))
        if current_attributes == INVALID_FILE_ATTRIBUTES:
            current_attributes = 0
        desired_attributes = current_attributes | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
        if desired_attributes != current_attributes:
            return bool(set_attributes(normalized, desired_attributes))
        return True
    except Exception:
        logger.debug("Failed to mark hidden runtime path: %s", path, exc_info=True)
        return False


def ensure_pro_auth_runtime_dir():
    runtime_dir = get_pro_auth_runtime_dir()
    runtime_dir.mkdir(parents=True, exist_ok=True)
    set_hidden_path_flag(runtime_dir)
    return runtime_dir


def normalize_pro_auth_guard_state(payload=None):
    data = payload if isinstance(payload, dict) else {}
    normalized = {
        "version": 1,
        "failure_count": 0,
        "last_failure_at": 0,
        "locked_at": 0,
        "locked_until": 0,
        "hard_locked": False,
        "time_source": "",
    }
    for key in ("version", "failure_count", "last_failure_at", "locked_at", "locked_until"):
        try:
            normalized[key] = max(0, int(data.get(key, normalized[key])))
        except Exception:
            pass
    normalized["hard_locked"] = bool(data.get("hard_locked", False))
    normalized["time_source"] = str(data.get("time_source", "") or "").strip()[:255]
    return normalized


def load_pro_auth_guard_state():
    lock_file = get_pro_auth_lock_file()
    with pro_auth_guard_lock:
        if not lock_file.exists():
            return normalize_pro_auth_guard_state()
        try:
            raw_payload = lock_file.read_text(encoding="utf-8").strip()
        except Exception:
            return normalize_pro_auth_guard_state()
    if not raw_payload:
        return normalize_pro_auth_guard_state()
    if os.name == "nt":
        plain_payload = decrypt_with_dpapi(raw_payload)
    else:
        try:
            plain_payload = base64.b64decode(raw_payload).decode("utf-8")
        except Exception:
            plain_payload = ""
    if not plain_payload:
        return normalize_pro_auth_guard_state()
    try:
        decoded = json.loads(plain_payload)
    except Exception:
        decoded = {}
    return normalize_pro_auth_guard_state(decoded)


def save_pro_auth_guard_state(payload):
    state = normalize_pro_auth_guard_state(payload)
    should_clear = (
        state["failure_count"] <= 0
        and state["last_failure_at"] <= 0
        and state["locked_at"] <= 0
        and state["locked_until"] <= 0
        and not state["hard_locked"]
    )
    runtime_dir = ensure_pro_auth_runtime_dir()
    lock_file = get_pro_auth_lock_file()
    with pro_auth_guard_lock:
        if should_clear:
            try:
                if lock_file.exists():
                    lock_file.unlink()
            except Exception:
                pass
            return
        serialized = json.dumps(state, separators=(",", ":"), sort_keys=True)
        if os.name == "nt":
            stored_payload = encrypt_with_dpapi(serialized)
            if not stored_payload:
                raise RuntimeError("Could not protect the legacy auth guard state with DPAPI.")
        else:
            stored_payload = base64.b64encode(serialized.encode("utf-8")).decode("ascii")
        temp_path = runtime_dir / f"{PRO_AUTH_HIDDEN_FILE_NAME}.{secrets.token_hex(6)}.tmp"
        temp_path.write_text(stored_payload, encoding="utf-8")
        try:
            os.replace(temp_path, lock_file)
            set_hidden_path_flag(lock_file)
        finally:
            try:
                if temp_path.exists():
                    temp_path.unlink()
            except Exception:
                pass


def clear_pro_auth_guard_state():
    save_pro_auth_guard_state({})


def parse_remote_utc_epoch(value):
    text = str(value or "").strip()
    if not text:
        return 0
    try:
        normalized = text.replace("Z", "+00:00")
        normalized = re.sub(r"\.(\d{6})\d+(?=([+-]\d{2}:\d{2})?$)", r".\1", normalized)
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return max(0, int(parsed.timestamp()))
    except Exception:
        return 0


def extract_trusted_epoch_from_payload(payload):
    if not isinstance(payload, dict):
        return 0
    for key in ("unixtime", "unixTime", "timestamp"):
        raw_value = payload.get(key)
        if isinstance(raw_value, (int, float)):
            return max(0, int(raw_value))
        try:
            candidate = int(str(raw_value or "").strip())
            if candidate > 0:
                return candidate
        except Exception:
            pass
    for key in ("utc_datetime", "utcDateTime", "datetime", "dateTime", "currentDateTime"):
        candidate = parse_remote_utc_epoch(payload.get(key))
        if candidate > 0:
            return candidate
    return 0


def fetch_trusted_utc_epoch():
    requests_module = get_requests_module()
    headers = {
        "Accept": "application/json",
        "User-Agent": f"{APP_NAME}/{APP_VERSION}",
    }
    urls = tuple(TRUSTED_TIME_URLS)
    if not urls:
        raise RuntimeError(tr("error.pro_time_unavailable"))
    failures = []

    def _fetch_one(url):
        session = requests_module.Session()
        session.trust_env = False
        try:
            response = session.get(url, headers=headers, timeout=TRUSTED_TIME_TIMEOUT_SECONDS, allow_redirects=True)
        except requests_module.RequestException as exc:
            return 0, url, f"{url} ({exc})"
        except Exception as exc:
            return 0, url, f"{url} ({exc})"
        finally:
            try:
                session.close()
            except Exception:
                pass
        if not response.ok:
            return 0, url, f"{url} (status {response.status_code})"
        try:
            payload = response.json()
        except Exception:
            return 0, url, f"{url} (non-JSON)"
        trusted_epoch = extract_trusted_epoch_from_payload(payload)
        if trusted_epoch > 0:
            return trusted_epoch, url, ""
        return 0, url, f"{url} (missing time value)"

    max_workers = max(1, min(4, len(urls)))
    try:
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="trusted-time") as executor:
            future_map = {executor.submit(_fetch_one, url): url for url in urls}
            for future in as_completed(future_map):
                try:
                    trusted_epoch, source_url, failure = future.result()
                except Exception as exc:
                    failures.append(f"{future_map.get(future, '?')} ({exc})")
                    continue
                if trusted_epoch > 0:
                    return trusted_epoch, source_url
                if failure:
                    failures.append(failure)
    except Exception:
        logger.debug("Parallel trusted time fetch failed; falling back to sequential mode.", exc_info=True)
        for url in urls:
            trusted_epoch, source_url, failure = _fetch_one(url)
            if trusted_epoch > 0:
                return trusted_epoch, source_url
            if failure:
                failures.append(failure)

    if failures:
        logger.warning("Trusted online time lookup failed: %s", "; ".join(failures[:3]))
    raise RuntimeError(tr("error.pro_time_unavailable"))


def extract_lockout_seconds_from_message(message):
    text = str(message or "").strip().lower()
    if not text:
        return 0, False
    seconds_match = re.search(r"(\d+)\s+seconds?", text)
    if seconds_match:
        seconds_value = max(0, int(seconds_match.group(1)))
        return seconds_value, "locked for" in text
    hours_match = re.search(r"(\d+)\s+hours?", text)
    if hours_match:
        return max(0, int(hours_match.group(1))) * 3600, True
    return 0, False


def pro_auth_lockout_duration_for_failure_count(failure_count):
    count = max(0, int(failure_count or 0))
    if count >= PRO_AUTH_HARD_LOCKOUT_FAILURE:
        return PRO_AUTH_HARD_LOCKOUT_SECONDS, True
    if count < PRO_AUTH_FIRST_LOCKOUT_FAILURE:
        return 0, False
    lockout_level = max(0, count - 2)
    return PRO_AUTH_LOCKOUT_BASE_SECONDS * (2 ** max(0, lockout_level - 1)), False


def build_pro_auth_lockout_message(seconds, hard_locked=False):
    remaining_seconds = max(1, int(math.ceil(float(seconds or 0))))
    key = "error.pro_lockout_locked" if hard_locked else "error.pro_lockout_wait"
    return tr(key, seconds=remaining_seconds)


def inspect_pro_auth_guard(now_epoch):
    current_time = max(0, int(now_epoch or 0))
    state = load_pro_auth_guard_state()
    changed = False
    if state["locked_until"] > 0 and current_time >= state["locked_until"]:
        state = normalize_pro_auth_guard_state()
        changed = True
    elif state["failure_count"] > 0 and state["last_failure_at"] > 0:
        if current_time - state["last_failure_at"] > PRO_AUTH_FAILURE_WINDOW_SECONDS:
            state = normalize_pro_auth_guard_state()
            changed = True
    if changed:
        save_pro_auth_guard_state(state)
    if state["locked_until"] > current_time:
        remaining = max(1, state["locked_until"] - current_time)
        return True, remaining, bool(state["hard_locked"]), state
    return False, 0, False, state


def get_live_pro_auth_lockout_state():
    try:
        trusted_now, _time_source = fetch_trusted_utc_epoch()
    except Exception:
        return 0, False
    is_locked, remaining_seconds, hard_locked, _state = inspect_pro_auth_guard(trusted_now)
    if not is_locked or remaining_seconds <= 0:
        return 0, False
    return int(max(1, remaining_seconds)), bool(hard_locked)


def record_local_pro_auth_failure(now_epoch, time_source=""):
    current_time = max(0, int(now_epoch or 0))
    _, _, _, state = inspect_pro_auth_guard(current_time)
    if state["failure_count"] > 0 and state["last_failure_at"] > 0:
        if current_time - state["last_failure_at"] > PRO_AUTH_FAILURE_WINDOW_SECONDS:
            state = normalize_pro_auth_guard_state()
    state["failure_count"] = max(0, int(state.get("failure_count", 0))) + 1
    state["last_failure_at"] = current_time
    state["time_source"] = str(time_source or "").strip()[:255]
    lockout_seconds, hard_locked = pro_auth_lockout_duration_for_failure_count(state["failure_count"])
    if lockout_seconds > 0:
        state["locked_at"] = current_time
        state["locked_until"] = current_time + lockout_seconds
        state["hard_locked"] = bool(hard_locked)
    else:
        state["locked_at"] = 0
        state["locked_until"] = 0
        state["hard_locked"] = False
    save_pro_auth_guard_state(state)
    if lockout_seconds > 0:
        return build_pro_auth_lockout_message(lockout_seconds, hard_locked=hard_locked)
    return ""


def sync_local_pro_auth_lockout(now_epoch, server_message, time_source=""):
    lockout_seconds, hard_locked = extract_lockout_seconds_from_message(server_message)
    if lockout_seconds <= 0:
        return str(server_message or tr("error.auth_denied"))
    state = load_pro_auth_guard_state()
    state["failure_count"] = max(
        int(state.get("failure_count", 0) or 0),
        PRO_AUTH_HARD_LOCKOUT_FAILURE if hard_locked else PRO_AUTH_FIRST_LOCKOUT_FAILURE,
    )
    state["last_failure_at"] = max(0, int(now_epoch or 0))
    state["locked_at"] = max(0, int(now_epoch or 0))
    state["locked_until"] = state["locked_at"] + lockout_seconds
    state["hard_locked"] = bool(hard_locked)
    state["time_source"] = str(time_source or "").strip()[:255]
    save_pro_auth_guard_state(state)
    return build_pro_auth_lockout_message(lockout_seconds, hard_locked=hard_locked)


def center_window(window, width, height):
    return


def fit_window_to_content(window, min_width=0, min_height=0, max_width=0, max_height=0):
    return


def make_dialog_shell(title, width, height, parent=None):
    raise RuntimeError("Tk dialog shell is no longer available.")


def apply_widget_corner_region(widget, radius=12):
    return False


def schedule_widget_rounding(widget, radius=12):
    return


def style_button(widget, *, primary=False, active=False):
    return


STARTUP_PROGRESS_STAGE_ORDER = [
    "startup.launching",
    "startup.restoring",
    "startup.opening_setup",
    "startup.checking_auth",
    "startup.connecting_pro",
    "startup.initializing_model",
    "startup.starting_indicator",
    "startup.ready",
]


def build_startup_splash_html():
    return r"""
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        :root {
            color-scheme: dark;
            --shell-bg:
                radial-gradient(circle at 18% 14%, rgba(72, 126, 255, 0.26), transparent 28%),
                radial-gradient(circle at 84% 10%, rgba(90, 190, 255, 0.14), transparent 22%),
                linear-gradient(180deg, #0f1b31 0%, #091326 100%);
            --card-bg: rgba(9, 20, 40, 0.82);
            --card-border: rgba(145, 179, 235, 0.18);
            --title: #edf4ff;
            --brand: #9fb7dc;
            --muted: #a8b9d7;
            --pill-bg: rgba(83, 138, 255, 0.14);
            --pill-border: rgba(148, 186, 255, 0.22);
            --pill-text: #c6d8ff;
            --stage-bg:
                radial-gradient(circle at 50% 46%, rgba(56, 111, 241, 0.12), transparent 26%),
                linear-gradient(180deg, rgba(7, 16, 33, 0.26), rgba(12, 31, 61, 0.08));
            --stage-border: rgba(132, 173, 243, 0.12);
            --star: rgba(148, 192, 255, 0.94);
        }

        body.theme-light {
            color-scheme: light;
            --shell-bg:
                radial-gradient(circle at 18% 14%, rgba(96, 166, 255, 0.22), transparent 30%),
                radial-gradient(circle at 84% 10%, rgba(160, 212, 255, 0.2), transparent 24%),
                linear-gradient(180deg, #eef4fd 0%, #e3edf9 100%);
            --card-bg: rgba(255, 255, 255, 0.82);
            --card-border: rgba(44, 83, 149, 0.12);
            --title: #17315d;
            --brand: #59729a;
            --muted: #5f7698;
            --pill-bg: rgba(83, 138, 255, 0.12);
            --pill-border: rgba(83, 138, 255, 0.2);
            --pill-text: #29518d;
            --stage-bg:
                radial-gradient(circle at 50% 46%, rgba(56, 111, 241, 0.1), transparent 24%),
                linear-gradient(180deg, rgba(255, 255, 255, 0.18), rgba(222, 235, 255, 0.08));
            --stage-border: rgba(90, 134, 214, 0.1);
            --star: rgba(80, 130, 235, 0.92);
        }

        * { box-sizing: border-box; }

        html, body {
            margin: 0;
            width: 100%;
            height: 100%;
            overflow: hidden;
            font-family: "Segoe UI Variable Text", "Segoe UI", sans-serif;
            background: var(--shell-bg);
        }

        body {
            display: grid;
            place-items: center;
            padding: 0;
        }

        .shell {
            width: min(680px, calc(100vw - 14px));
            min-height: min(470px, calc(100vh - 14px));
            max-height: calc(100vh - 8px);
            overflow: auto;
            padding: 22px 22px 24px;
            border-radius: 34px;
            border: 1px solid var(--card-border);
            background:
                linear-gradient(180deg, rgba(255,255,255,0.06), rgba(255,255,255,0.02)),
                var(--card-bg);
            box-shadow:
                0 30px 80px rgba(1, 7, 18, 0.34),
                inset 0 1px 0 rgba(255, 255, 255, 0.08);
            backdrop-filter: blur(22px);
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 14px;
            text-align: center;
            position: relative;
            isolation: isolate;
        }

        .shell::before {
            content: "";
            position: absolute;
            inset: 0;
            background:
                radial-gradient(circle at 50% 0%, rgba(255, 255, 255, 0.14), transparent 28%),
                radial-gradient(circle at 50% 58%, rgba(43, 92, 195, 0.12), transparent 34%);
            pointer-events: none;
        }

        .shell > * {
            position: relative;
            z-index: 1;
        }

        .brand {
            margin: 0;
            font-size: 12px;
            letter-spacing: 0.13em;
            text-transform: uppercase;
            font-weight: 800;
            color: var(--brand);
        }

        .eye-stage {
            position: relative;
            width: min(100%, 520px);
            min-height: 182px;
            display: grid;
            place-items: center;
            border-radius: 28px;
            overflow: hidden;
            background: var(--stage-bg);
            border: 1px solid var(--stage-border);
        }

        .stars {
            position: absolute;
            inset: 0;
            pointer-events: none;
            opacity: 0.7;
            transform: rotate(34deg);
        }

        .star {
            position: absolute;
            left: 50%;
            top: 50%;
            width: 0;
            height: 2px;
            border-radius: 999px;
            background: linear-gradient(-45deg, var(--star), transparent);
            box-shadow: 0 0 10px rgba(135, 185, 255, 0.4);
            animation: shoot 3.8s ease-in-out infinite;
        }

        .star:nth-child(1) { top: calc(50% - 76px); left: calc(50% - 140px); animation-delay: 0s; }
        .star:nth-child(2) { top: calc(50% - 18px); left: calc(50% + 96px); animation-delay: .55s; }
        .star:nth-child(3) { top: calc(50% + 44px); left: calc(50% - 52px); animation-delay: 1.1s; }
        .star:nth-child(4) { top: calc(50% + 82px); left: calc(50% + 144px); animation-delay: 1.65s; }
        .star:nth-child(5) { top: calc(50% - 104px); left: calc(50% + 168px); animation-delay: 2.2s; }
        .star:nth-child(6) { top: calc(50% + 118px); left: calc(50% - 178px); animation-delay: 2.75s; }

        .eye-loader {
            position: relative;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 228px;
            height: 142px;
            padding: 18px;
            border-radius: 999px;
        }

        .eye-loader::before {
            content: "";
            position: absolute;
            inset: 0;
            border-radius: inherit;
            background:
                radial-gradient(circle at 50% 50%, rgba(58, 118, 242, 0.5) 0%, rgba(58, 118, 242, 0.18) 42%, rgba(58, 118, 242, 0) 76%),
                radial-gradient(circle at 50% 50%, rgba(196, 220, 255, 0.12), transparent 74%);
            filter: blur(18px);
            opacity: 0.98;
        }

        .brand-eye {
            position: relative;
            width: 188px;
            height: 102px;
            display: block;
            filter: drop-shadow(0 18px 32px rgba(26, 77, 183, 0.28));
            animation: bob 4.6s ease-in-out infinite;
        }

        .brand-eye-shell {
            position: absolute;
            inset: 0;
            overflow: hidden;
            border-radius: 999px;
            border: 5px solid #2f6feb;
            background: linear-gradient(180deg, rgba(121, 164, 255, 0.96), rgba(58, 109, 226, 0.98));
            box-shadow:
                0 0 0 1px rgba(235, 243, 255, 0.28) inset,
                0 18px 30px rgba(14, 54, 128, 0.24),
                inset 0 -8px 12px rgba(19, 58, 137, 0.24);
            animation: squish 6.2s linear infinite;
        }

        .brand-eye-sclera,
        .brand-eye-lid {
            position: absolute;
            inset: 6px;
            border-radius: 999px;
        }

        .brand-eye-sclera {
            overflow: hidden;
            background:
                radial-gradient(circle at 50% 50%, rgba(249, 252, 255, 0.99), rgba(226, 237, 255, 0.98) 62%, rgba(172, 198, 249, 0.96) 100%),
                linear-gradient(180deg, #fbfdff, #e4efff);
        }

        .brand-eye-iris {
            position: absolute;
            top: 50%;
            left: 50%;
            width: 50px;
            height: 50px;
            border-radius: 50%;
            background: radial-gradient(circle at 35% 28%, #8dccff 0%, #5c95ff 28%, #3a63d8 56%, #243c93 78%, #16214e 100%);
            box-shadow:
                inset 0 0 0 3px rgba(205, 226, 255, 0.34),
                0 0 0 1px rgba(34, 64, 149, 0.18),
                0 0 28px rgba(56, 113, 241, 0.34);
            transform: translate(calc(-50% + var(--look-x, 0px)), calc(-50% + var(--look-y, 0px)));
            transition: transform 1.9s cubic-bezier(0.25, 0.85, 0.25, 1);
        }

        .brand-eye-pupil {
            position: absolute;
            top: 50%;
            left: 50%;
            width: 15px;
            height: 15px;
            border-radius: 50%;
            background: #13204b;
            transform: translate(-50%, -50%);
        }

        .brand-eye-highlight {
            position: absolute;
            left: 24%;
            top: 16%;
            width: 30%;
            height: 16%;
            border-radius: 999px;
            background: linear-gradient(180deg, rgba(255,255,255,0.88), rgba(255,255,255,0));
            opacity: .82;
        }

        .brand-eye-lid {
            background: linear-gradient(180deg, rgba(120, 165, 255, 0.98), rgba(79, 118, 215, 0.98) 58%, rgba(201, 221, 255, 0.94) 100%);
            transform-origin: center top;
            transform: translateY(-114%) scaleY(.92);
            animation: blink 6.2s linear infinite;
        }

        .title {
            margin: 0;
            max-width: 520px;
            font-size: clamp(30px, 4.6vw, 40px);
            line-height: 1.02;
            color: var(--title);
            letter-spacing: -0.035em;
        }

        .stage {
            margin: 0;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 9px 16px;
            border-radius: 999px;
            background: var(--pill-bg);
            border: 1px solid var(--pill-border);
            color: var(--pill-text);
            font-size: 15px;
            font-weight: 800;
        }

        .detail {
            margin: 0;
            max-width: 470px;
            color: var(--muted);
            font-size: 14px;
            line-height: 1.45;
        }

        @keyframes shoot {
            0% { width: 0; transform: translateX(0); opacity: 0; }
            14% { opacity: 1; }
            30% { width: 92px; opacity: 1; }
            100% { width: 0; transform: translateX(260px); opacity: 0; }
        }

        @keyframes bob {
            0% { transform: translate3d(0, 0, 0) scale(1); }
            50% { transform: translate3d(0, -1px, 0) scale(1.01); }
            100% { transform: translate3d(0, 0, 0) scale(1); }
        }

        @keyframes blink {
            0%, 43%, 49%, 100% { transform: translateY(-104%) scaleY(1); }
            45%, 47% { transform: translateY(0) scaleY(1.02); }
        }

        @keyframes squish {
            0%, 43%, 49%, 100% { transform: scale(1); }
            45% { transform: scale(0.95, 0.74); }
            47% { transform: scale(0.97, 0.86); }
        }

        @media (max-width: 640px), (max-height: 620px) {
            .shell {
                width: min(680px, calc(100vw - 8px));
                min-height: min(420px, calc(100vh - 8px));
                padding: 18px 14px 18px;
                border-radius: 28px;
            }

            .eye-stage {
                min-height: 154px;
                border-radius: 24px;
            }

            .title { font-size: clamp(26px, 8.4vw, 34px); }
            .detail { font-size: 13px; }
        }

        @media (prefers-reduced-motion: reduce) {
            .brand-eye,
            .brand-eye-shell,
            .brand-eye-lid,
            .star {
                animation: none !important;
                transition: none !important;
            }
        }
    </style>
</head>
<body>
    <div class="shell">
        <div class="brand">EyesAndEars</div>
        <div class="eye-stage">
            <div class="stars" aria-hidden="true">
                <span class="star"></span>
                <span class="star"></span>
                <span class="star"></span>
                <span class="star"></span>
                <span class="star"></span>
                <span class="star"></span>
            </div>
            <div class="eye-loader" data-brand-eye>
                <span class="brand-eye" aria-hidden="true">
                    <span class="brand-eye-shell">
                        <span class="brand-eye-sclera">
                            <span class="brand-eye-iris">
                                <span class="brand-eye-pupil"></span>
                            </span>
                        </span>
                        <span class="brand-eye-highlight"></span>
                        <span class="brand-eye-lid"></span>
                    </span>
                </span>
            </div>
        </div>
        <h1 class="title" id="startup-title">Starting EyesAndEars</h1>
        <p class="stage" id="startup-stage">Launching</p>
        <p class="detail" id="startup-detail">Loading interface</p>
    </div>
    <script>
        const setText = (id, value) => {
            const node = document.getElementById(id);
            if (node) node.textContent = String(value || "");
        };

        const applyTheme = (theme) => {
            const dark = String(theme || "").toLowerCase() === "dark";
            document.body.classList.toggle("theme-dark", dark);
            document.body.classList.toggle("theme-light", !dark);
            document.documentElement.style.colorScheme = dark ? "dark" : "light";
        };

        const initBrandEyes = (signal) => {
            const eyeRoots = Array.from(document.querySelectorAll("[data-brand-eye]"));
            const looks = [
                { x: 0, y: 0 },
                { x: -3, y: 0 },
                { x: 3, y: 0 },
                { x: -2, y: 2 },
                { x: 2, y: 2 }
            ];

            eyeRoots.forEach((eyeRoot) => {
                let timer = 0;
                const tick = () => {
                    const look = looks[Math.floor(Math.random() * looks.length)];
                    eyeRoot.style.setProperty("--look-x", `${look.x}px`);
                    eyeRoot.style.setProperty("--look-y", `${look.y}px`);
                    timer = window.setTimeout(tick, 1700 + Math.random() * 1800);
                };
                tick();
                signal.addEventListener("abort", () => {
                    if (timer) window.clearTimeout(timer);
                }, { once: true });
            });
        };

        const applyState = (state) => {
            setText("startup-title", state.title || "Starting EyesAndEars");
            setText("startup-stage", state.stage || "Launching");
            setText("startup-detail", state.detail || "Loading interface");
            applyTheme(state.theme || "dark");
        };

        const startPolling = (signal, api) => {
            const tick = async () => {
                try {
                    const payload = await api.get_state();
                    applyState(payload || {});
                    if (payload && payload.close) {
                        signal.abort();
                        if (typeof api.close_window === "function") {
                            await api.close_window();
                        } else {
                            window.close();
                        }
                        return;
                    }
                } catch (_error) {
                }
                window.setTimeout(tick, 120);
            };
            tick();
        };

        let initialized = false;
        const initBridge = () => {
            if (initialized) return;
            const api = window.pywebview && window.pywebview.api;
            if (!api) {
                window.setTimeout(initBridge, 80);
                return;
            }
            initialized = true;
            const abortController = new AbortController();
            initBrandEyes(abortController.signal);
            startPolling(abortController, api);
            if (typeof api.notify_ready === "function") {
                Promise.resolve(api.notify_ready()).catch(() => {});
            }
        };

        window.addEventListener("pywebviewready", initBridge);
        if (document.readyState === "loading") {
            document.addEventListener("DOMContentLoaded", initBridge, { once: true });
        } else {
            initBridge();
        }
    </script>
</body>
</html>
"""


class StartupSplashBridge:
    def __init__(self, state_path, ready_path=None):
        self._state_path = Path(state_path)
        self._ready_path = Path(ready_path) if ready_path else self._state_path.with_name(STARTUP_SPLASH_READY_FILE_NAME)
        self._window = None
        self._lock = Lock()

    def bind_window(self, window):
        with self._lock:
            self._window = window

    def get_state(self):
        state = {
            "title": tr("startup.title"),
            "stage": tr("startup.launching"),
            "detail": tr("startup.detail.launching"),
            "theme": "dark" if resolve_theme_dark(ui_theme_preference) else "light",
            "hidden": False,
            "close": False,
        }
        try:
            loaded = json.loads(self._state_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                state.update(loaded)
        except Exception:
            pass
        return state

    def notify_ready(self):
        try:
            self._ready_path.write_text("ready\n", encoding="utf-8")
        except Exception:
            return False
        return True

    def close_window(self):
        with self._lock:
            window = self._window
        if window is None:
            return False
        try:
            window.destroy()
            return True
        except Exception:
            return False


def run_startup_splash_subprocess(state_path):
    with profile_span("startup_splash.run", state_path=os.path.basename(str(state_path or ""))):
        ensure_ui_crisp_mode()
        hide_console_window()
        webview_module = get_webview_module()
        if webview_module is None or not has_pywebview_support():
            return 1

        screen_width = 1920
        screen_height = 1080
        if os.name == "nt":
            try:
                screen_width = int(ctypes.windll.user32.GetSystemMetrics(0))
                screen_height = int(ctypes.windll.user32.GetSystemMetrics(1))
            except Exception:
                logger.debug("Could not read screen metrics for startup splash sizing.", exc_info=True)
        left, top, right, bottom = get_active_monitor_work_area(screen_width, screen_height)
        work_width = max(1, int(right - left))
        work_height = max(1, int(bottom - top))
        splash_width = min(700, max(430, work_width - 72))
        splash_height = min(560, max(400, work_height - 84))
        splash_width = min(splash_width, work_width)
        splash_height = min(splash_height, work_height)
        splash_x = int(left + max(0, ((right - left) - splash_width) // 2))
        splash_y = int(top + max(0, ((bottom - top) - splash_height) // 2))

        ready_path = Path(state_path).with_name(STARTUP_SPLASH_READY_FILE_NAME)
        bridge = StartupSplashBridge(state_path, ready_path=ready_path)
        close_watcher_stop = Event()
        try:
            window = webview_module.create_window(
                tr("startup.title"),
                html=build_startup_splash_html(),
                js_api=bridge,
                width=splash_width,
                height=splash_height,
                x=splash_x,
                y=splash_y,
                min_size=(500, 380),
                resizable=False,
                hidden=False,
                frameless=True,
                easy_drag=True,
                shadow=True,
                focus=True,
                on_top=False,
                background_color="#0f1b2f",
                text_select=False,
            )
            if window is None:
                return 1
            bridge.bind_window(window)

            def _on_window_shown(*_args, **_kwargs):
                try:
                    splash_hwnd = resolve_webview_window_hwnd(window, title=tr("startup.title"), timeout_seconds=0.0)
                    if splash_hwnd and is_capture_privacy_active():
                        set_window_capture_excluded(splash_hwnd, enabled=True)
                except Exception:
                    logger.debug("Could not apply startup splash capture privacy.", exc_info=True)
                try:
                    place_startup_splash_window(
                        window,
                        tr("startup.title"),
                        splash_x,
                        splash_y,
                        splash_width,
                        splash_height,
                    )
                except Exception:
                    logger.debug("Could not position startup splash window after show.", exc_info=True)
                bridge.notify_ready()

            try:
                window.events.shown += _on_window_shown
            except Exception:
                pass

            def _prepare(window_obj):
                def _close_watcher():
                    last_hidden = False
                    last_mtime_ns = -1
                    state_file = Path(state_path)
                    while not close_watcher_stop.wait(0.20):
                        try:
                            if not state_file.exists():
                                try:
                                    window_obj.destroy()
                                except Exception:
                                    pass
                                break
                            mtime_ns = int(state_file.stat().st_mtime_ns)
                            if mtime_ns == last_mtime_ns:
                                continue
                            last_mtime_ns = mtime_ns
                            payload = json.loads(state_file.read_text(encoding="utf-8"))
                            if not isinstance(payload, dict):
                                continue
                            hidden = bool(payload.get("hidden"))
                            if hidden != last_hidden:
                                last_hidden = hidden
                                try:
                                    if hidden:
                                        window_obj.hide()
                                    else:
                                        window_obj.show()
                                        place_startup_splash_window(
                                            window_obj,
                                            str(payload.get("title") or tr("startup.title")),
                                            splash_x,
                                            splash_y,
                                            splash_width,
                                            splash_height,
                                            attempts=2,
                                            delay_seconds=0.03,
                                        )
                                        bridge.notify_ready()
                                except Exception:
                                    pass
                            if bool(payload.get("close")):
                                try:
                                    window_obj.destroy()
                                except Exception:
                                    pass
                                break
                        except Exception:
                            continue

                Thread(target=_close_watcher, daemon=True).start()
                try:
                    profile_mark("startup_splash.window_show")
                    window_obj.show()
                    place_startup_splash_window(
                        window_obj,
                        tr("startup.title"),
                        splash_x,
                        splash_y,
                        splash_width,
                        splash_height,
                    )
                    bridge.notify_ready()
                except Exception:
                    bridge.close_window()

            webview_module.start(
                _prepare,
                args=(window,),
                **resolve_pywebview_start_kwargs(),
            )
        except Exception:
            logger.warning("Startup splash webview failed.", exc_info=True)
            return 1
        finally:
            close_watcher_stop.set()
        return 0


class WebsiteEyeStartupProgressWindow:
    STAGE_ORDER = STARTUP_PROGRESS_STAGE_ORDER

    def __init__(self):
        self.stage_key = "startup.launching"
        self.hidden = False
        self._visible_started_at = time.monotonic()
        self._state_dir = Path(tempfile.mkdtemp(prefix="eae-startup-splash-"))
        self._state_path = self._state_dir / "state.json"
        self._ready_path = self._state_dir / STARTUP_SPLASH_READY_FILE_NAME
        self._process = None
        self._closed = False
        self._hidden = False
        self._write_state(self.stage_key, close=False)
        try:
            self._spawn_subprocess()
            self._wait_until_ready()
            self.set_stage(self.stage_key)
        except Exception:
            try:
                self.close()
            except Exception:
                pass
            raise

    def _spawn_subprocess(self):
        profile_mark("startup_splash.spawn_subprocess")
        command = [sys.executable]
        if not getattr(sys, "frozen", False):
            command.append(os.path.abspath(__file__))
        command.extend([STARTUP_SPLASH_SUBPROCESS_FLAG, str(self._state_path)])
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self._process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creation_flags,
        )

    def _wait_until_ready(self):
        deadline = time.monotonic() + STARTUP_SPLASH_READY_TIMEOUT_SECONDS
        sleep_seconds = max(0.02, float(STARTUP_SPLASH_READY_POLL_SECONDS))
        while time.monotonic() < deadline:
            if self._ready_path.exists():
                return True
            process = self._process
            if process is not None:
                returncode = process.poll()
                if returncode is not None:
                    logger.debug("Startup splash subprocess exited early with code %s.", returncode)
                    return False
            time.sleep(sleep_seconds)
            sleep_seconds = min(0.25, sleep_seconds * 1.35)
        return False

    def _wait_for_minimum_visible(self):
        remaining = float(STARTUP_SPLASH_MIN_VISIBLE_SECONDS) - (
            time.monotonic() - float(self._visible_started_at)
        )
        if remaining > 0:
            time.sleep(remaining)

    def _write_state(self, stage_key, close=None):
        close_flag = bool(close) if close is not None else False
        payload = {
            "title": tr("startup.title"),
            "stage": tr(stage_key),
            "detail": tr(stage_key.replace("startup.", "startup.detail.")),
            "theme": "dark" if resolve_theme_dark(ui_theme_preference) else "light",
            "hidden": bool(self._hidden),
            "close": close_flag,
        }
        self._state_path.write_text(json.dumps(payload, ensure_ascii=True), encoding="utf-8")

    def set_stage(self, stage_key):
        if stage_key not in self.STAGE_ORDER:
            stage_key = "startup.launching"
        self.stage_key = stage_key
        if self._closed:
            return
        try:
            self._write_state(stage_key, close=False)
        except Exception:
            pass

    def refresh(self):
        if self._closed:
            return
        try:
            if self._process is not None and self._process.poll() is not None:
                self._closed = True
        except Exception:
            pass

    def hide(self):
        self.hidden = True
        self._hidden = True
        if self._closed:
            return
        try:
            self._write_state(self.stage_key, close=False)
        except Exception:
            pass

    def show(self):
        self.hidden = False
        self._hidden = False
        if self._closed:
            return
        try:
            self._write_state(self.stage_key, close=False)
        except Exception:
            pass

    def close(self):
        if self._closed:
            return
        if not self.hidden:
            self._wait_for_minimum_visible()
        self._closed = True
        try:
            self._write_state(self.stage_key, close=True)
        except Exception:
            pass

        process = self._process
        self._process = None
        if process is not None:
            try:
                process.wait(timeout=1.4)
            except Exception:
                try:
                    process.terminate()
                except Exception:
                    pass
                try:
                    process.wait(timeout=0.8)
                except Exception:
                    pass
                try:
                    process.kill()
                    process.wait(timeout=0.6)
                except Exception:
                    pass
        if process is not None:
            try:
                if process.poll() is None and os.name == "nt":
                    subprocess.run(
                        ["taskkill", "/PID", str(int(process.pid)), "/T", "/F"],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False,
                    )
            except Exception:
                pass

        try:
            if self._state_path.exists():
                self._state_path.unlink()
        except Exception:
            pass
        try:
            if self._ready_path.exists():
                self._ready_path.unlink()
        except Exception:
            pass
        try:
            self._state_dir.rmdir()
        except Exception:
            pass


def startup_progress_open():
    global startup_progress_window
    with startup_progress_lock:
        if not startup_loading_screen_enabled:
            return None
        if not has_pywebview_support():
            return None
        if startup_progress_window is None:
            env_theme_raw = os.environ.get("EAE_THEME", "").strip()
            if env_theme_raw:
                apply_ui_theme_preference(env_theme_raw)
            else:
                try:
                    startup_record = load_config_record()
                except Exception:
                    startup_record = {}
                saved_theme = normalize_theme_preference(startup_record.get("ui_theme", ui_theme_preference))
                apply_ui_theme_preference(saved_theme)
            try:
                startup_progress_window = WebsiteEyeStartupProgressWindow()
            except Exception:
                startup_progress_window = None
        return startup_progress_window


def startup_progress_update(stage_key):
    profile_mark("startup.stage", stage=stage_key)
    window = startup_progress_open()
    if window:
        window.set_stage(stage_key)


def startup_progress_hide():
    with startup_progress_lock:
        window = startup_progress_window
    if window:
        window.hide()


def startup_progress_show():
    with startup_progress_lock:
        window = startup_progress_window
    if window:
        window.show()


def startup_progress_close():
    global startup_progress_window
    with startup_progress_lock:
        window = startup_progress_window
        startup_progress_window = None
    if window:
        window.close()

def run_startup_background_task(task, stage_key=None, interval_seconds=0.10):
    if stage_key:
        startup_progress_update(stage_key)
    result = {"value": None, "error": None}
    completed = Event()
    task_name = getattr(task, "__name__", task.__class__.__name__)

    def _runner():
        with profile_span("startup.background_task", task=task_name, stage=stage_key or ""):
            try:
                result["value"] = task()
            except Exception as exc:
                result["error"] = exc
            finally:
                completed.set()

    Thread(target=_runner, daemon=True).start()
    poll_interval = max(0.05, float(interval_seconds or 0.10))
    next_refresh_at = 0.0
    while not completed.wait(poll_interval):
        window = startup_progress_window
        now = time.monotonic()
        if window and now >= next_refresh_at:
            window.refresh()
            next_refresh_at = now + 0.12

    window = startup_progress_window
    if window:
        window.refresh()
    if result["error"] is not None:
        raise result["error"]
    return result["value"]


def show_styled_message(title, message, is_error=False, ask_retry=False, parent=None):
    return show_native_dialog(title, message, is_error=is_error, ask_retry=ask_retry, parent=parent)


WEBVIEW_RESIZE_HIT_TESTS = {
    "n": HTTOP,
    "s": HTBOTTOM,
    "e": HTRIGHT,
    "w": HTLEFT,
    "ne": HTTOPRIGHT,
    "nw": HTTOPLEFT,
    "se": HTBOTTOMRIGHT,
    "sw": HTBOTTOMLEFT,
}


def _coerce_hwnd_value(candidate):
    if candidate is None:
        return 0
    for attr_name in ("ToInt64", "ToInt32"):
        method = getattr(candidate, attr_name, None)
        if callable(method):
            try:
                value = int(method())
                if value > 0:
                    return value
            except Exception:
                pass
    try:
        value = int(candidate)
        if value > 0:
            return value
    except Exception:
        pass
    return 0


def is_valid_window_handle(hwnd):
    if os.name != "nt":
        return False
    try:
        value = int(hwnd or 0)
        return bool(value and _user32.IsWindow(wintypes.HWND(value)))
    except Exception:
        return False


def get_top_level_window_handle(hwnd):
    if os.name != "nt":
        return 0
    try:
        normalized = int(hwnd or 0)
        if not normalized:
            return 0
        top_level = int(_user32.GetAncestor(wintypes.HWND(normalized), GA_ROOT) or 0)
        candidate = top_level if top_level else normalized
        if is_valid_window_handle(candidate):
            return int(candidate)
    except Exception:
        pass
    return 0


def get_window_text_safe(hwnd, timeout_ms=50, max_chars=512):
    if os.name != "nt":
        return ""
    try:
        normalized_hwnd = int(hwnd or 0)
        if not normalized_hwnd:
            return ""
        buffer = ctypes.create_unicode_buffer(max(2, int(max_chars or 512)))
        result = DWORD_PTR()
        success = _user32.SendMessageTimeoutW(
            wintypes.HWND(normalized_hwnd),
            WM_GETTEXT,
            wintypes.WPARAM(len(buffer)),
            ctypes.cast(buffer, ctypes.c_void_p),
            SMTO_ABORTIFHUNG,
            max(1, int(timeout_ms or 50)),
            ctypes.byref(result),
        )
        if not success:
            return ""
        return str(buffer.value or "").strip()
    except Exception:
        return ""


def get_window_title(hwnd):
    return get_window_text_safe(hwnd, timeout_ms=50, max_chars=512)


def cache_webview_window_hwnd(window, hwnd):
    try:
        normalized = int(hwnd or 0)
    except Exception:
        normalized = 0
    if not normalized or not is_valid_window_handle(normalized):
        return 0
    try:
        setattr(window, "_eae_hwnd_cache", int(normalized))
    except Exception:
        pass
    return int(normalized)


def get_cached_webview_window_hwnd(window):
    try:
        cached = int(getattr(window, "_eae_hwnd_cache", 0) or 0)
    except Exception:
        cached = 0
    if cached and is_valid_window_handle(cached):
        return int(cached)
    return 0


def capture_webview_window_hwnd(window, title=""):
    hwnd = get_cached_webview_window_hwnd(window)
    if hwnd:
        return int(hwnd)
    hwnd = extract_native_window_handle(window, max_depth=3)
    if not hwnd:
        hwnd = extract_native_window_handle(getattr(window, "native", None), max_depth=4)
    if not hwnd:
        hwnd = find_webview_window_hwnd(title or getattr(window, "title", ""), process_id=os.getpid())
    if hwnd:
        hwnd = get_top_level_window_handle(hwnd) or int(hwnd)
    if hwnd and is_valid_window_handle(hwnd):
        return cache_webview_window_hwnd(window, hwnd)
    return 0


def extract_native_window_handle(obj, max_depth=2):
    if os.name != "nt" or obj is None:
        return 0
    seen = set()
    queue = [(obj, 0)]
    follow_attrs = ("Handle", "handle", "hwnd", "Hwnd", "window", "Window", "form", "Form", "native", "Native")
    while queue:
        candidate, depth = queue.pop(0)
        if candidate is None:
            continue
        candidate_id = id(candidate)
        if candidate_id in seen:
            continue
        seen.add(candidate_id)
        hwnd = _coerce_hwnd_value(candidate)
        if hwnd and is_valid_window_handle(hwnd):
            return hwnd
        if depth >= int(max_depth):
            continue
        for attr_name in follow_attrs:
            try:
                nested = getattr(candidate, attr_name, None)
            except Exception:
                nested = None
            if nested is not None:
                queue.append((nested, depth + 1))
    return 0


def find_webview_window_hwnd(title, process_id=None):
    if os.name != "nt":
        return 0
    target_title = str(title or "").strip()
    target_pid = int(process_id or os.getpid())
    exact_matches = []
    partial_matches = []
    try:
        @WNDENUMPROC
        def _collect(hwnd, _lparam):
            try:
                normalized_hwnd = int(hwnd or 0)
                if not normalized_hwnd:
                    return True
                window_pid = wintypes.DWORD(0)
                _user32.GetWindowThreadProcessId(wintypes.HWND(normalized_hwnd), ctypes.byref(window_pid))
                if target_pid and int(window_pid.value or 0) != target_pid:
                    return True
                window_title = get_window_title(normalized_hwnd)
                if target_title:
                    if window_title == target_title:
                        exact_matches.append(normalized_hwnd)
                    elif target_title.lower() in window_title.lower():
                        partial_matches.append(normalized_hwnd)
                elif window_title:
                    partial_matches.append(normalized_hwnd)
            except Exception:
                return True
            return True

        _user32.EnumWindows(_collect, 0)
    except Exception:
        logger.debug("Auth window enumeration failed.", exc_info=True)
    if exact_matches:
        return int(exact_matches[-1])
    if partial_matches:
        return int(partial_matches[-1])
    try:
        fallback_hwnd = int(_user32.FindWindowW(None, target_title) or 0)
        if fallback_hwnd:
            return fallback_hwnd
    except Exception:
        logger.debug("Auth window title lookup failed.", exc_info=True)
    return 0


def resolve_webview_window_hwnd(window, title="", timeout_seconds=0.0):
    if os.name != "nt":
        return 0
    hwnd = capture_webview_window_hwnd(window, title=title)
    if hwnd or float(timeout_seconds or 0.0) <= 0.0:
        return int(hwnd or 0)
    deadline = time.monotonic() + max(0.0, float(timeout_seconds or 0.0))
    while True:
        hwnd = capture_webview_window_hwnd(window, title=title)
        if hwnd:
            return int(hwnd)
        if time.monotonic() >= deadline:
            return 0
        time.sleep(0.03)


def get_native_window_bounds(hwnd):
    if os.name != "nt":
        return None
    try:
        normalized_hwnd = int(hwnd or 0)
        if not normalized_hwnd:
            return None
        top_level = int(_user32.GetAncestor(wintypes.HWND(normalized_hwnd), GA_ROOT) or 0)
        if top_level:
            normalized_hwnd = top_level
        rect = wintypes.RECT()
        if not _user32.GetWindowRect(wintypes.HWND(normalized_hwnd), ctypes.byref(rect)):
            return None
        width = int(max(1, rect.right - rect.left))
        height = int(max(1, rect.bottom - rect.top))
        return int(rect.left), int(rect.top), width, height
    except Exception:
        logger.debug("Could not read native window bounds.", exc_info=True)
        return None


def position_native_window(hwnd, x, y, width, height, *, on_top=False):
    if os.name != "nt":
        return False
    try:
        normalized_hwnd = int(hwnd or 0)
        if not normalized_hwnd or not is_valid_window_handle(normalized_hwnd):
            return False
        left = int(x)
        top = int(y)
        target_width = max(320, int(width))
        target_height = max(240, int(height))
        insert_after = wintypes.HWND(HWND_TOPMOST if on_top else 0)
        flags = SWP_NOACTIVATE | SWP_SHOWWINDOW
        applied = bool(
            _user32.SetWindowPos(
                wintypes.HWND(normalized_hwnd),
                insert_after,
                left,
                top,
                target_width,
                target_height,
                flags,
            )
        )
        if not applied:
            applied = bool(
                _user32.MoveWindow(
                    wintypes.HWND(normalized_hwnd),
                    left,
                    top,
                    target_width,
                    target_height,
                    True,
                )
            )
        return applied
    except Exception:
        logger.debug("Native window positioning failed.", exc_info=True)
        return False


def move_native_window(hwnd, x, y, *, on_top=False):
    if os.name != "nt":
        return False
    try:
        normalized_hwnd = int(hwnd or 0)
        if not normalized_hwnd or not is_valid_window_handle(normalized_hwnd):
            return False
        left = int(x)
        top = int(y)
        insert_after = wintypes.HWND(HWND_TOPMOST if on_top else 0)
        flags = SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW
        return bool(
            _user32.SetWindowPos(
                wintypes.HWND(normalized_hwnd),
                insert_after,
                left,
                top,
                0,
                0,
                flags,
            )
        )
    except Exception:
        logger.debug("Native window move failed.", exc_info=True)
        return False


def run_auth_shell_automated_selftest(bridge, result_path):
    output = {
        "move": False,
        "maximize": False,
        "drag_region_enabled": False,
        "hwnd": 0,
        "before_move": None,
        "after_move": None,
        "after_maximize": None,
        "restored_bounds": None,
        "expected_work_area": None,
        "errors": [],
    }
    try:
        time.sleep(0.45)
        hwnd = int(bridge._get_hwnd() or 0)
        output["hwnd"] = hwnd
        if not hwnd:
            output["errors"].append("Could not resolve auth window handle.")
        else:
            before_move = get_native_window_bounds(hwnd)
            output["before_move"] = before_move
            if before_move:
                target_left = int(before_move[0] + 180)
                target_top = int(before_move[1] + 110)
                if bridge._window is not None:
                    deadline = time.time() + 3.0
                    while time.time() < deadline:
                        try:
                            js_ready = bridge._window.evaluate_js(
                                "Boolean(window.pywebview && typeof window.pywebview._jsApiCallback === 'function')"
                            )
                        except Exception:
                            js_ready = False
                        if js_ready:
                            break
                        time.sleep(0.08)
                    else:
                        output["errors"].append("Auth shell JS bridge did not become ready.")
                    try:
                        output["drag_region_enabled"] = bool(
                            bridge._window.evaluate_js(
                                "Boolean(document.getElementById('windowDragZone') && document.getElementById('windowDragZone').classList.contains('pywebview-drag-region'))"
                            )
                        )
                    except Exception:
                        output["drag_region_enabled"] = False
                    try:
                        bridge._window.evaluate_js(
                            f"window.pywebview._jsApiCallback('pywebviewMoveWindow', [{target_left}, {target_top}], 'move')"
                        )
                    except Exception as exc:
                        output["errors"].append(f"Drag callback failed: {exc}")
                time.sleep(0.35)
                after_move = get_native_window_bounds(hwnd)
                output["after_move"] = after_move
                if after_move:
                    output["move"] = bool(
                        int(after_move[0]) != int(before_move[0]) or int(after_move[1]) != int(before_move[1])
                    )

            toggled = bool(bridge.toggle_maximize())
            time.sleep(0.35)
            after_maximize = get_native_window_bounds(hwnd)
            output["after_maximize"] = after_maximize
            screen_width = 1920
            screen_height = 1080
            if os.name == "nt":
                try:
                    screen_width = int(ctypes.windll.user32.GetSystemMetrics(0))
                    screen_height = int(ctypes.windll.user32.GetSystemMetrics(1))
                except Exception:
                    pass
            work_left, work_top, work_right, work_bottom = get_window_monitor_work_area(hwnd, screen_width, screen_height)
            output["expected_work_area"] = (
                int(work_left),
                int(work_top),
                int(max(1, work_right - work_left)),
                int(max(1, work_bottom - work_top)),
            )
            if toggled and after_maximize:
                output["maximize"] = bool(
                    abs(int(after_maximize[0]) - int(work_left)) <= 2
                    and abs(int(after_maximize[1]) - int(work_top)) <= 2
                    and abs(int(after_maximize[2]) - int(work_right - work_left)) <= 2
                    and abs(int(after_maximize[3]) - int(work_bottom - work_top)) <= 2
                )
            if bridge._manual_maximized:
                bridge.toggle_maximize()
                time.sleep(0.2)
            output["restored_bounds"] = get_native_window_bounds(hwnd)
    except Exception as exc:
        output["errors"].append(str(exc))
    finally:
        try:
            Path(result_path).write_text(json.dumps(output, ensure_ascii=True), encoding="utf-8")
        except Exception:
            pass
        try:
            bridge.close()
        except Exception:
            pass


def place_startup_splash_window(window, title, x, y, width, height, attempts=5, delay_seconds=0.05):
    normalized_title = str(title or "").strip()
    applied = False
    hwnd = resolve_webview_window_hwnd(window, title=normalized_title, timeout_seconds=0.0)
    if hwnd:
        applied = bool(position_native_window(hwnd, x, y, width, height, on_top=True))
    if not applied:
        try:
            if hasattr(window, "resize"):
                window.resize(int(width), int(height))
            if hasattr(window, "move"):
                window.move(int(x), int(y))
        except Exception:
            pass
    return applied

class AuthShellBridge:
    def __init__(self):
        self._window = None
        self._result = None
        self._done = Event()
        self._closing = False
        self._manual_maximized = False
        self._normal_bounds = None
        self._hwnd_cache = 0
        self._initial_state = {}
        self._import_preview = None
        self._corner_radius = 20
        self._drag_active = False
        self._drag_origin = (0, 0)
        self._drag_window_origin = (0, 0)
        self._drag_window_size = (0, 0)
        self._drag_hwnd = 0
        self._drag_last_position = None
        self._corner_refresh_lock = Lock()
        self._corner_refresh_timer = None

    def bind_window(self, window):
        self._window = window
        try:
            if self._window is not None:
                self._window.events.closed += self._on_closed
                self._window.events.shown += self._on_window_shown
                self._window.events.maximized += self._on_window_maximized
                self._window.events.resized += self._on_window_geometry_changed
                self._window.events.restored += self._on_window_geometry_changed
        except Exception:
            pass

    @property
    def result(self):
        return self._result

    def wait(self, timeout=None):
        self._done.wait(timeout)
        return self._result

    def _on_closed(self, *args, **kwargs):
        self._cancel_corner_refresh_timer()
        self._window = None
        self._done.set()

    def _capture_hwnd(self):
        if self._window is None:
            return 0
        hwnd = capture_webview_window_hwnd(
            self._window,
            title=getattr(self._window, "title", ""),
        )
        if hwnd:
            self._hwnd_cache = int(hwnd)
            return int(hwnd)
        return 0

    def _cancel_corner_refresh_timer(self):
        with self._corner_refresh_lock:
            timer = self._corner_refresh_timer
            self._corner_refresh_timer = None
        if timer is not None:
            try:
                timer.cancel()
            except Exception:
                pass

    def schedule_native_corner_refresh(self, delay_ms=100, immediate=False):
        if immediate:
            self._cancel_corner_refresh_timer()
            try:
                self.refresh_native_corners()
            except Exception:
                pass
            return

        timer = None

        def _run():
            with self._corner_refresh_lock:
                if self._corner_refresh_timer is not timer:
                    return
                self._corner_refresh_timer = None
            try:
                self.refresh_native_corners()
            except Exception:
                pass

        new_timer = threading.Timer(max(0.01, float(delay_ms or 100) / 1000.0), _run)
        new_timer.daemon = True
        with self._corner_refresh_lock:
            previous = self._corner_refresh_timer
            self._corner_refresh_timer = new_timer
            timer = new_timer
        if previous is not None:
            try:
                previous.cancel()
            except Exception:
                pass
        new_timer.start()

    def _on_window_shown(self, *args, **kwargs):
        self._capture_hwnd()
        self.schedule_native_corner_refresh(immediate=True)
        try:
            self.ensure_capture_privacy()
        except Exception:
            pass

    def _on_window_geometry_changed(self, *args, **kwargs):
        self._capture_hwnd()
        self.schedule_native_corner_refresh(delay_ms=100)

    def _on_window_maximized(self, *args, **kwargs):
        self._manual_maximized = True
        self._capture_hwnd()
        self.schedule_native_corner_refresh(immediate=True)

    def _get_hwnd(self):
        if is_valid_window_handle(self._hwnd_cache):
            return int(self._hwnd_cache)
        hwnd = self._capture_hwnd()
        if hwnd:
            self._hwnd_cache = int(hwnd)
            return int(hwnd)
        return 0

    def ensure_capture_privacy(self):
        if not is_capture_privacy_active():
            return True
        hwnd = self._get_hwnd()
        if not hwnd:
            return False
        return bool(set_window_capture_excluded(hwnd, enabled=True))

    def refresh_native_corners(self):
        hwnd = self._get_hwnd()
        if not hwnd or self._window is None:
            return False
        try:
            width = int(getattr(self._window, "width", 0) or 0)
            height = int(getattr(self._window, "height", 0) or 0)
        except Exception:
            width = 0
            height = 0
        if width <= 1 or height <= 1:
            return False
        radius = 0 if self._manual_maximized else int(self._corner_radius)
        return bool(apply_hwnd_corner_region(hwnd, width, height, radius))

    def submit(self, payload):
        with profile_span("auth_bridge.submit"):
            if not isinstance(payload, dict):
                return {"ok": False, "error": "Invalid setup payload."}
            hotkeys, hotkey_mode, hotkeys_customized = resolve_command_hotkey_state(
                payload.get("hotkeys"),
                payload.get("hotkey_mode", command_key_mode),
            )
            normalized = {
                "mode": "account",
                "language": normalize_language(payload.get("language", ui_language)),
                "theme": normalize_theme_preference(payload.get("theme", ui_theme_preference)),
                "blob_size": normalize_indicator_blob_size(payload.get("blob_size", indicator_blob_size_key)),
                "indicator_position": normalize_indicator_position(payload.get("indicator_position", indicator_position_key)),
                "show_startup_screen": normalize_startup_loading_screen_enabled(payload.get("show_startup_screen", startup_loading_screen_enabled)),
                "preferred_model": normalize_pro_model(payload.get("preferred_model", payload.get("pro_model", selected_pro_model_key))),
                "hotkeys": hotkeys,
                "hotkey_mode": hotkey_mode,
                "hotkeys_customized": bool(hotkeys_customized),
                "email": normalize_account_email(payload.get("email", "")),
                "password": str(payload.get("password", "") or ""),
                "remember_me": normalize_remember_me_preference(payload.get("remember_me", False)),
            }
            normalized["pro_model"] = normalized["preferred_model"]
            preview_snapshot = None
            if isinstance(self._import_preview, dict):
                preview_snapshot = self._import_preview.get("auth_snapshot")
            if isinstance(preview_snapshot, dict):
                if (
                    normalize_account_email(preview_snapshot.get("email", "")) == normalized["email"]
                    and str(preview_snapshot.get("password", "") or "") == normalized["password"]
                ):
                    normalized["auth_snapshot"] = preview_snapshot
            self._result = normalized
            self.close()
            return {"ok": True}

    def import_settings(self, payload):
        with profile_span("auth_bridge.import_settings"):
            if not isinstance(payload, dict):
                return {"ok": False, "error": "Invalid setup payload."}
            ok, result = request_account_preferences_preview(
                payload.get("email", ""),
                password_value=str(payload.get("password", "") or ""),
                live_session_token=self._initial_state.get("live_session_token", ""),
                live_session_email=self._initial_state.get("live_session_email", ""),
            )
            if not ok:
                return {"ok": False, "error": str(result or "Could not import the synced settings.")}
            self._import_preview = result if isinstance(result, dict) else None
            return {
                "ok": True,
                "preferences": dict((result or {}).get("preferences") or {}),
            }

    def record_ui_action(self, name):
        profile_mark("auth.ui_action", name=str(name or "").strip())
        return True

    def close(self):
        profile_mark("auth_bridge.close")
        if self._closing:
            self._done.set()
            return True
        self._closing = True
        self._cancel_corner_refresh_timer()
        window = self._window
        self._window = None
        try:
            if window is not None:
                window.destroy()
        except Exception:
            pass
        self._done.set()
        return True

    def exit_app(self):
        profile_mark("auth_bridge.exit_app")
        if AUTH_SHELL_SUBPROCESS_FLAG in sys.argv:
            self._result = {"__action__": "exit_app"}
            self.close()
            return True
        self.close()
        exit_program(trigger_uninstall=False)
        return True

    def minimize(self):
        profile_mark("auth_bridge.minimize")
        try:
            if self._window is not None:
                self._window.minimize()
        except Exception:
            return False
        return True

    def toggle_maximize(self):
        profile_mark("auth_bridge.toggle_maximize")
        try:
            if self._window is None:
                return False
            hwnd = self._get_hwnd()
            if self._manual_maximized and self._normal_bounds:
                x, y, width, height = self._normal_bounds
                try:
                    self._window.restore()
                except Exception:
                    pass
                restored = False
                if hwnd:
                    restored = position_native_window(hwnd, x, y, width, height)
                if not restored:
                    self._window.resize(int(width), int(height))
                    self._window.move(int(x), int(y))
                self._manual_maximized = False
                self.refresh_native_corners()
                return False

            native_bounds = get_native_window_bounds(hwnd) if hwnd else None
            if native_bounds:
                self._normal_bounds = native_bounds
            else:
                self._normal_bounds = (
                    int(self._window.x),
                    int(self._window.y),
                    int(self._window.width),
                    int(self._window.height),
                )
            screen_width = 0
            screen_height = 0
            try:
                screen_width = int(getattr(getattr(self._window, "screen", None), "width", 0) or 0)
                screen_height = int(getattr(getattr(self._window, "screen", None), "height", 0) or 0)
            except Exception:
                screen_width = 0
                screen_height = 0
            if screen_width <= 0 or screen_height <= 0:
                screen_width = 1920
                screen_height = 1080
                if os.name == "nt":
                    try:
                        screen_width = int(ctypes.windll.user32.GetSystemMetrics(0))
                        screen_height = int(ctypes.windll.user32.GetSystemMetrics(1))
                    except Exception:
                        pass
            left, top, right, bottom = get_window_monitor_work_area(hwnd, screen_width, screen_height)
            target_width = int(max(320, right - left))
            target_height = int(max(240, bottom - top))
            applied = False
            if hwnd:
                applied = position_native_window(hwnd, left, top, target_width, target_height)
            if not applied:
                self._window.move(int(left), int(top))
                self._window.resize(target_width, target_height)
            self._manual_maximized = True
            self.refresh_native_corners()
            return True
        except Exception:
            logger.exception("Auth window maximize toggle failed.")
            return False

    def start_move(self):
        profile_mark("auth_bridge.start_move")
        if self._window is None:
            return False
        if self._manual_maximized and self._normal_bounds:
            try:
                x, y, width, height = self._normal_bounds
                self._window.restore()
                self._window.resize(int(width), int(height))
                self._window.move(int(x), int(y))
                self._manual_maximized = False
                self.refresh_native_corners()
            except Exception:
                logger.exception("Auth window restore before move failed.")
                return False
        hwnd = self._get_hwnd()
        if not hwnd:
            return False
        try:
            _user32.SetForegroundWindow(wintypes.HWND(int(hwnd)))
        except Exception:
            pass
        lparam = 0
        try:
            point = wintypes.POINT()
            if _user32.GetCursorPos(ctypes.byref(point)):
                lparam = ((int(point.y) & 0xFFFF) << 16) | (int(point.x) & 0xFFFF)
        except Exception:
            lparam = 0
        try:
            _user32.ReleaseCapture()
            _user32.SendMessageW(wintypes.HWND(int(hwnd)), WM_SYSCOMMAND, SC_MOVE | HTCAPTION, lparam)
            return True
        except Exception:
            try:
                _user32.PostMessageW(wintypes.HWND(int(hwnd)), WM_NCLBUTTONDOWN, HTCAPTION, lparam)
                return True
            except Exception:
                logger.exception("Auth window move dispatch failed.")
                return False

    def begin_window_drag(self, screen_x=0, screen_y=0):
        if self._window is None:
            return False
        if self._manual_maximized and self._normal_bounds:
            try:
                x, y, width, height = self._normal_bounds
                self._window.restore()
                self._window.resize(int(width), int(height))
                self._window.move(int(x), int(y))
                self._manual_maximized = False
                self.refresh_native_corners()
            except Exception:
                logger.exception("Auth window restore before manual drag failed.")
                return False
        hwnd = self._get_hwnd()
        bounds = get_native_window_bounds(hwnd) if hwnd else None
        if bounds is not None:
            left, top, width, height = bounds
        else:
            try:
                left = int(getattr(self._window, "x", 0) or 0)
                top = int(getattr(self._window, "y", 0) or 0)
                width = int(getattr(self._window, "width", 0) or 0)
                height = int(getattr(self._window, "height", 0) or 0)
            except Exception:
                return False
        pointer_x = int(screen_x or 0)
        pointer_y = int(screen_y or 0)
        if pointer_x == 0 and pointer_y == 0:
            try:
                point = wintypes.POINT()
                if _user32.GetCursorPos(ctypes.byref(point)):
                    pointer_x = int(point.x)
                    pointer_y = int(point.y)
            except Exception:
                pass
        self._drag_origin = (pointer_x, pointer_y)
        self._drag_window_origin = (int(left), int(top))
        self._drag_window_size = (int(width), int(height))
        self._drag_hwnd = int(hwnd or 0)
        self._drag_last_position = None
        self._drag_active = True
        return True

    def update_window_drag(self, screen_x=0, screen_y=0):
        if not self._drag_active:
            return False
        pointer_x = int(screen_x or 0)
        pointer_y = int(screen_y or 0)
        origin_x, origin_y = self._drag_origin
        window_x, window_y = self._drag_window_origin
        width, height = self._drag_window_size
        next_x = int(window_x + (pointer_x - origin_x))
        next_y = int(window_y + (pointer_y - origin_y))
        if self._drag_last_position == (next_x, next_y):
            return True
        hwnd = int(self._drag_hwnd or 0)
        if not hwnd:
            hwnd = self._get_hwnd()
            self._drag_hwnd = int(hwnd or 0)
        applied = False
        if hwnd:
            applied = bool(move_native_window(hwnd, next_x, next_y))
            if not applied:
                applied = bool(position_native_window(hwnd, next_x, next_y, width, height))
        if not applied:
            try:
                if self._window is not None:
                    self._window.move(int(next_x), int(next_y))
                    applied = True
            except Exception:
                applied = False
        if applied:
            self._drag_last_position = (next_x, next_y)
        return applied

    def end_window_drag(self):
        self._drag_active = False
        self._drag_hwnd = 0
        self._drag_last_position = None
        return True

    def start_resize(self, edge):
        profile_mark("auth_bridge.start_resize", edge=str(edge or "").strip().lower())
        direction = str(edge or "").strip().lower()
        hit_test = WEBVIEW_RESIZE_HIT_TESTS.get(direction)
        if not hit_test or self._window is None:
            return False
        if self._manual_maximized and self._normal_bounds:
            try:
                x, y, width, height = self._normal_bounds
                self._window.resize(int(width), int(height))
                self._window.move(int(x), int(y))
                self._manual_maximized = False
            except Exception:
                logger.exception("Auth window restore before resize failed.")
                return False
        hwnd = self._get_hwnd()
        if not hwnd:
            return False
        def _dispatch_resize():
            try:
                time.sleep(0.01)
                _user32.ReleaseCapture()
                _user32.SendMessageW(wintypes.HWND(int(hwnd)), WM_NCLBUTTONDOWN, hit_test, 0)
            except Exception:
                logger.exception("Auth window resize dispatch failed for edge '%s'.", direction)

        Thread(target=_dispatch_resize, daemon=True, name=f"auth-window-resize-{direction or 'edge'}").start()
        return True

    def read_clipboard(self):
        try:
            return str(pyperclip.paste() or "")
        except Exception:
            return ""

    def open_external(self, url):
        profile_mark("auth_bridge.open_external")
        target = str(url or "").strip()
        if not target:
            return False
        try:
            parsed = urlparse(target)
        except Exception:
            return False
        if parsed.scheme not in {"http", "https"}:
            logger.warning("open_external blocked non-http(s) URL scheme: %s", parsed.scheme)
            return False
        try:
            return bool(webbrowser.open(target, new=2))
        except Exception:
            return False


def build_auth_shell_html(initial_state):
    bootstrap = {
        "translations": TRANSLATIONS,
        "initialState": dict(initial_state),
        "hotkeyActionIds": list(HOTKEY_ACTION_ORDER),
        "allowedHotkeys": {
            key: dict(value)
            for key, value in ALLOWED_HOTKEY_BINDINGS.items()
            if not is_reserved_system_hotkey_binding(key)
        },
        "defaultNumpadHotkeys": get_default_command_hotkeys("numpad"),
        "sizeIds": list(INDICATOR_BLOB_SIZES.keys()),
        "positionIds": list(INDICATOR_POSITIONS.keys()),
        "positionPoints": dict(INDICATOR_PREVIEW_POINTS),
        "proModels": list(get_pro_model_options()),
        "websiteUrl": DEFAULT_WEBSITE_URL,
        "dashboardUrl": f"{str(DEFAULT_WEBSITE_URL).rstrip('/')}/dashboard.php#dashboard-app-access",
        "tutorialUrl": f"{str(DEFAULT_WEBSITE_URL).rstrip('/')}/#features",
        "forgotPasswordUrl": f"{str(DEFAULT_WEBSITE_URL).rstrip('/')}/forgot-password.php",
        "themeDark": bool(system_dark_theme_enabled),
    }
    template = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root {
      --bg0: #050a14;
      --bg1: #08101d;
      --bg2: #111a2c;
      --glass: rgba(22,31,49,0.74);
      --glass-strong: rgba(16,24,39,0.86);
      --border: rgba(100,128,182,0.18);
      --text: #edf3ff;
      --muted: #aab8d4;
      --primary: #4b80ff;
      --danger: #ff9898;
      --radius-xl: 34px;
      --radius-lg: 28px;
      --radius-md: 20px;
      --font: "Segoe UI Variable Text", "Segoe UI", sans-serif;
      --brand-eye-width: 166px;
      --brand-eye-height: 90px;
      --brand-eye-iris-size: 44px;
      --brand-eye-pupil-size: 14px;
      --badge-blink-duration: 6.2s;
      --badge-bob-duration: 4.6s;
      --badge-glance-duration: 1.9s;
      --badge-look-x: 0px;
      --badge-look-y: 0px;
      --star-core: rgba(116, 162, 241, 0.96);
      --star-tail: rgba(116, 162, 241, 0);
      --star-glow: rgba(179, 209, 255, 0.8);
    }
    body.theme-light {
      --bg0: #e7eef8;
      --bg1: #dbe6f3;
      --bg2: #f4f8ff;
      --glass: rgba(255,255,255,0.76);
      --glass-strong: rgba(255,255,255,0.88);
      --border: rgba(16,42,86,0.10);
      --text: #102a56;
      --muted: #5a6e90;
      --primary: #1459d9;
      --danger: #ba1a1a;
      --star-core: rgba(58, 109, 226, 0.96);
      --star-tail: rgba(58, 109, 226, 0);
      --star-glow: rgba(105, 155, 255, 0.92);
    }
    * { box-sizing: border-box; }
    html, body {
      margin: 0;
      min-height: 100%;
      font-family: var(--font);
      color: var(--text);
      background:
        radial-gradient(circle at 12% 12%, rgba(34, 73, 147, 0.22), transparent 24%),
        radial-gradient(circle at 74% 84%, rgba(45, 90, 181, 0.14), transparent 28%),
        linear-gradient(180deg, var(--bg0), var(--bg1));
    }
    body {
      padding: 0;
      overflow: hidden;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .window-shell {
      width: 100%;
      height: 100vh;
      min-height: 100vh;
      background:
        radial-gradient(circle at 14% 14%, rgba(31, 67, 132, 0.34), transparent 26%),
        radial-gradient(circle at 78% 18%, rgba(32, 74, 155, 0.18), transparent 30%),
        linear-gradient(180deg, rgba(10, 15, 28, 0.98), rgba(13, 20, 35, 0.96));
      border: none;
      box-shadow: none;
      backdrop-filter: none;
      border-radius: 0;
      overflow: hidden;
      position: relative;
      display: flex;
      flex-direction: column;
    }
    body.window-maximized .window-shell {
      width: 100%;
      max-width: none;
      height: 100vh;
      min-height: 100vh;
      border-radius: 0;
      border: none;
      box-shadow: none;
    }
    .window-shell::before {
      content: "";
      position: absolute;
      inset: 0;
      pointer-events: none;
      background:
        radial-gradient(circle at 24% 0%, rgba(132, 164, 234, 0.08), transparent 22%),
        linear-gradient(180deg, rgba(255,255,255,0.02), transparent 30%);
      z-index: 0;
    }
    body.theme-light .window-shell {
      background:
        radial-gradient(circle at 14% 14%, rgba(114, 179, 255, 0.24), transparent 26%),
        radial-gradient(circle at 78% 18%, rgba(160, 212, 255, 0.14), transparent 30%),
        linear-gradient(180deg, rgba(248,252,255,0.98), rgba(227,238,248,0.96));
    }
    body.theme-light .window-status,
    body.theme-light .chrome-control,
    body.theme-light .card,
    body.theme-light .actions .ghost {
      background: rgba(255,255,255,0.74);
    }
    body.theme-light .hero {
      background:
        radial-gradient(circle at 14% 18%, rgba(114, 179, 255, 0.22), transparent 34%),
        linear-gradient(180deg, rgba(255, 255, 255, 0.12), rgba(255, 255, 255, 0));
    }
    body.theme-light .hero-wordmark {
      color: #2956c7;
    }
    .window-shell > * {
      position: relative;
      z-index: 1;
    }
    .window-bar {
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      justify-content: space-between;
      gap: 12px;
      min-height: 64px;
      padding: 16px 24px 14px;
      border-bottom: 1px solid rgba(255,255,255,0.06);
      background: linear-gradient(180deg, rgba(255,255,255,0.04), rgba(255,255,255,0));
    }
    .window-drag-zone {
      min-width: 0;
      flex: 1 1 auto;
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
      user-select: none;
      cursor: grab;
    }
    .window-brand {
      display: flex;
      align-items: center;
      gap: 12px;
      min-width: 0;
    }
    .window-brand-link,
    .hero-title-link {
      padding: 0;
      border: none;
      background: transparent;
      color: inherit;
      font: inherit;
      text-align: left;
      cursor: pointer;
      transition: color 180ms ease, transform 180ms ease, text-shadow 180ms ease;
    }
    .window-brand-link {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      min-width: 0;
      max-width: 100%;
      border-radius: 12px;
    }
    .window-brand-link:hover,
    .window-brand-link:focus-visible,
    .hero-title-link:hover,
    .hero-title-link:focus-visible {
      color: #7fb6ff;
      text-shadow: 0 0 18px rgba(91, 162, 255, 0.26);
      transform: translateY(-1px);
      outline: none;
    }
    .window-drag-fill {
      min-width: 28px;
      flex: 1 1 auto;
      align-self: stretch;
      cursor: grab;
    }
    .window-drag-zone:active,
    .window-status:active,
    .window-drag-fill:active {
      cursor: grabbing;
    }
    .window-caption {
      font-size: 14px;
      font-weight: 700;
      letter-spacing: 0.01em;
      overflow-wrap: anywhere;
    }
    .window-status {
            display: none;
      align-items: center;
      justify-content: center;
      min-width: 0;
      flex: 0 1 360px;
      max-width: min(100%, 360px);
      padding: 9px 15px;
      border-radius: 999px;
      background: rgba(27,39,63,0.84);
      border: 1px solid var(--border);
      color: var(--muted);
      font-size: 12px;
      text-align: center;
      overflow-wrap: anywhere;
      cursor: grab;
    }
    .window-controls {
      display: flex;
      align-items: center;
      justify-content: flex-end;
      flex-wrap: wrap;
      gap: 8px;
      flex: 0 0 auto;
      max-width: 100%;
    }
    .chrome-control {
      width: 38px;
      height: 38px;
      border-radius: 16px;
      border: 1px solid var(--border);
      background: rgba(29,41,67,0.72);
      color: var(--text);
      cursor: pointer;
      font-size: 16px;
      transition: 180ms ease;
    }
    .chrome-control:hover {
      background: rgba(255,255,255,0.14);
      transform: translateY(-1px);
    }
    .chrome-control.close:hover {
      background: rgba(255,108,108,0.18);
      border-color: rgba(255,108,108,0.34);
    }
    .chrome-control.active {
      background: rgba(59,140,255,0.18);
      border-color: rgba(120,183,255,0.48);
    }
    .app {
      min-height: 0;
      flex: 1 1 auto;
      display: grid;
      grid-template-columns: minmax(420px, 1.08fr) minmax(420px, 0.92fr);
      overflow: hidden;
      align-items: stretch;
    }
    body.window-maximized .app {
      grid-template-columns: minmax(520px, 1.14fr) minmax(500px, 0.86fr);
    }
    .hero, .panel { min-height: 0; min-width: 0; padding: 34px 38px 32px; }
    body.window-maximized .hero,
    body.window-maximized .panel {
      padding: 42px 48px 40px;
    }
    .hero {
      position: relative;
      border-right: 1px solid rgba(255,255,255,0.08);
      display: flex;
      flex-direction: column;
    gap: 20px;
      justify-content: flex-start;
      overflow: hidden;
      background:
        radial-gradient(circle at 14% 18%, rgba(54, 89, 163, 0.26), transparent 34%),
        linear-gradient(180deg, rgba(8, 13, 24, 0.18), rgba(8, 13, 24, 0));
    }
    .hero > * {
      position: relative;
      z-index: 1;
    }
    .hero-brand-stage {
      position: relative;
      width: fit-content;
      min-height: auto;
      display: flex;
      flex-direction: column;
      align-items: flex-start;
      gap: 10px;
      padding: 0;
      border: none;
      background: none;
      overflow: visible;
    }
    body.window-maximized .hero-brand-stage {
      transform: scale(1.08);
      transform-origin: top left;
    }
    .hero-stars {
      position: absolute;
      inset: -12% -16% -8% 26%;
      overflow: hidden;
      pointer-events: none;
      opacity: 0.82;
      z-index: 0;
      mask-image: radial-gradient(circle at 44% 44%, rgba(0, 0, 0, 1) 34%, rgba(0, 0, 0, 0.78) 66%, transparent 100%);
      -webkit-mask-image: radial-gradient(circle at 44% 44%, rgba(0, 0, 0, 1) 34%, rgba(0, 0, 0, 0.78) 66%, transparent 100%);
    }
    body.window-maximized .hero-stars {
      inset: -10% -10% -6% 18%;
    }
    .hero-night {
      --hero-shoot-time: 3600ms;
      position: absolute;
      inset: -40% -18%;
      opacity: 0.5;
      transform: rotateZ(34deg);
    }
    .hero-shooting-star {
      position: absolute;
      left: 50%;
      top: 50%;
      width: 0;
      height: 2px;
      background: linear-gradient(-45deg, var(--star-core), var(--star-tail));
      border-radius: 999px;
      animation:
        hero-tail var(--hero-shoot-time) ease-in-out infinite,
        hero-shooting var(--hero-shoot-time) ease-in-out infinite;
    }
    .hero-shooting-star:nth-child(n+7) {
      display: none;
    }
    .hero-shooting-star::before,
    .hero-shooting-star::after {
      content: "";
      position: absolute;
      top: calc(50% - 1px);
      right: 0;
      height: 2px;
      background: linear-gradient(-45deg, var(--star-tail), var(--star-core), var(--star-tail));
      border-radius: 100%;
      animation: hero-shining var(--hero-shoot-time) ease-in-out infinite;
      animation-delay: inherit;
    }
    .hero-shooting-star::before {
      transform: translateX(50%) rotateZ(45deg);
    }
    .hero-shooting-star::after {
      transform: translateX(50%) rotateZ(-45deg);
    }
    .hero-shooting-star:nth-child(1) { top: calc(50% - 162px); left: calc(50% - 190px); animation-delay: 0ms; }
    .hero-shooting-star:nth-child(2) { top: calc(50% - 124px); left: calc(50% - 36px); animation-delay: 340ms; }
    .hero-shooting-star:nth-child(3) { top: calc(50% - 86px); left: calc(50% + 128px); animation-delay: 760ms; }
    .hero-shooting-star:nth-child(4) { top: calc(50% - 24px); left: calc(50% - 250px); animation-delay: 1120ms; }
    .hero-shooting-star:nth-child(5) { top: calc(50% + 18px); left: calc(50% + 182px); animation-delay: 1560ms; }
    .hero-shooting-star:nth-child(6) { top: calc(50% + 58px); left: calc(50% - 144px); animation-delay: 1940ms; }
    .hero-shooting-star:nth-child(7) { top: calc(50% + 100px); left: calc(50% + 42px); animation-delay: 2360ms; }
    .hero-shooting-star:nth-child(8) { top: calc(50% + 138px); left: calc(50% - 222px); animation-delay: 2820ms; }
    .hero-shooting-star:nth-child(9) { top: calc(50% - 188px); left: calc(50% + 230px); animation-delay: 620ms; }
    .hero-shooting-star:nth-child(10) { top: calc(50% - 56px); left: calc(50% + 280px); animation-delay: 1280ms; }
    .hero-shooting-star:nth-child(11) { top: calc(50% + 156px); left: calc(50% + 150px); animation-delay: 1820ms; }
    .hero-shooting-star:nth-child(12) { top: calc(50% + 182px); left: calc(50% - 20px); animation-delay: 2460ms; }
    @keyframes hero-tail {
      0% { width: 0; }
      30% { width: 100px; }
      100% { width: 0; }
    }
    @keyframes hero-shining {
      0% { width: 0; }
      50% { width: 30px; }
      100% { width: 0; }
    }
    @keyframes hero-shooting {
      0% { transform: translateX(0); }
      100% { transform: translateX(300px); }
    }
    .eye-loader {
      position: relative;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: calc(var(--brand-eye-width) + 36px);
      height: calc(var(--brand-eye-height) + 36px);
      padding: 16px;
      border-radius: 999px;
      background: transparent;
      user-select: none;
      isolation: isolate;
      transform-origin: center;
      -webkit-tap-highlight-color: transparent;
    }
    .eye-loader::before {
      content: "";
      position: absolute;
      inset: 0;
      z-index: 0;
      border-radius: inherit;
      background:
        radial-gradient(circle at 50% 50%, rgba(58, 118, 242, 0.40) 0%, rgba(58, 118, 242, 0.12) 44%, rgba(58, 118, 242, 0) 78%),
        radial-gradient(circle at 50% 50%, rgba(196, 220, 255, 0.10), transparent 74%);
      filter: blur(10px);
      opacity: 0.72;
    }
    .eye-loader .brand-eye {
      position: relative;
      z-index: 1;
      display: block;
      width: var(--brand-eye-width);
      height: var(--brand-eye-height);
      filter: none;
    }
    .eye-loader .brand-eye-shell {
      position: absolute;
      inset: 0;
      overflow: hidden;
      border-radius: 999px;
      background: linear-gradient(180deg, rgba(140, 180, 255, 0.98), rgba(74, 122, 226, 0.98));
      box-shadow:
        0 0 0 1px rgba(235, 243, 255, 0.26) inset,
        0 16px 24px rgba(14, 54, 128, 0.18),
        inset 0 -7px 10px rgba(19, 58, 137, 0.18);
    }
    .hero-wordmark {
      margin-left: 18px;
      font-size: 14px;
      font-weight: 800;
      letter-spacing: 0.11em;
      color: #3d67df;
      text-transform: uppercase;
    }
    .eye-loader .brand-eye-sclera,
    .eye-loader .brand-eye-lid {
      position: absolute;
      inset: 6px;
      border-radius: 999px;
    }
    .eye-loader .brand-eye-sclera {
      overflow: hidden;
      background:
        radial-gradient(circle at 50% 50%, rgba(249, 252, 255, 0.99), rgba(226, 237, 255, 0.98) 62%, rgba(172, 198, 249, 0.96) 100%),
        linear-gradient(180deg, #fbfdff, #e4efff);
      box-shadow:
        inset 0 -3px 8px rgba(96, 136, 221, 0.18),
        inset 0 1px 0 rgba(255, 255, 255, 0.66);
    }
    .eye-loader .brand-eye-sclera::before,
    .eye-loader .brand-eye-sclera::after {
      content: "";
      position: absolute;
      top: 50%;
      width: 18px;
      height: 18px;
      border-radius: 50%;
      background: radial-gradient(circle at 40% 35%, rgba(236, 243, 255, 0.98), rgba(204, 220, 252, 0.96));
      transform: translateY(-50%);
    }
    .eye-loader .brand-eye-sclera::before { left: -8px; }
    .eye-loader .brand-eye-sclera::after { right: -8px; }
    .eye-loader .brand-eye-iris {
      position: absolute;
      top: 50%;
      left: 50%;
      width: var(--brand-eye-iris-size);
      height: var(--brand-eye-iris-size);
      border-radius: 50%;
      background: radial-gradient(circle at 35% 28%, #8dccff 0%, #5c95ff 28%, #3a63d8 56%, #243c93 78%, #16214e 100%);
      box-shadow:
        inset 0 0 0 3px rgba(205, 226, 255, 0.34),
        0 0 0 1px rgba(34, 64, 149, 0.18),
        0 0 24px rgba(56, 113, 241, 0.28);
      transform: translate(calc(-50% + var(--badge-look-x)), calc(-50% + var(--badge-look-y)));
      transition: transform var(--badge-glance-duration) cubic-bezier(0.25, 0.85, 0.25, 1);
    }
    .eye-loader .brand-eye-pupil {
      position: absolute;
      top: 50%;
      left: 50%;
      width: var(--brand-eye-pupil-size);
      height: var(--brand-eye-pupil-size);
      border-radius: 50%;
      background: #13204b;
      transform: translate(-50%, -50%);
      box-shadow:
        0 0 0 3px rgba(24, 39, 86, 0.24),
        inset 0 1px 2px rgba(255, 255, 255, 0.08);
    }
    .eye-loader .brand-eye-pupil::after {
      content: "";
      position: absolute;
      top: 2px;
      left: 2px;
      width: 4px;
      height: 4px;
      border-radius: 50%;
      background: rgba(255, 255, 255, 0.95);
    }
    .eye-loader .brand-eye-highlight {
      position: absolute;
      left: 24%;
      top: 16%;
      width: 30%;
      height: 16%;
      border-radius: 999px;
      background: linear-gradient(180deg, rgba(255, 255, 255, 0.88), rgba(255, 255, 255, 0));
      opacity: 0.82;
      pointer-events: none;
    }
    .eye-loader .brand-eye-lid {
      background: linear-gradient(180deg, rgba(120, 165, 255, 0.98), rgba(79, 118, 215, 0.98) 58%, rgba(201, 221, 255, 0.94) 100%);
      box-shadow: inset 0 -3px 6px rgba(21, 56, 131, 0.22);
      transform-origin: center top;
      transform: translateY(-104%) scaleY(1);
    }
    @keyframes dashboardBadgeBob {
      0% { transform: translate3d(0, 0, 0) scale(1); }
      50% { transform: translate3d(0, -1px, 0) scale(1.01); }
      100% { transform: translate3d(0, 0, 0) scale(1); }
    }
    @keyframes dashboardBadgeBlink {
      0%, 43%, 49%, 100% { transform: translateY(-104%) scaleY(1); }
      45%, 47% { transform: translateY(0) scaleY(1.02); }
    }
    @keyframes dashboardBadgeSquish {
      0%, 43%, 49%, 100% { transform: scale(1); }
      45% { transform: scale(0.95, 0.74); }
      47% { transform: scale(0.97, 0.86); }
    }
        @keyframes authEyeFloat {
            0% { transform: translateY(0px); }
            50% { transform: translateY(-2px); }
            100% { transform: translateY(0px); }
        }
        .auth-eye-loader {
            animation: authEyeFloat 5.2s ease-in-out infinite;
        }
    .hero-copy {
      display: flex;
      flex-direction: column;
      gap: 12px;
      max-width: 620px;
            margin-top: 12px;
    }
    body.window-maximized .hero-copy {
      max-width: 760px;
            margin-top: 20px;
    }
    h1 {
      margin: 0;
      font-size: clamp(48px, 5.8vw, 74px);
      line-height: 1;
      letter-spacing: -0.04em;
    }
    .hero-title-link {
      width: fit-content;
      max-width: 100%;
      font-size: clamp(48px, 5.8vw, 74px);
      line-height: 0.98;
      letter-spacing: -0.04em;
      font-weight: 700;
    }
    .hero-title-link #title {
      display: block;
    }
    .subtitle { margin: 0; color: var(--muted); max-width: 620px; font-size: 17px; line-height: 1.45; }
    body.window-maximized .subtitle {
      max-width: 760px;
      font-size: 18px;
    }
    .subtitle,
    .hero-copy,
    .settings-summary,
    .main-card {
      min-width: 0;
    }
    .card {
            background:
                linear-gradient(180deg, rgba(255,255,255,0.12), rgba(255,255,255,0.05)),
                rgba(25, 36, 58, 0.58);
            border: 1px solid rgba(173, 202, 255, 0.18);
      border-radius: var(--radius-lg);
      padding: 16px;
            box-shadow:
                inset 0 1px 0 rgba(255,255,255,0.22),
                0 16px 34px rgba(4, 12, 26, 0.24);
            backdrop-filter: saturate(150%) blur(14px);
            -webkit-backdrop-filter: saturate(150%) blur(14px);
    }
        body.theme-light .card {
            background:
                linear-gradient(180deg, rgba(255,255,255,0.72), rgba(255,255,255,0.56)),
                rgba(233, 242, 252, 0.58);
            border: 1px solid rgba(125, 157, 208, 0.24);
        }
    .settings-summary {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
    }
    .settings-summary .selection-value {
      font-size: 14px;
      line-height: 1.45;
      color: var(--muted);
      font-weight: 600;
      letter-spacing: 0;
    }
    .settings-open-button {
      flex: 0 0 auto;
      min-width: 118px;
    }
    .modes { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
    .mode {
      cursor: pointer;
      transition: 180ms ease;
    }
        .mode:hover {
            transform: translateY(-1px);
            border-color: rgba(120,183,255,0.44);
        }
    .mode.active {
      border-color: rgba(120,183,255,0.52);
      background: linear-gradient(180deg, rgba(59,140,255,0.18), rgba(38, 55, 88, 0.86));
      transform: translateY(-1px);
      box-shadow: 0 16px 36px rgba(14,34,66,0.24);
    }
    .mode h3, .section { margin: 0 0 4px; font-size: 15px; }
    .mode p, .helper, .hint { margin: 0; color: var(--muted); font-size: 13px; line-height: 1.45; }
    .section { font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; color: #d5e2f7; }
    .panel { display: flex; flex-direction: column; gap: 14px; justify-content: center; overflow: auto; padding-bottom: 24px; }
    .main-card {
      display: flex;
      flex-direction: column;
      gap: 12px;
      width: min(100%, 520px);
      margin: 0 auto;
    }
    body.window-maximized .main-card,
    body.window-maximized .actions {
      width: min(100%, 680px);
    }
    .auth-panel {
      display: flex;
      flex-direction: column;
      gap: 0;
    }
    .label { display: block; margin-bottom: 8px; font-weight: 700; font-size: 13px; }
    .segment-wrap, .sizes {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }
    .segment-wrap {
      padding: 8px;
      border-radius: 999px;
      background: var(--glass);
      border: 1px solid var(--border);
      width: fit-content;
    }
    button, select, input {
      font: inherit;
      color: inherit;
    }
    input, textarea, select {
      -webkit-user-select: text;
      user-select: text;
      cursor: text;
    }
    .segment, .pill, .ghost, .primary {
      border: 1px solid var(--border);
      border-radius: 999px;
      background: transparent;
      color: var(--text);
      padding: 10px 14px;
      cursor: pointer;
      transition: 180ms ease;
    }
    .segment.active, .pill.active {
      background: rgba(59,140,255,0.18);
      border-color: rgba(120,183,255,0.56);
      box-shadow: 0 12px 26px rgba(14,34,66,0.26);
    }
    .ghost { background: rgba(255,255,255,0.06); }
    .primary {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      background: linear-gradient(180deg, #54a2ff, #1d6deb);
      border-color: rgba(120,183,255,0.56);
      box-shadow: 0 18px 36px rgba(26,92,205,0.35);
    }
    .primary:disabled,
    .ghost:disabled,
    .segment:disabled,
    .pill:disabled {
      cursor: default;
      opacity: 0.78;
      transform: none !important;
    }
    .primary.loading {
      box-shadow: 0 18px 36px rgba(26,92,205,0.28);
    }
    .button-spinner {
      width: 16px;
      height: 16px;
      display: none;
      border-radius: 999px;
      border: 2px solid rgba(255,255,255,0.28);
      border-top-color: rgba(255,255,255,0.96);
      animation: authSpin 820ms linear infinite;
      flex: 0 0 auto;
    }
    .primary.loading .button-spinner {
      display: inline-block;
    }
    @keyframes authSpin {
      from { transform: rotate(0deg); }
      to { transform: rotate(360deg); }
    }
    .field {
      min-width: 0;
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 11px 13px;
      border-radius: var(--radius-md);
      background: rgba(255,255,255,0.08);
      border: 1px solid var(--border);
    }
    .field input, .field select {
      width: 100%;
      min-width: 0;
      border: none;
      background: transparent;
      outline: none;
    }
        /* Hide Edge/WebView native password reveal/clear controls. */
        input[type="password"]::-ms-reveal,
        input[type="password"]::-ms-clear {
            display: none;
            width: 0;
            height: 0;
        }
    .field.icon-field {
      position: relative;
      padding-right: 86px;
    }
    .field-actions {
      position: absolute;
      top: 50%;
      right: 8px;
      display: flex;
      gap: 6px;
      transform: translateY(-50%);
    }
    .icon-button {
      width: 34px;
      height: 34px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border-radius: 18px;
      border: 1px solid rgba(255,255,255,0.08);
      background: rgba(255,255,255,0.06);
      color: var(--text);
      cursor: pointer;
      transition: 180ms ease;
    }
    .icon-button:hover {
      background: rgba(255,255,255,0.14);
      transform: translateY(-1px);
    }
    .icon-button svg,
    .chrome-control svg {
      width: 18px;
      height: 18px;
      stroke: currentColor;
      fill: none;
      stroke-linecap: round;
      stroke-linejoin: round;
      pointer-events: none;
    }
    .field select option { color: #081321; }
    .selection-value {
      font-size: 17px;
      font-weight: 700;
      letter-spacing: -0.02em;
    }
    .preview {
      min-height: 268px;
      position: relative;
      border-radius: 24px;
      background:
        radial-gradient(circle at 24% 18%, rgba(109,239,197,0.14), transparent 26%),
        linear-gradient(160deg, rgba(14,32,61,0.96), rgba(8,19,33,0.96));
      border: 1px solid var(--border);
      overflow: hidden;
    }
    .preview::before {
      content: "";
      position: absolute;
      inset: 18px;
      border-radius: 24px;
      border: 1px solid rgba(255,255,255,0.06);
      background:
        linear-gradient(180deg, rgba(255,255,255,0.02), transparent),
        radial-gradient(circle at 50% 50%, rgba(255,255,255,0.03), transparent 60%);
    }
    .preview-grid {
      position: absolute;
      inset: 18px;
      border-radius: 24px;
      background-image:
        linear-gradient(to right, rgba(255,255,255,0.05) 1px, transparent 1px),
        linear-gradient(to bottom, rgba(255,255,255,0.05) 1px, transparent 1px);
      background-size: calc(100% / 6) calc(100% / 4);
      opacity: 0.26;
      pointer-events: none;
    }
    .preview-hotspots {
      position: absolute;
      inset: 22px;
    }
    .hotspot {
      position: absolute;
      width: 26px;
      height: 26px;
      border-radius: 999px;
      border: 1px solid rgba(189,211,243,0.52);
      background: rgba(255,255,255,0.02);
      box-shadow: inset 0 0 0 5px rgba(0,0,0,0.18);
      cursor: pointer;
      transform: translate(-50%, -50%);
      transition: 180ms ease;
    }
    .hotspot:hover {
      border-color: rgba(255,255,255,0.82);
      transform: translate(-50%, -50%) scale(1.06);
    }
    .hotspot.active {
      border-color: rgba(34,208,93,0.84);
      background: rgba(34,208,93,0.12);
      box-shadow:
        inset 0 0 0 6px rgba(0,0,0,0.28),
        0 0 22px rgba(34,208,93,0.22);
    }
    .preview-chip {
      position: absolute;
      width: 24px;
      height: 24px;
      border-radius: 8px;
      background: rgba(99,106,116,0.98);
      border: 1px solid rgba(152,160,171,0.92);
      box-shadow: 0 6px 14px rgba(0,0,0,0.22);
      transition:
        left 220ms ease,
        top 220ms ease,
        background-color 180ms ease,
        border-color 180ms ease,
        box-shadow 180ms ease;
      z-index: 2;
    }
    .input-link-row {
      display: flex;
      flex-wrap: wrap;
      gap: 10px 14px;
      margin-top: 10px;
    }
    .text-link {
      padding: 0;
      border: none;
      background: transparent;
      color: var(--muted);
      cursor: pointer;
      text-decoration: underline;
      text-underline-offset: 3px;
    }
    .text-link:hover {
      color: var(--text);
    }
    .inline-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 12px;
    }
    .inline-actions .ghost {
      min-width: 0;
      padding: 10px 16px;
      border-radius: 16px;
      font-weight: 700;
    }
    .remember-toggle.active {
      background: rgba(59,140,255,0.18);
      border-color: rgba(120,183,255,0.56);
      box-shadow: 0 12px 26px rgba(14,34,66,0.18);
    }
    .model-options {
      display: grid;
      gap: 10px;
      margin-top: 14px;
    }
    .model-option {
      width: 100%;
      display: grid;
      gap: 4px;
      text-align: left;
      padding: 14px 16px;
      border-radius: 18px;
      border: 1px solid var(--border);
      background: rgba(255,255,255,0.05);
      color: var(--text);
      cursor: pointer;
      transition: 180ms ease;
    }
    .model-option:hover {
      transform: translateY(-1px);
      background: rgba(255,255,255,0.08);
    }
    .model-option.active {
      background: linear-gradient(180deg, rgba(59,140,255,0.22), rgba(20,39,69,0.92));
      border-color: rgba(120,183,255,0.58);
      box-shadow: 0 16px 30px rgba(14,34,66,0.24);
    }
    .model-option-title {
      font-size: 14px;
      font-weight: 700;
      letter-spacing: -0.01em;
    }
    .model-option-copy {
      font-size: 12px;
      color: var(--muted);
      line-height: 1.45;
    }
    .hotkey-list {
      display: grid;
      gap: 10px;
      margin-top: 14px;
    }
    .hotkey-row {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 12px;
      align-items: center;
      padding: 12px 14px;
      border-radius: 18px;
      background: rgba(255,255,255,0.05);
      border: 1px solid var(--border);
    }
    .hotkey-row-label {
      font-size: 13px;
      font-weight: 600;
      color: var(--text);
    }
    .hotkey-button {
      min-width: 88px;
      padding: 9px 14px;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: rgba(255,255,255,0.08);
      color: var(--text);
      font-weight: 700;
      cursor: pointer;
      transition: 180ms ease;
    }
    .hotkey-button:hover,
    .hotkey-button.waiting {
      background: rgba(59,140,255,0.18);
      border-color: rgba(120,183,255,0.56);
      box-shadow: 0 12px 26px rgba(14,34,66,0.26);
    }
    .hotkey-feedback {
      min-height: 20px;
    }
        .actions {
            display: flex;
            justify-content: center;
      flex-wrap: wrap;
      gap: 10px;
      margin: 0 auto;
      width: min(100%, 520px);
      padding-top: 4px;
    }
    .actions .ghost,
    .actions .primary {
      min-width: 142px;
      padding: 12px 20px;
      border-radius: 22px;
      font-weight: 700;
    }
    .actions .ghost {
      background: rgba(255,255,255,0.04);
    }
    .actions .ghost:hover {
      background: rgba(255,255,255,0.11);
    }
    .error {
      min-height: 20px;
      color: var(--danger);
      font-weight: 600;
      font-size: 13px;
    }
    .settings-backdrop {
      position: absolute;
      inset: 0;
      background: rgba(2, 8, 18, 0.46);
      opacity: 0;
      pointer-events: none;
      transition: opacity 180ms ease;
      z-index: 15;
    }
    .settings-backdrop.open {
      opacity: 1;
      pointer-events: auto;
    }
    .settings-drawer {
      position: absolute;
      top: 92px;
      right: 18px;
      bottom: 18px;
      width: min(420px, calc(100% - 36px));
      padding: 18px;
      border-radius: 28px;
      border: 1px solid var(--border);
      background: linear-gradient(180deg, rgba(8,19,33,0.96), rgba(14,32,61,0.94));
      box-shadow: 0 20px 44px rgba(0,0,0,0.28);
      backdrop-filter: none;
      display: flex;
      flex-direction: column;
      gap: 14px;
      transform: translateX(calc(100% + 24px));
      opacity: 0;
      pointer-events: none;
      transition: transform 220ms ease, opacity 220ms ease;
      z-index: 20;
    }
    @media (prefers-reduced-motion: reduce), (update: slow) {
      .hero-shooting-star,
      .hero-shooting-star::before,
      .hero-shooting-star::after,
    .auth-eye-loader,
      .eye-loader .brand-eye,
      .eye-loader .brand-eye-shell,
      .eye-loader .brand-eye-lid {
        animation: none !important;
      }
      .settings-backdrop,
      .settings-drawer,
      .preview-chip {
        transition-duration: 0ms !important;
      }
    }
    body.theme-light .settings-drawer {
      background: linear-gradient(180deg, rgba(248,252,255,0.97), rgba(227,238,248,0.95));
    }
    .settings-drawer.open {
      transform: translateX(0);
      opacity: 1;
      pointer-events: auto;
    }
    .settings-head {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 14px;
    }
    .settings-body {
      min-height: 0;
      overflow: auto;
      display: flex;
      flex-direction: column;
      gap: 14px;
      padding-right: 2px;
    }
    .resize-handle {
      position: absolute;
      z-index: 35;
      background: transparent;
    }
    .resize-handle.n,
    .resize-handle.s {
      left: 14px;
      right: 14px;
      height: 10px;
      cursor: ns-resize;
    }
    .resize-handle.n { top: 0; }
    .resize-handle.s { bottom: 0; }
    .resize-handle.e,
    .resize-handle.w {
      top: 14px;
      bottom: 14px;
      width: 10px;
      cursor: ew-resize;
    }
    .resize-handle.e { right: 0; }
    .resize-handle.w { left: 0; }
    .resize-handle.ne,
    .resize-handle.nw,
    .resize-handle.se,
    .resize-handle.sw {
      width: 16px;
      height: 16px;
    }
    .resize-handle.ne {
      top: 0;
      right: 0;
      cursor: nesw-resize;
    }
    .resize-handle.nw {
      top: 0;
      left: 0;
      cursor: nwse-resize;
    }
    .resize-handle.se {
      right: 0;
      bottom: 0;
      cursor: nwse-resize;
    }
    .resize-handle.sw {
      left: 0;
      bottom: 0;
      cursor: nesw-resize;
    }
    .hidden { display: none !important; }
    @media (max-height: 760px) {
      body { padding: 0; }
      .window-shell {
        height: 100vh;
        min-height: 100vh;
      }
      .hero, .panel {
        padding: 26px 28px 24px;
      }
      .hero-title-link {
        font-size: clamp(40px, 5.2vw, 60px);
      }
      .subtitle {
        font-size: 15px;
      }
      .hero-shooting-star:nth-child(11),
      .hero-shooting-star:nth-child(12) {
        display: none;
      }
    }
    @media (max-width: 1120px) {
      body { padding: 0; }
      .window-shell { height: 100vh; min-height: 100vh; }
      .window-bar {
        flex-wrap: wrap;
        justify-content: flex-start;
      }
      .window-status {
        order: 3;
        width: 100%;
      }
      .window-controls {
        margin-left: auto;
      }
      .app { grid-template-columns: 1fr; }
      .hero { border-right: none; border-bottom: 1px solid rgba(255,255,255,0.08); }
      .hero { overflow: hidden; }
      .hero-brand-stage { width: min(100%, 420px); }
      .modes { grid-template-columns: 1fr; }
      .preview { min-height: 224px; }
      .actions .ghost,
      .actions .primary {
        flex: 1 1 180px;
      }
      .settings-summary {
        flex-direction: column;
        align-items: stretch;
      }
      .settings-open-button {
        width: 100%;
      }
      .settings-drawer {
        top: 84px;
        left: 14px;
        right: 14px;
        bottom: 14px;
        width: auto;
      }
    }
    @media (max-width: 760px), (max-height: 640px) {
      body { padding: 0; }
      .window-shell {
        width: 100%;
        height: 100vh;
        min-height: 100vh;
        border-radius: 0;
      }
      .window-bar {
        gap: 12px;
        min-height: 0;
        padding: 12px 16px 10px;
      }
      .window-controls {
        width: 100%;
      }
      .chrome-control {
        width: 36px;
        height: 36px;
        border-radius: 12px;
      }
      .hero-stars {
        inset: 18px 0 0 20%;
      }
      .hero,
      .panel {
        padding: 18px 18px 16px;
      }
      .hero-title-link {
        font-size: clamp(36px, 12vw, 54px);
      }
      .hero-wordmark {
        margin-left: 10px;
        font-size: 12px;
      }
      .window-status {
        padding: 8px 12px;
        font-size: 11px;
      }
      .preview {
        min-height: 190px;
      }
      .hotkey-row {
        grid-template-columns: 1fr;
      }
      .hotkey-button {
        width: 100%;
      }
      .actions {
        margin-left: 0;
      }
      .actions .ghost,
      .actions .primary {
        flex: 1 1 100%;
        min-width: 0;
      }
      .inline-actions .ghost {
        flex: 1 1 100%;
      }
      .text-link {
        max-width: 100%;
        text-align: left;
      }
      .settings-drawer {
        top: 112px;
        left: 10px;
        right: 10px;
        bottom: 10px;
        padding: 14px;
        border-radius: 24px;
      }
    }
  </style>
</head>
  <body class="theme-dark">
  <div class="window-shell">
    <header class="window-bar">
      <div class="window-drag-zone pywebview-drag-region" id="windowDragZone">
        <button class="window-brand-link" id="windowBrandLink" type="button">
          <div class="window-caption" id="windowCaption"></div>
        </button>
        <div class="window-status" id="windowStatus"></div>
        <div class="window-drag-fill pywebview-drag-region" id="windowDragFill"></div>
      </div>
      <div class="window-controls">
        <button class="chrome-control" id="settingsToggleButton" type="button" aria-label="Settings"></button>
        <button class="chrome-control" id="minimizeButton" type="button" aria-label="Minimize"></button>
        <button class="chrome-control" id="maximizeButton" type="button" aria-label="Maximize"></button>
        <button class="chrome-control close" id="closeChromeButton" type="button" aria-label="Close"></button>
      </div>
    </header>
    <main class="app">
      <section class="hero">
        <div class="hero-stars" aria-hidden="true">
          <div class="hero-night">
            <span class="hero-shooting-star"></span>
            <span class="hero-shooting-star"></span>
            <span class="hero-shooting-star"></span>
            <span class="hero-shooting-star"></span>
            <span class="hero-shooting-star"></span>
            <span class="hero-shooting-star"></span>
            <span class="hero-shooting-star"></span>
            <span class="hero-shooting-star"></span>
            <span class="hero-shooting-star"></span>
            <span class="hero-shooting-star"></span>
            <span class="hero-shooting-star"></span>
            <span class="hero-shooting-star"></span>
          </div>
        </div>
        <div class="hero-brand-stage" aria-hidden="true">
          <div class="eye-loader auth-eye-loader" data-brand-eye>
            <span class="brand-eye" aria-hidden="true">
              <span class="brand-eye-shell">
                <span class="brand-eye-sclera">
                  <span class="brand-eye-iris">
                    <span class="brand-eye-pupil"></span>
                  </span>
                </span>
                <span class="brand-eye-highlight"></span>
                <span class="brand-eye-lid"></span>
              </span>
            </span>
          </div>
        </div>
        <div class="hero-copy">
          <button class="hero-title-link" id="titleButton" type="button"><span id="title"></span></button>
        </div>
        <div class="modes">
                    <article class="card mode" id="modeDashboardCard"><h3 id="modeDashboardTitle"></h3><p id="modeDashboardHelp"></p></article>
                    <article class="card mode" id="modeTutorialCard"><h3 id="modeTutorialTitle"></h3><p id="modeTutorialHelp"></p></article>
        </div>
        <div class="card settings-summary">
          <div>
            <div class="section" id="settingsSummaryTitle"></div>
            <div class="selection-value" id="settingsSummaryValue"></div>
          </div>
          <button class="ghost settings-open-button" id="openSettingsButton" type="button"></button>
        </div>
      </section>
      <section class="panel">
        <div class="card main-card">
          <div class="section" id="accountTitle"></div>
          <div class="auth-panel" id="accountPanel">
          <label class="label" id="emailLabel"></label>
          <div class="field">
            <input id="emailInput" type="email" autocomplete="username email" spellcheck="false">
          </div>
          <label class="label" id="passwordLabel" style="margin-top: 14px;"></label>
          <div class="field icon-field">
            <input id="passwordInput" type="password" autocomplete="current-password" spellcheck="false">
            <div class="field-actions">
              <button class="icon-button" id="showButton" type="button"></button>
            </div>
          </div>
          <div class="inline-actions">
            <button class="ghost" id="importSettingsButton" type="button"></button>
            <button class="ghost remember-toggle" id="rememberMeButton" type="button"></button>
          </div>
          </div>
        </div>
        <div class="error" id="errorText"></div>
        <div class="actions">
          <button class="ghost" id="cancelButton" type="button"></button>
          <button class="primary" id="continueButton" type="button">
            <span class="button-spinner" id="continueSpinner"></span>
            <span id="continueButtonLabel"></span>
          </button>
        </div>
      </section>
    </main>
    <div class="settings-backdrop" id="settingsBackdrop"></div>
    <aside class="settings-drawer" id="settingsDrawer" aria-hidden="true">
      <div class="settings-head">
        <div>
          <div class="section" id="settingsPanelTitle"></div>
          <p class="helper" id="settingsPanelCopy" style="margin-top: 6px;"></p>
        </div>
        <button class="ghost" id="settingsDoneButton" type="button"></button>
      </div>
      <div class="settings-body">
        <div class="card">
          <div class="section" id="languageTitle"></div>
          <div class="segment-wrap" id="languageButtons"></div>
        </div>
        <div class="card">
          <div class="section" id="startupSectionTitle"></div>
          <label class="label" id="startupScreenLabel"></label>
          <p class="helper" id="startupScreenCopy" style="margin-bottom: 12px;"></p>
          <button class="pill" id="startupScreenToggle" type="button"></button>
        </div>
        <div class="card">
          <div class="section" id="previewTitle"></div>
          <div class="selection-value" id="positionValue" style="margin: 4px 0 14px;"></div>
          <div class="preview" id="previewSurface">
            <div class="preview-grid"></div>
            <div class="preview-hotspots" id="positionButtons"></div>
            <div class="preview-chip" id="previewChip"></div>
          </div>
          <p class="hint" id="previewCopy" style="margin-top: 12px;"></p>
        </div>
        <div class="card">
          <div class="section" id="appearanceTitle"></div>
          <label class="label" id="themeTitle"></label>
          <div class="segment-wrap" id="themeButtons"></div>
          <p class="helper" id="themeCopy" style="margin: 12px 0 14px;"></p>
          <label class="label" id="sizeTitle"></label>
          <div class="sizes" id="sizeButtons"></div>
        </div>
        <div class="card">
          <div class="section" id="hotkeysTitle"></div>
          <p class="helper" id="hotkeysCopy"></p>
          <div class="actions" style="justify-content: flex-start; margin: 12px 0 0; padding-top: 0;">
            <button class="ghost" id="hotkeysResetButton" type="button" style="min-width: 0; padding: 10px 16px;"></button>
          </div>
          <div class="hotkey-list" id="hotkeyList"></div>
          <p class="helper hotkey-feedback" id="hotkeysFeedback" style="margin-top: 12px;"></p>
          <p class="helper" id="securityCopy" style="margin-top: 12px;"></p>
        </div>
        <div class="card" id="modelSettingsCard">
          <div class="section" id="proSectionTitle"></div>
          <label class="label" id="modelLabel"></label>
          <input id="modelSelect" type="hidden" value="">
          <div class="model-options" id="modelOptions"></div>
          <p class="helper" id="modelNote" style="margin-top: 12px;"></p>
        </div>
      </div>
    </aside>
    <div class="resize-handle n" data-edge="n"></div>
    <div class="resize-handle s" data-edge="s"></div>
    <div class="resize-handle e" data-edge="e"></div>
    <div class="resize-handle w" data-edge="w"></div>
    <div class="resize-handle ne" data-edge="ne"></div>
    <div class="resize-handle nw" data-edge="nw"></div>
    <div class="resize-handle se" data-edge="se"></div>
    <div class="resize-handle sw" data-edge="sw"></div>
  </div>
  <script>
    /*__BOOTSTRAP__*/
    const bootstrap = window.AUTH_BOOTSTRAP || {};
    const copy = bootstrap.translations || {};
    const state = Object.assign({
      language: 'en',
      theme: 'system',
      blob_size: 'medium',
      indicator_position: 'bottom_right',
      show_startup_screen: true,
      hotkeys: {},
      hotkey_mode: 'numpad',
      preferred_model: '',
      pro_model: '',
      email: '',
      password: '',
      remember_me: false,
    allow_cancel: false,
      live_session_email: '',
      live_session_token: '',
      error_message: ''
    }, bootstrap.initialState || {});
    const hotkeyActionIds = bootstrap.hotkeyActionIds || [];
    const allowedHotkeys = bootstrap.allowedHotkeys || {};
    const defaultNumpadHotkeys = bootstrap.defaultNumpadHotkeys || {};
    const sizeIds = bootstrap.sizeIds || [];
    const positionIds = bootstrap.positionIds || [];
    const positionPoints = bootstrap.positionPoints || {};
    const proModels = bootstrap.proModels || [];
    const websiteUrl = bootstrap.websiteUrl || '';
    const dashboardUrl = bootstrap.dashboardUrl || websiteUrl;
    const tutorialUrl = bootstrap.tutorialUrl || 'https://eyesandears-platform-vercel.vercel.app/#features';
    const forgotPasswordUrl = bootstrap.forgotPasswordUrl || websiteUrl;
    let themeDark = !!bootstrap.themeDark;
    let closePending = false;
    let settingsOpen = false;
    let awaitingHotkeyAction = '';
    let hotkeyFeedbackKey = 'auth.hotkeys.copy';
    let windowMaximized = false;
    let isSubmitting = false;
    const themeMedia = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;

    function t(key, vars) {
      let text = (((copy[state.language] || {})[key]) || ((copy.en || {})[key]) || key);
      if (vars) Object.keys(vars).forEach((name) => { text = text.replaceAll(`{${name}}`, String(vars[name])); });
      return text;
    }

    function setText(id, value) {
      const node = document.getElementById(id);
      if (node) node.textContent = value;
    }

    function nextPaint() {
      return new Promise((resolve) => {
        if (typeof window.requestAnimationFrame === 'function') {
          window.requestAnimationFrame(() => resolve());
          return;
        }
        window.setTimeout(resolve, 0);
      });
    }

    function recordUiAction(name) {
      try {
        if (window.pywebview && window.pywebview.api && typeof window.pywebview.api.record_ui_action === 'function') {
          Promise.resolve(window.pywebview.api.record_ui_action(String(name || ''))).catch(() => {});
        }
      } catch (_error) {}
    }

    function renderSubmitButton() {
      const button = document.getElementById('continueButton');
      if (!button) return;
      button.classList.toggle('loading', isSubmitting);
      button.disabled = !!isSubmitting;
      button.setAttribute('aria-busy', isSubmitting ? 'true' : 'false');
      setText('continueButtonLabel', isSubmitting ? t('auth.continue.loading') : t('auth.continue'));
    }

    function iconSvg(name) {
      if (name === 'settings') {
        return '<svg viewBox="0 0 512 512" aria-hidden="true"><path d="M262.29 192.31a64 64 0 1 0 57.4 57.4 64.13 64.13 0 0 0-57.4-57.4M416.39 256a154 154 0 0 1-1.53 20.79l45.21 35.46a10.81 10.81 0 0 1 2.45 13.75l-42.77 74a10.81 10.81 0 0 1-13.14 4.59l-44.9-18.08a16.11 16.11 0 0 0-15.17 1.75A164.5 164.5 0 0 1 325 400.8a15.94 15.94 0 0 0-8.82 12.14l-6.73 47.89a11.08 11.08 0 0 1-10.68 9.17h-85.54a11.11 11.11 0 0 1-10.69-8.87l-6.72-47.82a16.07 16.07 0 0 0-9-12.22 155 155 0 0 1-21.46-12.57 16 16 0 0 0-15.11-1.71l-44.89 18.07a10.81 10.81 0 0 1-13.14-4.58l-42.77-74a10.8 10.8 0 0 1 2.45-13.75l38.21-30a16.05 16.05 0 0 0 6-14.08c-.36-4.17-.58-8.33-.58-12.5s.21-8.27.58-12.35a16 16 0 0 0-6.07-13.94l-38.19-30A10.81 10.81 0 0 1 49.48 186l42.77-74a10.81 10.81 0 0 1 13.14-4.59l44.9 18.08a16.11 16.11 0 0 0 15.17-1.75A164.5 164.5 0 0 1 187 111.2a15.94 15.94 0 0 0 8.82-12.14l6.73-47.89A11.08 11.08 0 0 1 213.23 42h85.54a11.11 11.11 0 0 1 10.69 8.87l6.72 47.82a16.07 16.07 0 0 0 9 12.22 155 155 0 0 1 21.46 12.57 16 16 0 0 0 15.11 1.71l44.89-18.07a10.81 10.81 0 0 1 13.14 4.58l42.77 74a10.8 10.8 0 0 1-2.45 13.75l-38.21 30a16.05 16.05 0 0 0-6.05 14.08c.33 4.14.55 8.3.55 12.47" stroke="currentColor" stroke-width="32"></path></svg>';
      }
      if (name === 'paste') {
        return '<svg viewBox="0 0 512 512" aria-hidden="true"><path d="M336 64h32a48 48 0 0 1 48 48v320a48 48 0 0 1-48 48H144a48 48 0 0 1-48-48V112a48 48 0 0 1 48-48h32" stroke="currentColor" stroke-width="32"></path><rect width="160" height="64" x="176" y="32" rx="26.13" ry="26.13" stroke="currentColor" stroke-width="32"></rect></svg>';
      }
      if (name === 'remove') {
        return '<svg viewBox="0 0 512 512" aria-hidden="true"><path d="M400 256H112" stroke="currentColor" stroke-width="32"></path></svg>';
      }
      if (name === 'square') {
        return '<svg viewBox="0 0 512 512" aria-hidden="true"><path d="M416 448H96a32.09 32.09 0 0 1-32-32V96a32.09 32.09 0 0 1 32-32h320a32.09 32.09 0 0 1 32 32v320a32.09 32.09 0 0 1-32 32" stroke="currentColor" stroke-width="32"></path></svg>';
      }
      if (name === 'contract') {
        return '<svg viewBox="0 0 512 512" aria-hidden="true"><path d="M304 416V304h112M314.2 314.23 432 432M208 96v112H96M197.8 197.77 80 80M416 208H304V96M314.23 197.8 432 80M96 304h112v112M197.77 314.2 80 432" stroke="currentColor" stroke-width="32"></path></svg>';
      }
      if (name === 'eye-off') {
        return '<svg viewBox="0 0 512 512" aria-hidden="true"><path d="M432 448a15.92 15.92 0 0 1-11.31-4.69l-352-352a16 16 0 0 1 22.62-22.62l352 352A16 16 0 0 1 432 448M255.66 384c-41.49 0-81.5-12.28-118.92-36.5-34.07-22-64.74-53.51-88.7-91v-.08c19.94-28.57 41.78-52.73 65.24-72.21a2 2 0 0 0 .14-2.94L93.5 161.38a2 2 0 0 0-2.71-.12c-24.92 21-48.05 46.76-69.08 76.92a31.92 31.92 0 0 0-.64 35.54c26.41 41.33 60.4 76.14 98.28 100.65C162 402 207.9 416 255.66 416a239.1 239.1 0 0 0 75.8-12.58 2 2 0 0 0 .77-3.31l-21.58-21.58a4 4 0 0 0-3.83-1 204.8 204.8 0 0 1-51.16 6.47M490.84 238.6c-26.46-40.92-60.79-75.68-99.27-100.53C349 110.55 302 96 255.66 96a227.3 227.3 0 0 0-74.89 12.83 2 2 0 0 0-.75 3.31l21.55 21.55a4 4 0 0 0 3.88 1 192.8 192.8 0 0 1 50.21-6.69c40.69 0 80.58 12.43 118.55 37 34.71 22.4 65.74 53.88 89.76 91a.13.13 0 0 1 0 .16 310.7 310.7 0 0 1-64.12 72.73 2 2 0 0 0-.15 2.95l19.9 19.89a2 2 0 0 0 2.7.13 343.5 343.5 0 0 0 68.64-78.48 32.2 32.2 0 0 0-.1-34.78M256 160a96 96 0 0 0-21.37 2.4 2 2 0 0 0-1 3.38l112.59 112.56a2 2 0 0 0 3.38-1A96 96 0 0 0 256 160M165.78 233.66a2 2 0 0 0-3.38 1 96 96 0 0 0 115 115 2 2 0 0 0 1-3.38Z" fill="currentColor" stroke="none"></path></svg>';
      }
      if (name === 'close') {
        return '<svg viewBox="0 0 512 512" aria-hidden="true"><path d="M368 368 144 144M368 144 144 368" stroke="currentColor" stroke-width="32"></path></svg>';
      }
      return '<svg viewBox="0 0 512 512" aria-hidden="true"><path d="M255.66 112c-77.94 0-157.89 45.11-220.83 135.33a16 16 0 0 0-.27 17.77C82.92 340.8 161.8 400 255.66 400c92.84 0 173.34-59.38 221.79-135.25a16.14 16.14 0 0 0 0-17.47C428.89 172.28 347.8 112 255.66 112" stroke="currentColor" stroke-width="32"></path><circle cx="256" cy="256" r="80" stroke="currentColor" stroke-width="32"></circle></svg>';
    }

    function setIconButton(id, iconName, label) {
      const node = document.getElementById(id);
      if (!node) return;
      node.title = label;
      node.setAttribute('aria-label', label);
      node.innerHTML = iconSvg(iconName);
    }

    function currentStatus() {
            return '';
    }

    function resolveThemeDarkJs() {
      if (state.theme === 'dark') return true;
      if (state.theme === 'light') return false;
      if (themeMedia && typeof themeMedia.matches === 'boolean') return !!themeMedia.matches;
      return !!bootstrap.themeDark;
    }

    function settingsSummaryText() {
      return `${t(`lang.${state.language}`)} / ${t(`theme.${state.theme}`)} / ${t(`position.${state.indicator_position}`)} / ${t(`size.${state.blob_size}`)}`;
    }

    function initBrandEyes(signal) {
      const eyes = Array.from(document.querySelectorAll('[data-brand-eye]'));
      if (!eyes.length) return;

      const reduceMotion = Boolean(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
      const moodPool = [
        { blink: 7.8, bob: 5.6, glance: 3000, lookX: 2, tone: 'calm', waitMin: 2800, waitMax: 5200 },
        { blink: 6.2, bob: 4.6, glance: 2200, lookX: 3, tone: 'steady', waitMin: 1900, waitMax: 3400 },
        { blink: 4.5, bob: 3.2, glance: 1400, lookX: 5, tone: 'fast', waitMin: 1100, waitMax: 1900 }
      ];
      const lookPool = [
        { x: 0, y: 0 },
        { x: -1, y: 0 },
        { x: 1, y: 0 },
        { x: -1, y: 1 },
        { x: 1, y: 1 }
      ];

      eyes.forEach((eyeRoot) => {
        let moodTimer = 0;
        let glanceTimer = 0;
        let activeMood = moodPool[1];

        const clearTimers = () => {
          if (moodTimer) {
            window.clearTimeout(moodTimer);
            moodTimer = 0;
          }
          if (glanceTimer) {
            window.clearTimeout(glanceTimer);
            glanceTimer = 0;
          }
        };

        const setLook = (mood = activeMood) => {
          const look = lookPool[Math.floor(Math.random() * lookPool.length)];
          eyeRoot.style.setProperty('--badge-look-x', `${look.x * mood.lookX}px`);
          eyeRoot.style.setProperty('--badge-look-y', `${look.y * 2}px`);
        };

        const queueNextLook = (mood = activeMood) => {
          if (reduceMotion) {
            eyeRoot.style.setProperty('--badge-look-x', '0px');
            eyeRoot.style.setProperty('--badge-look-y', '0px');
            return;
          }
          if (glanceTimer) {
            window.clearTimeout(glanceTimer);
          }
          setLook(mood);
          const wait = Math.max(650, mood.glance + (Math.random() * 900) - 280);
          glanceTimer = window.setTimeout(() => queueNextLook(mood), wait);
        };

        const applyMood = (mood) => {
          activeMood = mood;
          eyeRoot.dataset.mood = mood.tone;
          eyeRoot.style.setProperty('--badge-blink-duration', `${(mood.blink + Math.random() * 0.45).toFixed(2)}s`);
          eyeRoot.style.setProperty('--badge-bob-duration', `${(mood.bob + Math.random() * 0.35).toFixed(2)}s`);
          eyeRoot.style.setProperty('--badge-glance-duration', `${Math.max(0.16, mood.glance / 1000).toFixed(2)}s`);
          queueNextLook(mood);
        };

        const queueNextMood = () => {
          if (reduceMotion) {
            applyMood(moodPool[1]);
            return;
          }
          const mood = moodPool[Math.floor(Math.random() * moodPool.length)];
          applyMood(mood);
          const wait = mood.waitMin + Math.random() * (mood.waitMax - mood.waitMin);
          moodTimer = window.setTimeout(queueNextMood, wait);
        };

        clearTimers();
        applyMood(moodPool[1]);
        queueNextMood();

        signal.addEventListener('abort', () => {
          clearTimers();
        }, { once: true });
      });
    }

    function hotkeyBindingLabelJs(bindingKey) {
      return ((allowedHotkeys[bindingKey] || {}).label) || '?';
    }

    function inferHotkeyModeJs() {
      const keypadFlags = hotkeyActionIds.map((action) => ((allowedHotkeys[state.hotkeys[action]] || {}).keypad));
      if (keypadFlags.length && keypadFlags.every((flag) => flag === true)) return 'numpad';
      if (keypadFlags.length && keypadFlags.every((flag) => flag === false)) return 'toprow';
      return state.hotkey_mode || 'numpad';
    }

    function normalizeHotkeyEvent(event) {
      const code = String(event.code || '');
      const map = {
        Escape: 'escape',
        Tab: 'tab',
        Space: 'space',
        Digit1: 'digit1',
        Digit2: 'digit2',
        Digit3: 'digit3',
        Digit4: 'digit4',
        Digit5: 'digit5',
        Digit6: 'digit6',
        Digit7: 'digit7',
        Digit8: 'digit8',
        Digit9: 'digit9',
        Digit0: 'digit0',
        F1: 'f1',
        F2: 'f2',
        F3: 'f3',
        F4: 'f4',
        F5: 'f5',
        F6: 'f6',
        F7: 'f7',
        F8: 'f8',
        F9: 'f9',
        F10: 'f10',
        F11: 'f11',
        F12: 'f12',
        Home: 'home',
        ArrowUp: 'arrowup',
        PageUp: 'pageup',
        Numpad9: 'numpad9',
        NumpadSubtract: 'numpadsubtract',
        ArrowLeft: 'arrowleft',
        Numpad4: 'numpad4',
        Numpad5: 'numpad5',
        ArrowRight: 'arrowright',
        Numpad6: 'numpad6',
        NumpadAdd: 'numpadadd',
        Numpad7: 'numpad7',
        Numpad8: 'numpad8',
        End: 'end',
        Numpad1: 'numpad1',
        ArrowDown: 'arrowdown',
        Numpad2: 'numpad2',
        PageDown: 'pagedown',
        Numpad3: 'numpad3',
        Insert: 'insert',
        Numpad0: 'numpad0',
        Delete: 'delete',
        NumpadDecimal: 'numpaddecimal',
        NumpadEnter: 'numpadenter',
        NumpadMultiply: 'numpadmultiply',
        NumpadDivide: 'numpaddivide',
      };
      if (/^Key[A-Z]$/.test(code)) return '';
      return allowedHotkeys[map[code]] ? map[code] : '';
    }

    function renderHotkeys() {
      const mount = document.getElementById('hotkeyList');
      if (!mount) return;
      mount.innerHTML = '';
      hotkeyActionIds.forEach((action) => {
        const row = document.createElement('div');
        row.className = 'hotkey-row';
        const label = document.createElement('div');
        label.className = 'hotkey-row-label';
        label.textContent = t(`auth.hotkey.${action}`);
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'hotkey-button' + (awaitingHotkeyAction === action ? ' waiting' : '');
        button.textContent = awaitingHotkeyAction === action ? t('auth.hotkeys.waiting') : hotkeyBindingLabelJs(state.hotkeys[action]);
        button.onclick = () => {
          recordUiAction(`ui.hotkey_select.${action}`);
          awaitingHotkeyAction = awaitingHotkeyAction === action ? '' : action;
          hotkeyFeedbackKey = awaitingHotkeyAction ? 'auth.hotkeys.waiting' : 'auth.hotkeys.copy';
          setText('hotkeysFeedback', t(hotkeyFeedbackKey));
          renderHotkeys();
        };
        row.appendChild(label);
        row.appendChild(button);
        mount.appendChild(row);
      });
    }

    function captureHotkey(event) {
      if (!awaitingHotkeyAction) return false;
      event.preventDefault();
      event.stopPropagation();
      if (event.ctrlKey || event.altKey || event.metaKey) {
        hotkeyFeedbackKey = 'auth.hotkeys.invalid';
        setText('hotkeysFeedback', t(hotkeyFeedbackKey));
        return true;
      }
      const bindingKey = normalizeHotkeyEvent(event);
      if (!bindingKey) {
        hotkeyFeedbackKey = 'auth.hotkeys.invalid';
        setText('hotkeysFeedback', t(hotkeyFeedbackKey));
        return true;
      }
      const duplicateAction = hotkeyActionIds.find((action) => action !== awaitingHotkeyAction && state.hotkeys[action] === bindingKey);
      if (duplicateAction) {
        hotkeyFeedbackKey = 'auth.hotkeys.duplicate';
        setText('hotkeysFeedback', t(hotkeyFeedbackKey));
        return true;
      }
      state.hotkeys[awaitingHotkeyAction] = bindingKey;
      state.hotkey_mode = inferHotkeyModeJs();
      awaitingHotkeyAction = '';
      hotkeyFeedbackKey = 'auth.hotkeys.copy';
      setText('hotkeysFeedback', t(hotkeyFeedbackKey));
      renderHotkeys();
      return true;
    }

    function resetHotkeysToDefault() {
      recordUiAction('ui.hotkeys_reset');
      state.hotkeys = Object.assign({}, defaultNumpadHotkeys);
      state.hotkey_mode = 'numpad';
      awaitingHotkeyAction = '';
      hotkeyFeedbackKey = 'auth.hotkeys.reset_done';
      renderHotkeys();
      setText('hotkeysFeedback', t(hotkeyFeedbackKey));
    }

    function positionPoint(positionId) {
      return positionPoints[positionId] || positionPoints.bottom_right || { x: 0.88, y: 0.83 };
    }

    function chipCornerRadius(sizePx) {
      return Math.max(4, Math.min(Math.round(sizePx * 0.32), Math.max(4, Math.floor(sizePx / 2) - 2)));
    }

    function applyPositionStyles(node, positionId) {
      const point = positionPoint(positionId);
      node.style.left = `${Math.round(point.x * 100)}%`;
      node.style.top = `${Math.round(point.y * 100)}%`;
    }

    function renderLanguageButtons() {
      const mount = document.getElementById('languageButtons');
      mount.innerHTML = '';
      ['en', 'fr'].forEach((lang) => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'segment' + (state.language === lang ? ' active' : '');
        btn.textContent = t(`lang.${lang}`);
        btn.onclick = () => { recordUiAction(`ui.language.${lang}`); state.language = lang; render(); };
        mount.appendChild(btn);
      });
    }

    function renderThemeButtons() {
      const mount = document.getElementById('themeButtons');
      mount.innerHTML = '';
      ['system', 'dark', 'light'].forEach((themeId) => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'segment' + (state.theme === themeId ? ' active' : '');
        btn.textContent = t(`theme.${themeId}`);
        btn.onclick = () => {
          recordUiAction(`ui.theme.${themeId}`);
          state.theme = themeId;
          render();
        };
        mount.appendChild(btn);
      });
    }

    function renderSizeButtons() {
      const mount = document.getElementById('sizeButtons');
      mount.innerHTML = '';
      sizeIds.forEach((sizeId) => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'pill' + (state.blob_size === sizeId ? ' active' : '');
        btn.textContent = t(`size.${sizeId}`);
        btn.onclick = () => { recordUiAction(`ui.blob_size.${sizeId}`); state.blob_size = sizeId; renderPreview(); renderSizeButtons(); };
        mount.appendChild(btn);
      });
    }

    function renderPositionButtons() {
      const mount = document.getElementById('positionButtons');
      mount.innerHTML = '';
      positionIds.forEach((positionId) => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'hotspot' + (state.indicator_position === positionId ? ' active' : '');
        btn.title = t(`position.${positionId}`);
        btn.setAttribute('aria-label', t(`position.${positionId}`));
        applyPositionStyles(btn, positionId);
        btn.onclick = () => {
          recordUiAction(`ui.position.${positionId}`);
          state.indicator_position = positionId;
          renderPreview();
          renderPositionButtons();
        };
        mount.appendChild(btn);
      });
    }

    function renderModels() {
      const hiddenInput = document.getElementById('modelSelect');
      const mount = document.getElementById('modelOptions');
      if (!hiddenInput || !mount) return;
      mount.innerHTML = '';
      const nextValue = state.preferred_model || state.pro_model || (proModels[0] ? proModels[0].id : '');
      state.preferred_model = nextValue;
      state.pro_model = nextValue;
      hiddenInput.value = nextValue;
      proModels.forEach((item) => {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'model-option' + (item.id === state.preferred_model ? ' active' : '');
        button.title = item.description || item.label || item.id;
        button.setAttribute('aria-pressed', item.id === state.preferred_model ? 'true' : 'false');
        button.onclick = () => {
          recordUiAction(`ui.model.${item.id}`);
          state.preferred_model = item.id;
          state.pro_model = item.id;
          hiddenInput.value = item.id;
          renderModels();
        };
        const title = document.createElement('div');
        title.className = 'model-option-title';
        title.textContent = item.label || item.id;
        const copy = document.createElement('div');
        copy.className = 'model-option-copy';
        copy.textContent = item.description || item.id;
        button.appendChild(title);
        button.appendChild(copy);
        mount.appendChild(button);
      });
    }

    function renderPreview() {
      const chip = document.getElementById('previewChip');
      const preview = document.getElementById('previewSurface');
      const sizeMap = { very_small: 16, small: 20, medium: 24, large: 30 };
      const sizePx = sizeMap[state.blob_size] || 24;
      const inset = 22;
      const point = positionPoint(state.indicator_position);
      const usableWidth = Math.max(1, preview.clientWidth - (inset * 2));
      const usableHeight = Math.max(1, preview.clientHeight - (inset * 2));
      const chipX = Math.round(inset + (usableWidth * point.x));
      const chipY = Math.round(inset + (usableHeight * point.y));
      chip.style.width = `${sizePx}px`;
      chip.style.height = `${sizePx}px`;
      chip.style.borderRadius = `${chipCornerRadius(sizePx)}px`;
      chip.style.left = `${chipX}px`;
      chip.style.top = `${chipY}px`;
      chip.style.transform = 'translate(-50%, -50%)';
      setText('positionValue', t(`position.${state.indicator_position}`));
    }

    function syncSettingsState() {
      const drawer = document.getElementById('settingsDrawer');
      const backdrop = document.getElementById('settingsBackdrop');
      const toggle = document.getElementById('settingsToggleButton');
      drawer.classList.toggle('open', settingsOpen);
      drawer.setAttribute('aria-hidden', settingsOpen ? 'false' : 'true');
      backdrop.classList.toggle('open', settingsOpen);
      toggle.classList.toggle('active', settingsOpen);
    }

    function toggleSettings(forceOpen) {
      recordUiAction(typeof forceOpen === 'boolean' ? (forceOpen ? 'ui.settings.open' : 'ui.settings.close') : 'ui.settings.toggle');
      settingsOpen = typeof forceOpen === 'boolean' ? forceOpen : !settingsOpen;
      if (!settingsOpen) awaitingHotkeyAction = '';
      syncSettingsState();
    }

    function render() {
      themeDark = resolveThemeDarkJs();
      document.body.classList.toggle('theme-dark', themeDark);
      document.body.classList.toggle('theme-light', !themeDark);
      document.body.classList.toggle('window-maximized', !!windowMaximized);
      document.documentElement.lang = state.language;
      setText('windowCaption', t('auth.window_caption'));
      setText('windowStatus', currentStatus());
      setText('title', t('auth.title'));
      const brandOpenLabel = t('auth.open_site');
      document.getElementById('windowBrandLink').setAttribute('aria-label', brandOpenLabel);
      document.getElementById('windowBrandLink').title = brandOpenLabel;
      document.getElementById('titleButton').setAttribute('aria-label', brandOpenLabel);
      document.getElementById('titleButton').title = brandOpenLabel;
      setText('settingsSummaryTitle', t('auth.settings'));
      setText('settingsSummaryValue', settingsSummaryText());
      setText('openSettingsButton', t('auth.settings'));
      setText('settingsPanelTitle', t('auth.settings'));
      setText('settingsPanelCopy', t('auth.settings.copy'));
      setText('settingsDoneButton', t('auth.settings.done'));
      setText('startupSectionTitle', t('auth.section.startup'));
      setText('startupScreenLabel', t('auth.startup_screen.label'));
      setText('startupScreenCopy', t('auth.startup_screen.copy'));
      setText('modeDashboardTitle', t('auth.account.dashboard'));
      setText('modeDashboardHelp', t('auth.account.helper'));
    setText('modeTutorialTitle', t('auth.account.tutorial'));
    setText('modeTutorialHelp', t('auth.account.tutorial.help'));
      setText('previewTitle', t('auth.preview.title'));
      setText('previewCopy', t('auth.preview.copy'));
      setText('languageTitle', t('auth.language'));
      setText('appearanceTitle', t('auth.section.appearance'));
      setText('themeTitle', t('auth.section.theme'));
      setText('themeCopy', t('auth.theme.copy'));
      setText('sizeTitle', t('auth.section.indicator_size'));
      setText('proSectionTitle', t('auth.section.pro'));
    setText('accountTitle', t('auth.login.title'));
      setText('emailLabel', t('auth.account.email'));
      setText('passwordLabel', t('auth.account.password'));
    setText('importSettingsButton', t('auth.account.reset'));
      setText('rememberMeButton', t('auth.account.remember'));
      setText('modelLabel', t('auth.pro.model'));
      setText('modelNote', t('auth.pro.model.note'));
      setText('hotkeysTitle', t('auth.section.hotkeys'));
      setText('hotkeysCopy', t('auth.hotkeys.copy'));
      setText('hotkeysResetButton', t('auth.hotkeys.reset'));
      setText('hotkeysFeedback', t(awaitingHotkeyAction ? 'auth.hotkeys.waiting' : hotkeyFeedbackKey));
      setText('securityCopy', t('auth.security'));
      setText('cancelButton', t('auth.cancel'));
            const cancelButton = document.getElementById('cancelButton');
            if (cancelButton) {
                cancelButton.style.display = state.allow_cancel ? '' : 'none';
            }
      document.getElementById('emailInput').placeholder = t('auth.account.email.placeholder');
      document.getElementById('passwordInput').placeholder = t('auth.account.password.placeholder');
      setIconButton('settingsToggleButton', 'settings', t('auth.settings'));
      setIconButton('minimizeButton', 'remove', t('auth.window.minimize'));
      setIconButton('maximizeButton', windowMaximized ? 'contract' : 'square', windowMaximized ? t('auth.window.restore') : t('auth.window.maximize'));
      setIconButton('closeChromeButton', 'close', t('auth.window.close'));
      setIconButton('showButton', document.getElementById('passwordInput').type === 'password' ? 'eye' : 'eye-off', document.getElementById('passwordInput').type === 'password' ? t('auth.api.show') : t('auth.api.hide'));
      const rememberButton = document.getElementById('rememberMeButton');
      if (rememberButton) {
        rememberButton.classList.toggle('active', !!state.remember_me);
        rememberButton.setAttribute('aria-pressed', state.remember_me ? 'true' : 'false');
      }
      const startupToggle = document.getElementById('startupScreenToggle');
      if (startupToggle) {
        startupToggle.textContent = state.show_startup_screen ? t('auth.startup_screen.enabled') : t('auth.startup_screen.disabled');
        startupToggle.className = 'pill' + (state.show_startup_screen ? ' active' : '');
        startupToggle.setAttribute('aria-pressed', state.show_startup_screen ? 'true' : 'false');
      }
      renderLanguageButtons();
      renderThemeButtons();
      renderSizeButtons();
      renderPositionButtons();
      renderHotkeys();
      renderModels();
      renderPreview();
      renderSubmitButton();
      syncSettingsState();
    }

    function validate() {
      const emailValue = String(document.getElementById('emailInput').value || '').trim().toLowerCase();
      const passwordValue = String(document.getElementById('passwordInput').value || '');
      state.email = emailValue;
      state.password = passwordValue;
      if (!emailValue) return 'auth.validation.account.email.empty';
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(emailValue)) return 'auth.validation.account.email.invalid';
      return '';
    }

    async function submit() {
      recordUiAction('ui.submit');
      if (isSubmitting) return;
      const errorKey = validate();
      setText('errorText', errorKey ? t(errorKey) : '');
      if (errorKey) return;
      state.error_message = '';
      const payload = {
        language: state.language,
        theme: state.theme,
        blob_size: state.blob_size,
        indicator_position: state.indicator_position,
        show_startup_screen: !!state.show_startup_screen,
        hotkeys: state.hotkeys,
        hotkey_mode: state.hotkey_mode,
        preferred_model: state.preferred_model || state.pro_model,
        pro_model: state.preferred_model || state.pro_model,
        email: state.email,
        password: state.password,
        remember_me: !!state.remember_me
      };
      if (window.pywebview && window.pywebview.api && window.pywebview.api.submit) {
        isSubmitting = true;
        renderSubmitButton();
        await nextPaint();
        try {
          const result = await window.pywebview.api.submit(payload);
          if (result && result.error) {
            state.error_message = String(result.error || '');
            setText('errorText', state.error_message);
            return;
          }
        } catch (error) {
          state.error_message = String((error && error.message) || t('error.auth_denied'));
          setText('errorText', state.error_message);
          return;
        } finally {
          isSubmitting = false;
          renderSubmitButton();
        }
      }
    }

    async function closeWindow() {
      recordUiAction('ui.close_window');
            if (!state.allow_cancel) return;
      if (closePending) return;
      closePending = true;
      try {
        if (window.pywebview && window.pywebview.api && window.pywebview.api.close) {
          const closed = await window.pywebview.api.close();
          if (closed) return;
        }
      } catch (error) {}
      try {
        window.close();
      } catch (error) {}
    }

    async function exitApp() {
      recordUiAction('ui.exit_app');
      if (window.pywebview && window.pywebview.api && window.pywebview.api.exit_app) {
        await window.pywebview.api.exit_app();
        return;
      }
      await closeWindow();
    }

    async function minimizeWindow() {
      recordUiAction('ui.minimize_window');
      if (window.pywebview && window.pywebview.api && window.pywebview.api.minimize) {
        await window.pywebview.api.minimize();
      }
    }

    async function toggleMaximize() {
      recordUiAction('ui.toggle_maximize');
      if (window.pywebview && window.pywebview.api && window.pywebview.api.toggle_maximize) {
        const nextState = await window.pywebview.api.toggle_maximize();
        if (typeof nextState === 'boolean') {
          windowMaximized = nextState;
          render();
        }
      }
    }

    async function startWindowMove() {
      if (window.pywebview && window.pywebview.api && window.pywebview.api.start_move) {
                try {
                    await window.pywebview.api.start_move();
                } catch (error) {}
      }
    }

        const manualDragState = {
            active: false,
            inFlight: false,
            hasPending: false,
            screenX: 0,
            screenY: 0,
        };

        function flushManualWindowDrag() {
            if (!manualDragState.active || manualDragState.inFlight) return;
            manualDragState.inFlight = true;
            const sendX = manualDragState.screenX;
            const sendY = manualDragState.screenY;
            Promise.resolve().then(async () => {
                try {
                    const api = window.pywebview && window.pywebview.api;
                    if (api && api.update_window_drag) {
                        await api.update_window_drag(sendX, sendY);
                    }
                } catch (error) {
                } finally {
                    manualDragState.inFlight = false;
                    if (manualDragState.active && manualDragState.hasPending) {
                        manualDragState.hasPending = false;
                        flushManualWindowDrag();
                    }
                }
            });
        }

        async function startManualWindowDrag(event) {
            const api = window.pywebview && window.pywebview.api;
            if (!api || !api.begin_window_drag || !api.update_window_drag || !api.end_window_drag) {
                startWindowMove().catch(() => {});
                return;
            }
            let started = false;
            try {
                started = !!(await api.begin_window_drag(Number(event.screenX || 0), Number(event.screenY || 0)));
            } catch (error) {
                started = false;
            }
            if (!started) {
                startWindowMove().catch(() => {});
                return;
            }
            manualDragState.active = true;
            manualDragState.inFlight = false;
            manualDragState.hasPending = false;
            manualDragState.screenX = Number(event.screenX || 0);
            manualDragState.screenY = Number(event.screenY || 0);
            window.addEventListener('mousemove', onManualWindowDragMove, true);
            window.addEventListener('mouseup', stopManualWindowDrag, true);
            window.addEventListener('blur', stopManualWindowDrag, true);
            flushManualWindowDrag();
        }

        function onManualWindowDragMove(event) {
            if (!manualDragState.active) return;
            manualDragState.screenX = Number(event.screenX || 0);
            manualDragState.screenY = Number(event.screenY || 0);
            manualDragState.hasPending = true;
            flushManualWindowDrag();
        }

        async function stopManualWindowDrag() {
            if (!manualDragState.active) return;
            manualDragState.active = false;
            window.removeEventListener('mousemove', onManualWindowDragMove, true);
            window.removeEventListener('mouseup', stopManualWindowDrag, true);
            window.removeEventListener('blur', stopManualWindowDrag, true);
            try {
                const api = window.pywebview && window.pywebview.api;
                if (api && api.end_window_drag) {
                    await api.end_window_drag();
                }
            } catch (error) {}
        }

    function blockHeaderDrag(event) {
      event.stopPropagation();
    }

    async function openDashboardLink() {
      recordUiAction('ui.open_dashboard');
      if (!dashboardUrl) return;
      if (window.pywebview && window.pywebview.api && window.pywebview.api.open_external) {
        await window.pywebview.api.open_external(dashboardUrl);
        return;
      }
      window.open(dashboardUrl, '_blank');
    }

    async function openResetPasswordLink() {
      recordUiAction('ui.open_reset_password');
      if (!forgotPasswordUrl) return;
      if (window.pywebview && window.pywebview.api && window.pywebview.api.open_external) {
        await window.pywebview.api.open_external(forgotPasswordUrl);
        return;
      }
      window.open(forgotPasswordUrl, '_blank');
    }

        async function openTutorialLink() {
            recordUiAction('ui.open_tutorial');
            if (!tutorialUrl) return;
            if (window.pywebview && window.pywebview.api && window.pywebview.api.open_external) {
                await window.pywebview.api.open_external(tutorialUrl);
                return;
            }
            window.open(tutorialUrl, '_blank');
        }

    async function openWebsiteLink() {
      recordUiAction('ui.open_website');
      if (!websiteUrl) return;
      if (window.pywebview && window.pywebview.api && window.pywebview.api.open_external) {
        await window.pywebview.api.open_external(websiteUrl);
        return;
      }
      window.open(websiteUrl, '_blank');
    }

    window.addEventListener('DOMContentLoaded', () => {
      const eyeAnimationController = window.AbortController
        ? new AbortController()
        : { signal: { addEventListener() {} }, abort() {} };
      window.addEventListener('beforeunload', () => eyeAnimationController.abort(), { once: true });
      hotkeyActionIds.forEach((action) => {
        if (!allowedHotkeys[state.hotkeys[action]]) {
          state.hotkeys[action] = '';
        }
      });
      state.hotkey_mode = inferHotkeyModeJs();
      document.getElementById('emailInput').value = state.email || '';
      document.getElementById('passwordInput').value = state.password || '';
      document.getElementById('showButton').onclick = () => {
        recordUiAction('ui.password_visibility_toggle');
        const input = document.getElementById('passwordInput');
        input.type = input.type === 'password' ? 'text' : 'password';
        render();
      };
    document.getElementById('importSettingsButton').onclick = openResetPasswordLink;
      document.getElementById('rememberMeButton').onclick = () => {
        recordUiAction('ui.remember_me_toggle');
        state.remember_me = !state.remember_me;
        render();
      };
      document.getElementById('settingsToggleButton').onclick = () => toggleSettings();
      document.getElementById('openSettingsButton').onclick = () => toggleSettings(true);
      document.getElementById('settingsDoneButton').onclick = () => toggleSettings(false);
      document.getElementById('settingsBackdrop').onclick = () => toggleSettings(false);
      document.getElementById('hotkeysResetButton').onclick = resetHotkeysToDefault;
      document.getElementById('startupScreenToggle').onclick = () => {
        recordUiAction('ui.startup_screen_toggle');
        state.show_startup_screen = !state.show_startup_screen;
        render();
      };
      document.querySelectorAll('.resize-handle').forEach((handle) => {
        handle.addEventListener('mousedown', async (event) => {
          event.preventDefault();
          event.stopPropagation();
          windowMaximized = false;
          render();
          if (window.pywebview && window.pywebview.api && window.pywebview.api.start_resize) {
            await window.pywebview.api.start_resize(handle.dataset.edge || '');
          }
        });
      });
      document.getElementById('windowBrandLink').onclick = openWebsiteLink;
      document.getElementById('titleButton').onclick = openWebsiteLink;
    const modeDashboardCard = document.getElementById('modeDashboardCard');
    if (modeDashboardCard) modeDashboardCard.onclick = () => openDashboardLink();
    const modeTutorialCard = document.getElementById('modeTutorialCard');
    if (modeTutorialCard) modeTutorialCard.onclick = () => openTutorialLink();
      document.getElementById('minimizeButton').onclick = minimizeWindow;
      document.getElementById('maximizeButton').onclick = toggleMaximize;
      document.getElementById('closeChromeButton').onclick = exitApp;
      document.getElementById('cancelButton').onclick = closeWindow;
      document.getElementById('continueButton').onclick = submit;
      ['windowBrandLink', 'settingsToggleButton', 'minimizeButton', 'maximizeButton', 'closeChromeButton'].forEach((id) => {
        const element = document.getElementById(id);
        if (element) {
          element.addEventListener('mousedown', blockHeaderDrag);
          element.addEventListener('dblclick', blockHeaderDrag);
        }
      });
      document.getElementById('windowDragZone').addEventListener('dblclick', (event) => {
        if (event.target.closest('button, input, select, textarea, label, a')) return;
        event.preventDefault();
        event.stopPropagation();
        toggleMaximize().catch(() => {});
      });
            ['windowDragZone', 'windowDragFill', 'windowStatus'].forEach((id) => {
                const element = document.getElementById(id);
                if (!element) return;
                element.addEventListener('mousedown', (event) => {
                    if (event.button !== 0) return;
                    if (event.target.closest('button, input, select, textarea, label, a, .resize-handle')) return;
                    event.preventDefault();
                    event.stopPropagation();
                    startManualWindowDrag(event).catch(() => {});
                });
            });
      document.getElementById('emailInput').addEventListener('input', () => { state.error_message = ''; setText('errorText', ''); });
      document.getElementById('passwordInput').addEventListener('input', () => { state.error_message = ''; setText('errorText', ''); });
      document.addEventListener('keydown', (event) => {
        if (captureHotkey(event)) return;
        if (event.key === 'Escape') {
          if (settingsOpen) toggleSettings(false);
                    else if (state.allow_cancel) closeWindow();
        }
        if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) submit();
      });
      if (themeMedia) {
        const applyThemeChange = (event) => {
          if (state.theme === 'system') {
            themeDark = !!event.matches;
            render();
          }
        };
        if (themeMedia.addEventListener) themeMedia.addEventListener('change', applyThemeChange);
        else if (themeMedia.addListener) themeMedia.addListener(applyThemeChange);
      }
      window.addEventListener('resize', renderPreview);
      render();
      initBrandEyes(eyeAnimationController.signal);
      if (state.error_message) {
        setText('errorText', state.error_message);
      }
    });
  </script>
</body>
</html>
"""
    return template.replace(
        "/*__BOOTSTRAP__*/",
        "window.AUTH_BOOTSTRAP = " + json.dumps(bootstrap, ensure_ascii=True) + ";",
    )


def prompt_account_auth_dialog_tk(initial_email="", initial_password="", initial_blob_size="medium", initial_error="", allow_cancel=False):
    show_styled_message(APP_NAME, webview_required_message("the sign-in and settings screen"), is_error=True, parent=None)
    return None


def build_account_auth_shell_state(initial_email="", initial_password="", initial_blob_size="medium", initial_error="", allow_cancel=False):
    record = load_config_record()
    preferred_model = normalize_pro_model(selected_pro_model_key)
    remembered = normalize_remember_me_preference(record.get("remember_me", remember_me_enabled))
    remembered_password = ""
    if remembered and not str(initial_password or ""):
        remembered_password = load_saved_secret(record, "remembered_password", "remembered_password_dpapi", persist_migration=False)
    live_session_email = ""
    live_session_token = ""
    with session_lock:
        if session_active:
            live_session_email = normalize_account_email(user_email)
            live_session_token = str(session_token or "").strip()
    return {
        "language": normalize_language(ui_language),
        "theme": normalize_theme_preference(ui_theme_preference),
        "blob_size": normalize_indicator_blob_size(initial_blob_size),
        "indicator_position": normalize_indicator_position(indicator_position_key),
        "show_startup_screen": normalize_startup_loading_screen_enabled(startup_loading_screen_enabled),
        "preferred_model": preferred_model,
        "pro_model": preferred_model,
        "hotkeys": dict(command_hotkeys),
        "hotkey_mode": command_key_mode,
        "email": normalize_account_email(initial_email),
        "password": str(initial_password or remembered_password or ""),
        "remember_me": bool(remembered),
        "live_session_email": live_session_email,
        "live_session_token": live_session_token,
        "error_message": str(initial_error or ""),
        "allow_cancel": bool(allow_cancel),
    }


def auth_shell_window_geometry():
    screen_width = 1920
    screen_height = 1080
    if os.name == "nt":
        try:
            screen_width = int(ctypes.windll.user32.GetSystemMetrics(0))
            screen_height = int(ctypes.windll.user32.GetSystemMetrics(1))
        except Exception:
            logger.debug("Could not read work-area metrics for auth shell sizing.", exc_info=True)
    left, top, right, bottom = get_work_area_bounds(screen_width, screen_height)
    available_width = max(980, int(right - left))
    available_height = max(700, int(bottom - top))
    width = min(1360, max(1180, available_width - 72))
    height = min(820, max(720, available_height - 90))
    width = min(width, max(960, available_width - 24))
    height = min(height, max(680, available_height - 24))
    min_width = min(width, 1080 if available_width < 1320 else 1160)
    min_height = min(height, 680 if available_height < 820 else 720)
    return {
        "width": int(width),
        "height": int(height),
        "min_size": (int(min_width), int(min_height)),
    }


def run_auth_shell_webview(initial_state):
    with profile_span("auth_shell.webview"):
        if not has_pywebview_support():
            return {"__error__": "webview_required"}

        webview_module = get_webview_module()
        if webview_module is None:
            return {"__error__": "webview_required"}

        bridge = AuthShellBridge()
        bridge._initial_state = dict(initial_state or {})
        title = tr("auth.window_title", language=normalize_language(initial_state.get("language", ui_language)))
        geometry = auth_shell_window_geometry()
        try:
            window = webview_module.create_window(
                title,
                html=build_auth_shell_html(initial_state),
                js_api=bridge,
                width=geometry["width"],
                height=geometry["height"],
                min_size=geometry["min_size"],
                resizable=True,
                hidden=True,
                frameless=True,
                easy_drag=False,
                shadow=False,
                focus=True,
                background_color="#081321",
                text_select=False,
            )
            if window is None:
                return {"__error__": "window_init"}
            bridge.bind_window(window)

            def _prepare(window_obj, bridge_obj):
                try:
                    profile_mark("auth_shell.window_show")
                    window_obj.show()
                    bridge_obj._on_window_shown()
                except Exception:
                    logger.warning("Could not show auth webview window.", exc_info=True)
                    bridge_obj._result = {"__error__": "show_failed"}
                    bridge_obj.close()
                    return

                selftest_path = str(os.environ.get("EAE_AUTH_SHELL_SELFTEST_FILE", "") or "").strip()
                if selftest_path:
                    Thread(
                        target=run_auth_shell_automated_selftest,
                        args=(bridge_obj, selftest_path),
                        daemon=True,
                        name="auth-shell-selftest",
                    ).start()

            webview_module.start(
                _prepare,
                args=(window, bridge),
                **resolve_pywebview_start_kwargs(),
            )
        except Exception:
            logger.warning("Webview auth shell failed.", exc_info=True)
            return {"__error__": "webview_error"}

        return bridge.result


def run_auth_shell_subprocess(request_path, response_path):
    with profile_span("auth_shell.subprocess"):
        ensure_ui_crisp_mode()
        hide_console_window()
        payload = {}
        try:
            payload = json.loads(Path(request_path).read_text(encoding="utf-8"))
        except Exception:
            payload = {}
        apply_ui_theme_preference(
            (payload.get("theme") if isinstance(payload, dict) else "")
            or os.environ.get("EAE_THEME", ui_theme_preference)
        )

        result = None
        try:
            result = run_auth_shell_webview(payload if isinstance(payload, dict) else {})
        except Exception:
            logger.warning("Auth shell subprocess exited unexpectedly.", exc_info=True)
            result = None
        try:
            Path(response_path).write_text(
                json.dumps({"result": result}, ensure_ascii=True),
                encoding="utf-8",
            )
        except Exception:
            logger.warning("Could not write auth shell response payload.", exc_info=True)
            return 1
        return 0


def prompt_account_auth_dialog(initial_email="", initial_password="", initial_blob_size="medium", initial_error="", allow_cancel=False):
    with profile_span("auth.prompt_account_dialog"):
        initial_state = build_account_auth_shell_state(
            initial_email=initial_email,
            initial_password=initial_password,
            initial_blob_size=initial_blob_size,
            initial_error=initial_error,
            allow_cancel=allow_cancel,
        )
        if not has_pywebview_support():
            show_styled_message(APP_NAME, webview_required_message("the sign-in and settings screen"), is_error=True, parent=None)
            return None

        with tempfile.TemporaryDirectory(prefix="eae-auth-") as temp_dir:
            request_path = Path(temp_dir) / "request.json"
            response_path = Path(temp_dir) / "response.json"
            request_path.write_text(json.dumps(initial_state, ensure_ascii=True), encoding="utf-8")

            command = [sys.executable]
            if not getattr(sys, "frozen", False):
                command.append(os.path.abspath(__file__))
            command.extend([AUTH_SHELL_SUBPROCESS_FLAG, str(request_path), str(response_path)])

            creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            profile_mark("auth_shell.spawn_subprocess")
            try:
                completed = subprocess.run(
                    command,
                    check=False,
                    timeout=None,
                    creationflags=creation_flags,
                )
            except Exception:
                logger.warning("Auth shell subprocess failed to start.", exc_info=True)
                completed = None

            if completed is None:
                show_styled_message(APP_NAME, webview_required_message("the sign-in and settings screen"), is_error=True, parent=None)
                return None
            if not response_path.exists():
                if completed.returncode != 0:
                    logger.warning("Auth shell subprocess closed without a response payload; treating as cancelled.")
                    return None
                return None

            try:
                payload = json.loads(response_path.read_text(encoding="utf-8"))
            except Exception:
                logger.warning("Auth shell subprocess returned invalid JSON.", exc_info=True)
                return None

        result = payload.get("result") if isinstance(payload, dict) else None
        if isinstance(result, dict) and str(result.get("__action__", "")).strip().lower() == "exit_app":
            exit_program(trigger_uninstall=False)
        if isinstance(result, dict) and result.get("__error__"):
            show_styled_message(APP_NAME, webview_required_message("the sign-in and settings screen"), is_error=True, parent=None)
            return None
        return result


def prompt_startup_auth(
    initial_email,
    initial_password,
    initial_blob_size="medium",
    initial_error="",
    allow_cancel=False,
):
    profile_mark("auth.prompt_startup_auth")
    should_restore_splash = False
    with startup_progress_lock:
        splash = startup_progress_window
        if splash is not None:
            should_restore_splash = not bool(getattr(splash, "hidden", True))
    startup_progress_hide()
    result = prompt_account_auth_dialog(
        initial_email=initial_email,
        initial_password=initial_password,
        initial_blob_size=initial_blob_size,
        initial_error=initial_error,
        allow_cancel=allow_cancel,
    )
    if result:
        result.setdefault("language", normalize_language(ui_language))
        result.setdefault("theme", normalize_theme_preference(ui_theme_preference))
        result.setdefault("indicator_position", normalize_indicator_position(indicator_position_key))
        result.setdefault("show_startup_screen", bool(startup_loading_screen_enabled))
        result.setdefault("preferred_model", normalize_pro_model(selected_pro_model_key))
        result.setdefault("pro_model", normalize_pro_model(selected_pro_model_key))
        result.setdefault("hotkeys", dict(command_hotkeys))
        result.setdefault("hotkey_mode", command_key_mode)
        result.setdefault("remember_me", bool(remember_me_enabled))
    if should_restore_splash:
        startup_progress_show()
    return result


def load_remembered_login_prefill():
    record = load_config_record()
    remembered = normalize_remember_me_preference(record.get("remember_me", remember_me_enabled))
    email_value = normalize_account_email(record.get("user_email", user_email))
    password_value = ""
    if remembered:
        password_value = load_saved_secret(
            record,
            "remembered_password",
            "remembered_password_dpapi",
            persist_migration=False,
        )
    return email_value, str(password_value or "")


def indicator_refresh_preferences():
    indicator_call(lambda obj: obj.refresh_preferences() if hasattr(obj, "refresh_preferences") else None)


def open_settings_menu(hide_indicator_temporarily=False):
    global settings_window_open, command_hotkeys, command_hotkeys_customized, command_key_mode
    global startup_loading_screen_enabled, auth_mode, api_key, user_email
    global local_model, local_chat_session, api_backend_name, ui_theme_preference
    with settings_window_lock:
        if settings_window_open:
            return
        settings_window_open = True
    restore_indicator_after_close = False
    try:
        if hide_indicator_temporarily and not indicator_is_hidden():
            restore_indicator_after_close = True
            indicator_hide()
        selected = prompt_startup_auth(
            initial_email=user_email,
            initial_password="",
            initial_blob_size=indicator_blob_size_key,
            allow_cancel=bool(hide_indicator_temporarily and session_active),
        )
        if not selected:
            return

        selected_email = normalize_account_email(selected.get("email", user_email))
        selected_password = str(selected.get("password", "") or "")
        current_email = normalize_account_email(user_email)
        auth_changed = bool(selected_password) or (selected_email != "" and selected_email != current_email)
        if selected_email != current_email and not selected_password:
            show_styled_message(APP_NAME, "Enter the password for the new account email.", is_error=True, parent=None)
            return

        previous_model = normalize_pro_model(selected_pro_model_key)
        if auth_changed:
            try:
                ok, message = authenticate_account_session(
                    selected_email or current_email,
                    selected_password,
                    remember_me=bool(selected.get("remember_me", remember_me_enabled)),
                    auth_snapshot=selected.get("auth_snapshot"),
                )
            except Exception as exc:
                ok, message = False, str(exc)
            if not ok:
                show_styled_message(APP_NAME, message, is_error=True, parent=None)
                return
            if not ensure_api_mode_ready(show_startup_progress=False):
                return
        else:
            apply_auth_dialog_selection(selected, persist=True)
            sync_remember_me_preference(bool(selected.get("remember_me", remember_me_enabled)), selected_password)
            if normalize_pro_model(selected_pro_model_key) != previous_model and api_key:
                if not ensure_api_mode_ready(show_startup_progress=False):
                    return
            push_remote_preferences_async()

        update_tray_menu()
        indicator_refresh_preferences()
    finally:
        if restore_indicator_after_close and not indicator_manual_hidden and not privacy_forced_hidden:
            indicator_show()
        with settings_window_lock:
            settings_window_open = False


def gui_show_error(message):
    parent = None
    splash = startup_progress_window
    splash_was_visible = False
    if parent is None and splash is not None:
        # During startup the loading screen is always-on-top.  Hide it so the
        # error dialog is visible, then restore it after the user dismisses.
        try:
            if splash.root.winfo_exists() and not splash.hidden:
                splash_was_visible = True
                splash.hide()
                parent = splash.root
        except Exception:
            pass
    show_styled_message(APP_NAME, message, is_error=True, parent=parent)
    if splash_was_visible:
        startup_progress_show()


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


def refresh_runtime_capture_privacy():
    global indicator_capture_protected, privacy_forced_hidden
    active = is_capture_privacy_active()
    indicator_capture_protected = False
    indicator_call(lambda obj: obj.refresh_capture_privacy() if hasattr(obj, "refresh_capture_privacy") else None)
    if not active:
        privacy_forced_hidden = False
        if not indicator_manual_hidden:
            indicator_show()
    update_tray_menu()


def set_capture_privacy_enabled(enabled):
    global capture_privacy_enabled
    capture_privacy_enabled = bool(enabled)
    refresh_runtime_capture_privacy()


def toggle_capture_privacy():
    set_capture_privacy_enabled(not is_capture_privacy_active())


def resolve_auth_settings():
    global auth_mode, server_url, api_key, device_id, indicator_blob_size_key
    global ui_language, indicator_position_key, selected_pro_model_key, session_status_text
    global command_hotkeys, command_hotkeys_customized, command_key_mode, startup_loading_screen_enabled
    global ui_theme_preference, user_email, session_id, session_token, session_active, model_name
    global remember_me_enabled
    record = load_config_record()
    env_language_raw = os.environ.get("EAE_LANGUAGE", "").strip()
    env_theme_raw = os.environ.get("EAE_THEME", "").strip()
    env_blob_size_raw = os.environ.get("EAE_BLOB_SIZE", "").strip()
    env_position_raw = os.environ.get("EAE_INDICATOR_POSITION", "").strip()
    env_startup_screen_raw = os.environ.get("EAE_SHOW_STARTUP_SCREEN", "").strip()
    env_blob_size = normalize_indicator_blob_size(env_blob_size_raw) if env_blob_size_raw else ""
    remember_me_enabled = normalize_remember_me_preference(record.get("remember_me", False))
    if not remember_me_enabled and (
        str(record.get("session_token_dpapi", "") or "").strip()
        or str(record.get("api_key_dpapi", "") or "").strip()
        or str(record.get("remembered_password_dpapi", "") or "").strip()
    ):
        record = clear_persisted_account_auth(record, clear_email=False)
    saved_api_key = load_saved_secret(record, "api_key", "api_key_dpapi", persist_migration=False) if remember_me_enabled else ""
    saved_session_token = load_saved_secret(record, "session_token", "session_token_dpapi", persist_migration=False) if remember_me_enabled else ""
    saved_blob_size = normalize_indicator_blob_size(record.get("indicator_blob_size", ""))
    saved_language = normalize_language(record.get("ui_language", ui_language))
    saved_theme = normalize_theme_preference(record.get("ui_theme", ui_theme_preference))
    saved_position = normalize_indicator_position(record.get("indicator_position", indicator_position_key))
    saved_startup_screen = normalize_startup_loading_screen_enabled(record.get("show_startup_screen", startup_loading_screen_enabled))
    saved_pro_model = normalize_pro_model(record.get("preferred_model", record.get("pro_model", selected_pro_model_key)))
    saved_hotkey_mode = "toprow" if str(record.get("command_key_mode", "")).strip().lower() == "toprow" else detect_initial_command_key_mode()
    saved_hotkeys, saved_hotkey_mode, saved_hotkeys_customized = resolve_command_hotkey_state(
        record.get("command_hotkeys"),
        saved_hotkey_mode,
    )
    saved_device_id = str(record.get("device_id", "")).strip()
    if not saved_device_id:
        saved_device_id = secrets.token_hex(16)
        record["device_id"] = saved_device_id
    device_id = saved_device_id
    record["auth_mode"] = "account"
    record["server_url"] = DEFAULT_SERVER_URL
    record["preferred_model"] = saved_pro_model
    record["pro_model"] = saved_pro_model
    record["remember_me"] = bool(remember_me_enabled)
    record.pop("license_code", None)
    record.pop("license_code_dpapi", None)
    mutate_config_record(
        lambda cfg: (
            cfg.update(
                {
                    "device_id": saved_device_id,
                    "auth_mode": "account",
                    "server_url": DEFAULT_SERVER_URL,
                    "preferred_model": saved_pro_model,
                    "pro_model": saved_pro_model,
                    "remember_me": bool(remember_me_enabled),
                }
            ),
            cfg.pop("license_code", None),
            cfg.pop("license_code_dpapi", None),
        )
    )

    ui_language = normalize_language(env_language_raw or saved_language or ui_language)
    ui_theme_preference = normalize_theme_preference(env_theme_raw or saved_theme or ui_theme_preference)
    apply_ui_theme_preference(ui_theme_preference)
    indicator_position_key = normalize_indicator_position(env_position_raw or saved_position or indicator_position_key)
    startup_loading_screen_enabled = normalize_startup_loading_screen_enabled(env_startup_screen_raw) if env_startup_screen_raw else saved_startup_screen
    selected_pro_model_key = normalize_pro_model(saved_pro_model)
    model_name = normalize_pro_model(selected_pro_model_key) or DEFAULT_MODEL_NAME
    command_hotkeys = dict(saved_hotkeys)
    command_hotkeys_customized = bool(saved_hotkeys_customized)
    command_key_mode = saved_hotkey_mode
    session_status_text = tr("status.not_authenticated")
    auth_mode = "account"
    server_url = DEFAULT_SERVER_URL
    api_key = saved_api_key
    user_email = normalize_account_email(record.get("user_email", ""))
    with session_lock:
        session_id = str(record.get("session_id", "") or "").strip()
        session_token = str(saved_session_token or "").strip()
        session_active = False

    indicator_blob_size_key = env_blob_size or saved_blob_size or indicator_blob_size_key
    return True


def request_json(method, path, token="", json_payload=None, files=None, timeout=30, suppress_request_log=False):
    requests_module = get_requests_module()
    session = get_http_session()
    normalized_server = normalize_server_url(server_url or DEFAULT_SERVER_URL)
    if not normalized_server:
        logger.warning("Blocked request with invalid server URL configuration.")
        raise RuntimeError("Server URL must use HTTPS unless it targets localhost.")
    normalized_path = str(path or "").strip()
    if not normalized_path.startswith("/"):
        logger.warning("Blocked request with invalid API path: %s", normalized_path)
        raise ValueError("API paths must start with '/'.")
    url = f"{normalized_server}{normalized_path}"
    headers = {"Accept": "application/json"}
    request_timeout = timeout
    if isinstance(timeout, (list, tuple)):
        if len(timeout) >= 2:
            request_timeout = (float(timeout[0]), float(timeout[1]))
    else:
        total_timeout = max(1.0, float(timeout or 0.0))
        request_timeout = (min(4.0, max(1.5, total_timeout * 0.25)), total_timeout)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with profile_span(
        "http.request",
        method=str(method or "").upper(),
        path=normalized_path,
        timeout=timeout,
        has_json=bool(json_payload is not None),
        has_files=bool(files),
    ):
        try:
            response = session.request(
                method=method,
                url=url,
                headers=headers,
                json=json_payload,
                files=files,
                timeout=request_timeout,
                allow_redirects=False,
            )
            profile_mark(
                "http.response",
                method=str(method or "").upper(),
                path=normalized_path,
                status=int(getattr(response, "status_code", 0) or 0),
                ok=bool(getattr(response, "ok", False)),
            )
            return response
        except requests_module.RequestException:
            if suppress_request_log:
                logger.debug("HTTP request failed for %s %s.", str(method or "").upper(), normalized_path, exc_info=True)
            else:
                logger.warning("HTTP request failed for %s %s.", str(method or "").upper(), normalized_path, exc_info=True)
            raise
        except Exception:
            logger.exception("Unexpected error while sending %s %s.", str(method or "").upper(), normalized_path)
            raise


def describe_request_exception(exc):
    text = str(exc or "").strip()
    lower_text = text.lower()
    requests_module = None
    try:
        requests_module = get_requests_module()
    except Exception:
        requests_module = None

    connect_timeout_type = getattr(requests_module, "ConnectTimeout", None) if requests_module is not None else None
    read_timeout_type = getattr(requests_module, "ReadTimeout", None) if requests_module is not None else None
    ssl_error_type = getattr(requests_module, "SSLError", None) if requests_module is not None else None
    connection_error_type = getattr(requests_module, "ConnectionError", None) if requests_module is not None else None

    if connect_timeout_type is not None and isinstance(exc, connect_timeout_type):
        return tr("error.network_timeout")
    if read_timeout_type is not None and isinstance(exc, read_timeout_type):
        return tr("error.network_timeout")
    if ssl_error_type is not None and isinstance(exc, ssl_error_type):
        return tr("error.network_secure")
    if connection_error_type is not None and isinstance(exc, connection_error_type):
        return tr("error.network_connect")

    if "connecttimeout" in lower_text or "timed out" in lower_text:
        return tr("error.network_timeout")
    if "ssl" in lower_text or "certificate" in lower_text:
        return tr("error.network_secure")
    if "failed to establish a new connection" in lower_text or "unreachable network" in lower_text:
        return tr("error.network_connect")

    return text or tr("error.connect_server", detail="")


def build_remote_preferences_payload():
    payload = {
        "language": normalize_language(ui_language),
        "theme": normalize_theme_preference(ui_theme_preference),
        "indicator_position": normalize_indicator_position(indicator_position_key),
        "indicator_blob_size": normalize_indicator_blob_size(indicator_blob_size_key),
        "show_startup_screen": bool(startup_loading_screen_enabled),
        "preferred_model": normalize_pro_model(selected_pro_model_key),
        "hotkey_mode": command_key_mode,
        "hotkeys": dict(command_hotkeys),
    }
    # Backward-compatible aliases for older server-side preference documents.
    payload["pro_model"] = payload["preferred_model"]
    payload["command_key_mode"] = payload["hotkey_mode"]
    payload["command_hotkeys"] = dict(command_hotkeys)
    payload["command_hotkeys_customized"] = bool(command_hotkeys_customized)
    return payload


def persist_runtime_preferences():
    def _apply(record):
        record["auth_mode"] = "account"
        record["server_url"] = DEFAULT_SERVER_URL
        record["ui_language"] = normalize_language(ui_language)
        record["ui_theme"] = normalize_theme_preference(ui_theme_preference)
        record["indicator_blob_size"] = normalize_indicator_blob_size(indicator_blob_size_key)
        record["indicator_position"] = normalize_indicator_position(indicator_position_key)
        record["show_startup_screen"] = normalize_startup_loading_screen_enabled(startup_loading_screen_enabled)
        record["preferred_model"] = normalize_pro_model(selected_pro_model_key)
        record["pro_model"] = normalize_pro_model(selected_pro_model_key)
        record["command_hotkeys"] = dict(command_hotkeys)
        record["command_key_mode"] = command_key_mode
        record["command_hotkeys_customized"] = bool(command_hotkeys_customized)
        record["user_email"] = normalize_account_email(user_email)
        if device_id:
            record["device_id"] = device_id

    mutate_config_record(_apply)


def normalize_remote_preferences_payload(payload):
    if not isinstance(payload, dict):
        return {}
    incoming_hotkeys = payload.get("hotkeys", payload.get("command_hotkeys"))
    incoming_hotkey_mode = payload.get("hotkey_mode", payload.get("command_key_mode", command_key_mode))
    normalized_hotkeys, normalized_hotkey_mode, normalized_hotkeys_customized = resolve_command_hotkey_state(
        incoming_hotkeys,
        incoming_hotkey_mode,
    )
    return {
        "language": normalize_language(payload.get("language", ui_language)),
        "theme": normalize_theme_preference(payload.get("theme", ui_theme_preference)),
        "indicator_position": normalize_indicator_position(payload.get("indicator_position", indicator_position_key)),
        "indicator_blob_size": normalize_indicator_blob_size(payload.get("indicator_blob_size", indicator_blob_size_key)),
        "show_startup_screen": normalize_startup_loading_screen_enabled(
            payload.get("show_startup_screen", startup_loading_screen_enabled)
        ),
        "preferred_model": normalize_pro_model(
            payload.get("preferred_model", payload.get("pro_model", selected_pro_model_key))
        ),
        "pro_model": normalize_pro_model(
            payload.get("preferred_model", payload.get("pro_model", selected_pro_model_key))
        ),
        "hotkeys": dict(normalized_hotkeys),
        "hotkey_mode": normalized_hotkey_mode,
        "hotkeys_customized": bool(
            payload.get("hotkeys_customized", payload.get("command_hotkeys_customized", normalized_hotkeys_customized))
        ),
    }


def apply_remote_preferences_payload(payload):
    global ui_language, ui_theme_preference, indicator_position_key, indicator_blob_size_key, model_name
    global selected_pro_model_key, startup_loading_screen_enabled
    global command_hotkeys, command_hotkeys_customized, command_key_mode
    normalized = normalize_remote_preferences_payload(payload)
    if not normalized:
        return False
    current_state = {
        "language": normalize_language(ui_language),
        "theme": normalize_theme_preference(ui_theme_preference),
        "indicator_position": normalize_indicator_position(indicator_position_key),
        "indicator_blob_size": normalize_indicator_blob_size(indicator_blob_size_key),
        "show_startup_screen": normalize_startup_loading_screen_enabled(startup_loading_screen_enabled),
        "preferred_model": normalize_pro_model(selected_pro_model_key),
        "pro_model": normalize_pro_model(selected_pro_model_key),
        "hotkeys": dict(command_hotkeys),
        "hotkey_mode": command_key_mode,
        "hotkeys_customized": bool(command_hotkeys_customized),
    }
    if normalized == current_state:
        return False
    ui_language = normalized["language"]
    ui_theme_preference = normalize_theme_preference(normalized["theme"])
    apply_ui_theme_preference(ui_theme_preference)
    indicator_position_key = normalized["indicator_position"]
    indicator_blob_size_key = normalized["indicator_blob_size"]
    startup_loading_screen_enabled = normalized["show_startup_screen"]
    selected_pro_model_key = normalized["preferred_model"]
    model_name = normalize_pro_model(selected_pro_model_key) or DEFAULT_MODEL_NAME
    command_hotkeys = dict(normalized["hotkeys"])
    command_key_mode = normalized["hotkey_mode"]
    command_hotkeys_customized = bool(normalized["hotkeys_customized"])
    persist_runtime_preferences()
    try:
        set_command_key_mode(command_key_mode)
    except Exception:
        pass
    indicator_refresh_preferences()
    return True


def apply_auth_dialog_selection(selected, persist=True):
    global ui_language, ui_theme_preference, indicator_blob_size_key, indicator_position_key
    global selected_pro_model_key, startup_loading_screen_enabled, command_hotkeys
    global command_key_mode, command_hotkeys_customized, model_name
    if not isinstance(selected, dict):
        return

    ui_language = normalize_language(selected.get("language", ui_language))
    ui_theme_preference = normalize_theme_preference(selected.get("theme", ui_theme_preference))
    indicator_blob_size_key = normalize_indicator_blob_size(selected.get("blob_size", indicator_blob_size_key))
    indicator_position_key = normalize_indicator_position(selected.get("indicator_position", indicator_position_key))
    startup_loading_screen_enabled = normalize_startup_loading_screen_enabled(
        selected.get("show_startup_screen", startup_loading_screen_enabled)
    )
    selected_pro_model_key = normalize_pro_model(
        selected.get("preferred_model", selected.get("pro_model", selected_pro_model_key))
    )
    model_name = normalize_pro_model(selected_pro_model_key) or DEFAULT_MODEL_NAME
    selected_hotkeys, selected_hotkey_mode, selected_hotkeys_customized = resolve_command_hotkey_state(
        selected.get("hotkeys"),
        selected.get("hotkey_mode", command_key_mode),
    )
    command_hotkeys = dict(selected_hotkeys)
    command_key_mode = selected_hotkey_mode
    command_hotkeys_customized = bool(selected_hotkeys_customized)
    apply_ui_theme_preference(ui_theme_preference)
    try:
        set_command_key_mode(command_key_mode)
    except Exception:
        pass
    if persist:
        persist_runtime_preferences()


def clear_account_session_state(clear_cached_api_key=False):
    global session_id, session_token, session_active, api_key, auth_mode, remember_me_enabled
    with session_lock:
        session_id = ""
        session_token = ""
        session_active = False
    auth_mode = "account"
    record = load_config_record()
    remember_me_enabled = normalize_remember_me_preference(record.get("remember_me", False))
    if clear_cached_api_key:
        api_key = ""

    def _apply(target):
        target["auth_mode"] = "account"
        target["server_url"] = DEFAULT_SERVER_URL
        target["session_id"] = ""
        remove_saved_secret(target, "session_token", "session_token_dpapi")
        if clear_cached_api_key:
            remove_saved_secret(target, "api_key", "api_key_dpapi")

    mutate_config_record(_apply)


def persist_account_session_state(email_value, session_id_value, session_token_value, api_key_value, password_value="", remember_me=False):
    failed = {"value": False}

    def _apply(record):
        record["auth_mode"] = "account"
        record["server_url"] = DEFAULT_SERVER_URL
        record["user_email"] = normalize_account_email(email_value)
        record["session_id"] = str(session_id_value or "").strip()
        record["remember_me"] = bool(remember_me)
        record["preferred_model"] = normalize_pro_model(selected_pro_model_key)
        record["pro_model"] = normalize_pro_model(selected_pro_model_key)
        if device_id:
            record["device_id"] = device_id
        record.pop("license_code", None)
        record.pop("license_code_dpapi", None)
        if not remember_me:
            record["session_id"] = ""
            remove_saved_secret(record, "session_token", "session_token_dpapi")
            remove_saved_secret(record, "api_key", "api_key_dpapi")
            remove_saved_secret(record, "remembered_password", "remembered_password_dpapi")
            return
        if not mutate_saved_secret(record, "session_token", "session_token_dpapi", str(session_token_value or "").strip()):
            failed["value"] = True
            return
        record["remember_me"] = True
        if not mutate_saved_secret(record, "api_key", "api_key_dpapi", str(api_key_value or "").strip()):
            failed["value"] = True
            return
        record["remember_me"] = True
        if not mutate_saved_secret(record, "remembered_password", "remembered_password_dpapi", str(password_value or "").strip()):
            failed["value"] = True

    mutate_config_record(_apply)
    return not failed["value"]


def app_device_name():
    value = str(os.environ.get("COMPUTERNAME", "") or "").strip()
    if value:
        return value
    value = str(os.environ.get("HOSTNAME", "") or "").strip()
    return value or "Windows PC"


def push_remote_preferences():
    with session_lock:
        local_token = str(session_token or "")
        local_active = bool(session_active)
    if not local_token or not local_active:
        return False

    try:
        response = request_json(
            "POST",
            "/api/v1/client/preferences",
            token=local_token,
            json_payload={"preferences": build_remote_preferences_payload()},
            timeout=15,
        )
        return bool(response.ok)
    except Exception:
        logger.debug("Remote preference push failed.", exc_info=True)
        return False


def push_remote_preferences_async():
    def _worker():
        delay = 0.8
        for attempt in range(3):
            try:
                if push_remote_preferences():
                    return
            except Exception:
                logger.debug("Async remote preference push failed (attempt %s).", attempt + 1, exc_info=True)
            if attempt >= 2:
                break
            time.sleep(delay)
            delay = min(4.0, delay * 2.0)

    Thread(target=_worker, daemon=True, name="preferences-push").start()


def extract_remote_preferences_blob(payload):
    if isinstance(payload, dict):
        if any(key in payload for key in ("hotkeys", "hotkey_mode", "indicator_position", "preferred_model")):
            return payload, str(payload.get("preferences_updated_at", "") or "")

        direct = payload.get("preferences")
        if isinstance(direct, dict):
            return direct, str(payload.get("preferences_updated_at", "") or "")

        nested = payload.get("data")
        if isinstance(nested, dict):
            nested_prefs = nested.get("preferences")
            if isinstance(nested_prefs, dict):
                return nested_prefs, str(nested.get("preferences_updated_at", payload.get("preferences_updated_at", "")) or "")

        if isinstance(direct, str):
            try:
                parsed = json.loads(direct)
            except Exception:
                parsed = None
            if isinstance(parsed, dict):
                return parsed, str(payload.get("preferences_updated_at", "") or "")
    return None, ""


def pull_remote_preferences_with_token(local_token):
    token_value = str(local_token or "").strip()
    if not token_value:
        return None, ""
    try:
        response = request_json("GET", "/api/v1/client/preferences", token=token_value, timeout=15)
        if not response.ok:
            return None, ""
        data = decode_json_response(response, "Remote preferences")
    except Exception:
        logger.debug("Remote preference pull failed.", exc_info=True)
        return None, ""
    if not isinstance(data, dict):
        return None, ""
    return extract_remote_preferences_blob(data)


def pull_remote_preferences():
    with session_lock:
        local_token = str(session_token or "")
    return pull_remote_preferences_with_token(local_token)


def sync_remote_preferences_after_auth(auth_data):
    applied = False
    remote_payload, _remote_updated_at = extract_remote_preferences_blob(auth_data)
    if isinstance(remote_payload, dict):
        applied = bool(apply_remote_preferences_payload(remote_payload)) or applied

    pulled_payload, _remote_updated_at = pull_remote_preferences()
    if isinstance(pulled_payload, dict):
        applied = bool(apply_remote_preferences_payload(pulled_payload)) or applied

    return applied


def request_account_login_snapshot(email_value, password_value):
    with profile_span("auth.request_login_snapshot"):
        normalized_email = normalize_account_email(email_value)
        password_text = str(password_value or "")
        if not normalized_email:
            return False, tr("auth.validation.account.email.empty")
        if not password_text:
            return False, tr("auth.validation.account.password.empty")

        try:
            response = request_json(
                "POST",
                "/api/v1/client/login",
                json_payload={
                    "email": normalized_email,
                    "password": password_text,
                    "device_id": device_id,
                    "device_name": app_device_name(),
                    "app_version": APP_VERSION,
                },
                timeout=20,
            )
        except Exception as exc:
            return False, describe_request_exception(exc)
        payload = decode_json_response(response, "App login")
        if not isinstance(payload, dict):
            return False, tr("error.server_non_json", status_code=getattr(response, "status_code", "?"))
        if not response.ok or not bool(payload.get("success")):
            message = str(payload.get("message", "") or f"Sign-in failed ({getattr(response, 'status_code', '?')}).").strip()
            if payload.get("password_setup_required"):
                open_dashboard_page("dashboard-security")
            return False, message
        if payload.get("password_setup_required"):
            open_dashboard_page("dashboard-security")
            return False, "Finish creating a password on the website before using the desktop app."
        if payload.get("api_key_required") or not isinstance(payload.get("api_key_bundle"), dict):
            open_dashboard_page("dashboard-app-access")
            return False, "Add your Gemini API key in the dashboard before using the desktop app."
        try:
            decrypted_api_key = decode_account_api_key_bundle(payload.get("api_key_bundle"), password_text)
        except Exception as exc:
            open_dashboard_page("dashboard-app-access")
            return False, str(exc)
        next_session_id = str(payload.get("session_id", "") or "").strip()
        next_session_token = str(payload.get("session_token", "") or "").strip()
        if not next_session_token:
            return False, "The website did not return a valid desktop session."
        return True, {
            "email": normalized_email,
            "password": password_text,
            "session_id": next_session_id,
            "session_token": next_session_token,
            "api_key": decrypted_api_key,
            "message": str(payload.get("message", "") or "Signed in."),
            "payload": payload,
        }


def request_account_preferences_preview(email_value, password_value="", live_session_token="", live_session_email=""):
    normalized_email = normalize_account_email(email_value)
    if not normalized_email:
        return False, tr("auth.validation.account.email.empty")
    preview_snapshot = None
    remote_payload = None
    remote_updated_at = ""
    live_token = str(live_session_token or "").strip()
    if live_token and normalized_email == normalize_account_email(live_session_email):
        remote_payload, remote_updated_at = pull_remote_preferences_with_token(live_token)
    if remote_payload is None:
        ok, snapshot_or_message = request_account_login_snapshot(normalized_email, password_value)
        if not ok:
            return False, snapshot_or_message
        preview_snapshot = snapshot_or_message
        payload = preview_snapshot.get("payload") if isinstance(preview_snapshot, dict) else {}
        remote_payload = payload.get("preferences") if isinstance(payload, dict) else None
        remote_updated_at = str(payload.get("preferences_updated_at", "") or "") if isinstance(payload, dict) else ""
        if remote_payload is None:
            remote_payload, remote_updated_at = pull_remote_preferences_with_token(preview_snapshot.get("session_token"))
    normalized_preferences = normalize_remote_preferences_payload(remote_payload)
    if not normalized_preferences:
        return False, "Could not import the synced settings from your account."
    return True, {
        "preferences": normalized_preferences,
        "preferences_updated_at": remote_updated_at,
        "auth_snapshot": preview_snapshot,
    }


def apply_authenticated_account_snapshot(snapshot, remember_me=False, password_value=""):
    global auth_mode, server_url, api_key, user_email
    global session_id, session_token, session_active, remember_me_enabled
    if not isinstance(snapshot, dict):
        return False, "Invalid account session."
    normalized_email = normalize_account_email(snapshot.get("email", ""))
    next_session_id = str(snapshot.get("session_id", "") or "").strip()
    next_session_token = str(snapshot.get("session_token", "") or "").strip()
    decrypted_api_key = str(snapshot.get("api_key", "") or "").strip()
    if not normalized_email or not next_session_token or not decrypted_api_key:
        return False, "The website did not return a valid desktop session."
    auth_mode = "account"
    server_url = DEFAULT_SERVER_URL
    user_email = normalized_email
    api_key = decrypted_api_key
    remember_me_enabled = bool(remember_me)
    with session_lock:
        session_id = next_session_id
        session_token = next_session_token
        session_active = True
    if not persist_account_session_state(
        normalized_email,
        next_session_id,
        next_session_token,
        decrypted_api_key,
        password_value=password_value or snapshot.get("password", ""),
        remember_me=remember_me_enabled,
    ):
        clear_account_session_state(clear_cached_api_key=True)
        return False, "Could not securely store the account session on this machine."
    sync_remote_preferences_after_auth(snapshot.get("payload"))
    set_session_status(tr("status.code_active"), active=True)
    return True, str(snapshot.get("message", "") or "Signed in.")


def _refresh_cached_session_after_boot(local_email, cached_password):
    local_session_token = ""
    with session_lock:
        local_session_token = str(session_token or "").strip()
    if not local_session_token:
        return
    try:
        response = request_json("GET", "/api/v1/client/preferences", token=local_session_token, timeout=(3.5, 10.0))
        if int(getattr(response, "status_code", 0) or 0) == 401:
            if cached_password:
                ok, snapshot_or_message = request_account_login_snapshot(local_email, cached_password)
                if ok:
                    apply_authenticated_account_snapshot(
                        snapshot_or_message,
                        remember_me=True,
                        password_value=cached_password,
                    )
                    return
            clear_persisted_account_auth(clear_email=False)
            clear_account_session_state(clear_cached_api_key=True)
            return
        if response.ok:
            payload = decode_json_response(response, "Remote preferences")
            if isinstance(payload, dict):
                apply_remote_preferences_payload(payload.get("preferences"))
    except Exception:
        logger.debug("Deferred cached-session refresh failed.", exc_info=True)


def restore_cached_account_session():
    with profile_span("auth.restore_cached_account_session"):
        global auth_mode, api_key, user_email, server_url, remember_me_enabled
        global session_id, session_token, session_active
        record = load_config_record()
        remember_me_enabled = normalize_remember_me_preference(record.get("remember_me", False))
        if not remember_me_enabled:
            return False
        cached_email = normalize_account_email(record.get("user_email", ""))
        cached_api_key = load_saved_secret(record, "api_key", "api_key_dpapi", persist_migration=False)
        cached_session_token = load_saved_secret(record, "session_token", "session_token_dpapi", persist_migration=False)
        cached_session_id = str(record.get("session_id", "") or "").strip()
        cached_password = load_saved_secret(record, "remembered_password", "remembered_password_dpapi", persist_migration=False)
        if not cached_email:
            return False
        auth_mode = "account"
        server_url = DEFAULT_SERVER_URL
        if cached_api_key and cached_session_token:
            user_email = cached_email
            api_key = cached_api_key
            with session_lock:
                session_id = cached_session_id
                session_token = cached_session_token
                session_active = True
            set_session_status(tr("status.code_active"), active=True)
            try:
                payload, _updated_at = pull_remote_preferences_with_token(cached_session_token)
                if isinstance(payload, dict):
                    apply_remote_preferences_payload(payload)
            except Exception:
                logger.debug("Initial cached-session preference pull failed.", exc_info=True)
            Thread(
                target=_refresh_cached_session_after_boot,
                args=(cached_email, cached_password),
                daemon=True,
                name="session-refresh",
            ).start()
            return True
        if cached_password:
            result = {"ok": False, "snapshot": None}
            completed = Event()

            def _cached_login_worker():
                try:
                    ok, snapshot_or_message = request_account_login_snapshot(cached_email, cached_password)
                    if ok:
                        result["ok"] = True
                        result["snapshot"] = snapshot_or_message
                except Exception:
                    logger.debug("Cached password login failed.", exc_info=True)
                finally:
                    completed.set()

            Thread(target=_cached_login_worker, daemon=True, name="cached-login").start()
            if completed.wait(1.2) and result.get("ok"):
                success, _message = apply_authenticated_account_snapshot(
                    result.get("snapshot"),
                    remember_me=True,
                    password_value=cached_password,
                )
                return bool(success)
            return False
        clear_persisted_account_auth(record, clear_email=False)
        return False


def authenticate_account_session(email_value, password_value, remember_me=False, auth_snapshot=None):
    with profile_span("auth.authenticate_account_session", remember_me=bool(remember_me)):
        normalized_email = normalize_account_email(email_value)
        snapshot = auth_snapshot if isinstance(auth_snapshot, dict) else None
        if not snapshot or normalize_account_email(snapshot.get("email", "")) != normalized_email:
            ok, snapshot_or_message = request_account_login_snapshot(normalized_email, password_value)
            if not ok:
                return False, snapshot_or_message
            snapshot = snapshot_or_message
        return apply_authenticated_account_snapshot(snapshot, remember_me=remember_me, password_value=password_value)


def sync_remember_me_preference(remember_me, password_value=""):
    global remember_me_enabled
    remember_me_enabled = bool(remember_me)
    local_email = normalize_account_email(user_email)
    local_api_key = str(api_key or "").strip()
    local_session_id = ""
    local_session_token = ""
    local_active = False
    with session_lock:
        local_session_id = str(session_id or "").strip()
        local_session_token = str(session_token or "").strip()
        local_active = bool(session_active)
    if not remember_me_enabled:
        clear_persisted_account_auth(clear_email=False)
        return True
    if not local_email or not local_api_key or not local_session_token or not local_active:
        mutate_config_record(lambda record: record.update({"remember_me": True}))
        return True
    stored_password = str(password_value or "").strip()
    if not stored_password:
        stored_password = load_saved_secret(load_config_record(), "remembered_password", "remembered_password_dpapi", persist_migration=False)
    return persist_account_session_state(
        local_email,
        local_session_id,
        local_session_token,
        local_api_key,
        password_value=stored_password,
        remember_me=True,
    )


class _SimpleApiResponse:
    def __init__(self, text):
        self.text = str(text or "")


def prepare_prompt_image(image):
    if not isinstance(image, PIL.Image.Image):
        raise TypeError("prepare_prompt_image expects a PIL image.")
    working_image = image
    width = int(getattr(working_image, "width", 0) or 0)
    height = int(getattr(working_image, "height", 0) or 0)
    max_edge = max(width, height)
    if max_edge > FAST_UPLOAD_MAX_EDGE:
        scale = float(FAST_UPLOAD_MAX_EDGE) / float(max_edge)
        resized = working_image.copy()
        resampling = getattr(getattr(PIL.Image, "Resampling", PIL.Image), "LANCZOS", PIL.Image.LANCZOS)
        resized.thumbnail(
            (
                max(1, int(round(width * scale))),
                max(1, int(round(height * scale))),
            ),
            resampling,
        )
        working_image = resized
    stream = io.BytesIO()
    encoded_image = working_image if getattr(working_image, "mode", "") == "RGB" else working_image.convert("RGB")
    encoded_image.save(
        stream,
        format="JPEG",
        quality=FAST_UPLOAD_JPEG_QUALITY,
        optimize=True,
    )
    payload = stream.getvalue()
    if working_image is not image:
        try:
            working_image.close()
        except Exception:
            pass
    if encoded_image is not working_image:
        try:
            encoded_image.close()
        except Exception:
            pass
    return payload, "image/jpeg"


class ModernGenAiSession:
    def __init__(self, module, local_api_key, local_model_name):
        self.module = module
        self.client = module.Client(api_key=local_api_key)
        self.model_name = local_model_name

    def reset(self):
        return

    def _coerce_payload(self, payload):
        parts = []
        part_type = getattr(getattr(self.module, "types", None), "Part", None)
        for item in payload:
            if isinstance(item, PIL.Image.Image):
                image_bytes, mime_type = prepare_prompt_image(item)
                if part_type and hasattr(part_type, "from_bytes"):
                    parts.append(part_type.from_bytes(data=image_bytes, mime_type=mime_type))
                else:
                    parts.append({"mime_type": mime_type, "data": image_bytes})
            else:
                parts.append(str(item))
        return parts

    def send_message(self, payload):
        contents = self._coerce_payload(payload)
        last_error = None
        request_models = build_genai_request_models(self.model_name)
        for model_index, candidate_model in enumerate(request_models):
            for attempt in range(1, GENAI_TRANSIENT_RETRY_ATTEMPTS + 1):
                try:
                    response = self.client.models.generate_content(model=candidate_model, contents=contents)
                    if candidate_model != self.model_name:
                        logger.warning(
                            "Gemini request fell back from '%s' to '%s' after temporary overload.",
                            self.model_name,
                            candidate_model,
                        )
                    return _SimpleApiResponse(extract_text_from_genai_response(response))
                except Exception as exc:
                    last_error = exc
                    if not is_retryable_genai_request_error(exc):
                        raise
                    if attempt < GENAI_TRANSIENT_RETRY_ATTEMPTS:
                        delay_seconds = min(
                            float(GENAI_TRANSIENT_RETRY_MAX_DELAY_SECONDS),
                            float(GENAI_TRANSIENT_RETRY_BASE_DELAY_SECONDS) * (2 ** (attempt - 1)),
                        )
                        logger.warning(
                            "Gemini request temporary failure for model '%s' (attempt %s/%s): %s",
                            candidate_model,
                            attempt,
                            GENAI_TRANSIENT_RETRY_ATTEMPTS,
                            exc,
                        )
                        time.sleep(delay_seconds)
                        continue
                    break
            if model_index + 1 < len(request_models):
                logger.warning(
                    "Gemini model '%s' remained temporarily unavailable after %s attempts; trying '%s'.",
                    candidate_model,
                    GENAI_TRANSIENT_RETRY_ATTEMPTS,
                    request_models[model_index + 1],
                )
        if last_error is not None and is_retryable_genai_request_error(last_error):
            raise RuntimeError("Gemini is temporarily busy. Try the scan again in a few seconds.") from last_error
        raise last_error if last_error is not None else RuntimeError("Gemini request failed.")


def extract_api_error_status_code(error):
    if error is None:
        return 0
    for attr_name in ("status_code", "code"):
        try:
            value = int(getattr(error, attr_name, 0) or 0)
            if 100 <= value <= 599:
                return value
        except Exception:
            pass
    response = getattr(error, "response", None)
    if response is not None:
        try:
            value = int(getattr(response, "status_code", 0) or 0)
            if 100 <= value <= 599:
                return value
        except Exception:
            pass
    response_json = getattr(error, "response_json", None)
    if isinstance(response_json, dict):
        try:
            value = int((response_json.get("error") or {}).get("code", 0) or 0)
            if 100 <= value <= 599:
                return value
        except Exception:
            pass
    match = re.search(r"\b(500|502|503|504)\b", str(error or ""))
    if match:
        try:
            return int(match.group(1))
        except Exception:
            return 0
    return 0


def is_retryable_genai_request_error(error):
    status_code = extract_api_error_status_code(error)
    if status_code in GENAI_TRANSIENT_STATUS_CODES:
        return True
    lower = str(error or "").strip().lower()
    if not lower:
        return False
    return any(marker in lower for marker in GENAI_TRANSIENT_ERROR_MARKERS)


def is_temporary_genai_busy_error(error):
    lower = str(error or "").strip().lower()
    if "temporarily busy" in lower or "scan again in a few seconds" in lower:
        return True
    return is_retryable_genai_request_error(error)


def build_genai_request_models(primary_model):
    ordered = []
    for candidate in (str(primary_model or "").strip(), FREE_MODEL_NAME):
        if candidate and candidate not in ordered:
            ordered.append(candidate)
    return ordered or [FREE_MODEL_NAME]


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
    global _modern_genai_module, _modern_genai_import_attempted
    if _modern_genai_import_attempted:
        if _modern_genai_module is not None:
            return "google.genai", _modern_genai_module, ""
        return "", None, "google.genai unavailable"
    try:
        with profile_span("runtime.import_google_genai"):
            with profile_suspend_calls():
                from google import genai as modern_genai

        _modern_genai_import_attempted = True
        _modern_genai_module = modern_genai
        return "google.genai", modern_genai, ""
    except Exception as modern_exc:
        _modern_genai_import_attempted = True
        _modern_genai_module = None
        return "", None, f"google.genai unavailable ({modern_exc})"


def initialize_api_runtime():
    with profile_span("api.initialize_runtime", model=model_name):
        if not api_key:
            raise RuntimeError("API key is empty.")

        backend_name, backend_module, backend_error = resolve_genai_backend()
        if not backend_module:
            raise RuntimeError(backend_error or tr("error.no_sdk", detail="No Gemini SDK available."))

        if backend_name == "google.genai":
            return {
                "backend_name": backend_name,
                "model": None,
                "chat_session": ModernGenAiSession(backend_module, api_key, model_name),
            }

        raise RuntimeError(tr("error.no_sdk", detail="Unsupported Gemini SDK backend."))


def ensure_api_mode_ready(show_startup_progress=True):
    global local_model, local_chat_session, api_backend_name, model_name
    if not api_key:
        gui_show_error(tr("error.api_empty"))
        return False
    model_name = normalize_pro_model(selected_pro_model_key) or DEFAULT_MODEL_NAME
    try:
        stage_key = "startup.initializing_model" if show_startup_progress else None
        runtime = run_startup_background_task(initialize_api_runtime, stage_key=stage_key)
        local_model = runtime["model"]
        local_chat_session = runtime["chat_session"]
        api_backend_name = runtime["backend_name"]
    except Exception as exc:
        local_model = None
        local_chat_session = None
        api_backend_name = "none"
        issue_kind = classify_api_runtime_issue(exc)
        if issue_kind == "credits":
            gui_show_error(tr("error.api_credits"))
        elif issue_kind == "invalid":
            gui_show_error(tr("error.api_invalid"))
        else:
            gui_show_error(tr("error.api_init", detail=exc))
        return False
    set_session_status(tr("status.api_active", backend=api_backend_name), active=True)
    return True


def classify_api_runtime_issue(error_text):
    text = str(error_text or "")
    lower = text.lower()
    invalid_markers = (
        "api key not valid",
        "invalid api key",
        "api_key_invalid",
        "invalid_argument",
        "permission denied",
        "permission_denied",
        "api mode not initialized",
        "api key is empty",
        "unauthenticated",
        "401",
    )
    credit_markers = (
        "resource_exhausted",
        "quota",
        "insufficient",
        "billing",
        "credit",
        "rate limit",
        "429",
        "exceeded",
    )
    if any(marker in lower for marker in invalid_markers):
        return "invalid"
    if any(marker in lower for marker in credit_markers):
        return "credits"
    return ""


def refresh_api_key_via_startup_ui(issue_kind):
    if str(issue_kind) == "credits":
        message = tr("error.api_credits")
        status_text = tr("status.api_credits")
    else:
        message = tr("error.api_invalid")
        status_text = tr("status.api_invalid")

    set_session_status(status_text, active=False)
    deactivate_post_type_guard()
    disable_typing_mode()
    clear_answer_state()
    indicator_set_idle()
    clear_account_session_state(clear_cached_api_key=True)
    open_dashboard_page("dashboard-app-access")
    show_styled_message(
        APP_NAME,
        f"{message}\n\nUpdate or replace the Gemini API key from the dashboard, then sign in again.",
        is_error=True,
        parent=None,
    )
    return False


def ensure_account_mode_ready(initial_error_message=""):
    with profile_span("auth.ensure_account_mode_ready"):
        remembered_email, remembered_password = load_remembered_login_prefill()
        initial_email = normalize_account_email(remembered_email or user_email)
        initial_password = str(remembered_password or "")
        error_message = str(initial_error_message or "")

        while True:
            selected = prompt_startup_auth(
                initial_email=initial_email,
                initial_password=initial_password,
                initial_blob_size=indicator_blob_size_key,
                initial_error=error_message,
            )
            if not selected:
                return False

            initial_email = normalize_account_email(selected.get("email", initial_email))
            password_value = str(selected.get("password", "") or "")
            if not password_value:
                error_message = "Enter your password."
                initial_password = ""
                continue

            try:
                ok, message = run_startup_background_task(
                    lambda: authenticate_account_session(
                        initial_email,
                        password_value,
                        remember_me=bool(selected.get("remember_me", remember_me_enabled)),
                        auth_snapshot=selected.get("auth_snapshot"),
                    ),
                    stage_key="startup.connecting_pro",
                )
            except Exception as exc:
                ok, message = False, str(exc)
            if ok:
                indicator_refresh_preferences()
                update_tray_menu()
                return ensure_api_mode_ready()
            error_message = str(message or "Could not sign in.").strip()
            initial_password = password_value


def initialize_auth_mode():
    if restore_cached_account_session():
        if ensure_api_mode_ready(show_startup_progress=False):
            return True
        clear_account_session_state(clear_cached_api_key=True)
        return ensure_account_mode_ready(
            "Finish setup by adding your Gemini API key in the dashboard, then sign in again."
        )
    return ensure_account_mode_ready()


def end_remote_session():
    with profile_span("auth.end_remote_session"):
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
                "/api/v1/client/logout",
                token=local_session_token,
                json_payload={"session_id": local_session_id},
                timeout=(1.5, 2.0),
                suppress_request_log=True,
            )
        except BaseException:
            logger.debug("Remote session shutdown request failed.", exc_info=True)
        finally:
            clear_account_session_state(clear_cached_api_key=False)


def list_running_process_snapshot():
    global process_snapshot_cache_at, process_snapshot_cache_running, process_snapshot_cache_pid
    running_names = set()
    pid_to_name = {}
    if os.name != "nt" or not STRICT_PRIVACY_FALLBACK:
        return running_names, pid_to_name
    now = time.monotonic()
    with process_snapshot_cache_lock:
        if process_snapshot_cache_running and (now - process_snapshot_cache_at) < PROCESS_SNAPSHOT_CACHE_SECONDS:
            return set(process_snapshot_cache_running), dict(process_snapshot_cache_pid)
    psutil_module = get_psutil_module()
    if psutil_module is not None:
        try:
            for proc in psutil_module.process_iter(attrs=("pid", "name")):
                info = getattr(proc, "info", {}) or {}
                name = str(info.get("name", "") or "").strip().lower()
                if not name:
                    continue
                running_names.add(name)
                try:
                    pid_to_name[int(info.get("pid", 0))] = name
                except Exception:
                    pass
        except Exception:
            running_names.clear()
            pid_to_name.clear()
        if running_names:
            with process_snapshot_cache_lock:
                process_snapshot_cache_at = now
                process_snapshot_cache_running = set(running_names)
                process_snapshot_cache_pid = dict(pid_to_name)
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

    import csv

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
    with process_snapshot_cache_lock:
        process_snapshot_cache_at = now
        process_snapshot_cache_running = set(running_names)
        process_snapshot_cache_pid = dict(pid_to_name)
    return running_names, pid_to_name


def is_google_meet_window_active(pid_to_name):
    if os.name != "nt":
        return False
    try:
        hwnd = _user32.GetForegroundWindow()
        if not hwnd:
            return False
        title = get_window_text_safe(hwnd, timeout_ms=50, max_chars=512).lower()
        if not title or not any(keyword in title for keyword in PRIVACY_MEET_WINDOW_KEYWORDS):
            return False
        process_id = wintypes.DWORD(0)
        _user32.GetWindowThreadProcessId(hwnd, ctypes.byref(process_id))
        return pid_to_name.get(int(process_id.value), "") in PRIVACY_MEET_BROWSERS
    except Exception:
        return False


def set_privacy_required_by_process(value):
    global privacy_required_by_process
    with privacy_process_state_lock:
        privacy_required_by_process = bool(value)


def get_privacy_required_by_process():
    with privacy_process_state_lock:
        return bool(privacy_required_by_process)


def privacy_process_monitor_loop():
    set_current_thread_low_priority()
    interval_fast = max(1.0, min(PRIVACY_GUARD_INTERVAL_SECONDS, 2.0))
    interval_slow = max(4.0, interval_fast * 3.0)
    wait_seconds = interval_slow
    try:
        while not privacy_guard_stop_event.is_set():
            capture_process_active = False
            if STRICT_PRIVACY_FALLBACK and is_capture_privacy_active():
                running, pid_to_name = list_running_process_snapshot()
                capture_process_active = bool(running.intersection(PRIVACY_GUARD_PROCESSES)) or is_google_meet_window_active(pid_to_name)
            set_privacy_required_by_process(capture_process_active)
            wait_seconds = interval_fast if capture_process_active else interval_slow
            if privacy_guard_stop_event.wait(wait_seconds):
                break
    finally:
        set_privacy_required_by_process(False)


def privacy_guard_loop():
    global privacy_forced_hidden
    interval_fast = max(1.0, min(PRIVACY_GUARD_INTERVAL_SECONDS, 2.0))
    interval_slow = max(4.0, interval_fast * 3.0)
    wait_seconds = interval_slow
    while not privacy_guard_stop_event.is_set():
        should_force_hide = False
        capture_process_active = bool(
            STRICT_PRIVACY_FALLBACK
            and is_capture_privacy_active()
            and get_privacy_required_by_process()
        )
        if capture_process_active and not indicator_capture_protected:
            should_force_hide = True
        wait_seconds = interval_fast if capture_process_active else interval_slow

        if should_force_hide != privacy_forced_hidden:
            privacy_forced_hidden = should_force_hide
            indicator_debug(
                "indicator.privacy_force_hide_changed",
                forced=privacy_forced_hidden,
                capture_process_active=capture_process_active,
                indicator_capture_protected=indicator_capture_protected,
            )
            if privacy_forced_hidden:
                indicator_hide()
            else:
                if not indicator_manual_hidden:
                    indicator_show()

        if privacy_guard_stop_event.wait(wait_seconds):
            break


def start_privacy_guard():
    global privacy_guard_thread, privacy_process_thread
    if os.name != "nt" or not STRICT_PRIVACY_FALLBACK:
        return
    set_privacy_required_by_process(False)
    privacy_guard_stop_event.clear()
    if privacy_process_thread is None or not privacy_process_thread.is_alive():
        privacy_process_thread = Thread(target=privacy_process_monitor_loop, daemon=True, name="privacy-process-monitor")
        privacy_process_thread.start()
    if privacy_guard_thread is not None and privacy_guard_thread.is_alive():
        return
    privacy_guard_thread = Thread(target=privacy_guard_loop, daemon=True, name="privacy-guard")
    privacy_guard_thread.start()


class Win32StatusIndicator:
    WM_DISPATCH = WM_APP + 0x431
    TIMER_FRAME = 0x501
    TIMER_NATIVE = 0x502
    TIMER_COLLAPSE = 0x503
    TIMER_CLICK = 0x504
    TEXT_SPACING = 4

    def __init__(self):
        ensure_ui_crisp_mode()
        self.hidden = True
        self.state = "idle"
        self.command_mode = str(command_key_mode).strip().lower() or "numpad"
        self.current_char = ""
        self.answer_preview = ""
        self.answer_progress_index = 0
        self.answer_preview_expires_at = 0.0
        self.cooldown_until = 0.0
        self.hover_inside = False
        self.panel_pinned = False
        self.panel_scroll_offset = 0
        self.panel_scroll_max = 0
        self.progress_rendered_at = 0.0
        self.progress_rendered_index = -1
        self._thread_id = 0
        self._thread_error = None
        self._hwnd_ready = Event()
        self._mouse_tracking = False
        self._timer_delays = {}
        self._last_render_signature = None
        self._surface_cache = OrderedDict()
        self._rendered_surface_cache = OrderedDict()
        self._render_cache_lock = Lock()
        self._render_request_lock = Lock()
        self._render_request_event = Event()
        self._render_stop_event = Event()
        self._render_pending_snapshot = None
        self._render_pending_signature = None
        self._render_inflight_signature = None
        self._screen_width = 1920
        self._screen_height = 1080
        self.hwnd = 0
        self._class_name = f"EyesAndEarsIndicatorWindow.{os.getpid()}.{id(self)}"
        self._wndproc = WNDPROC(self._wndproc_impl)
        self._update_screen_metrics()
        self._apply_size_metrics()
        self.current_width = self.collapsed_width
        self.current_height = self.collapsed_height
        self.current_x = 0
        self.current_y = 0
        self.target_width = self.collapsed_width
        self.target_height = self.collapsed_height
        self._render_thread = Thread(target=self._render_thread_main, daemon=True, name="indicator-render")
        self._render_thread.start()
        self._thread = Thread(target=self._thread_main, daemon=False, name="indicator-ui")
        self._thread.start()
        if not self._hwnd_ready.wait(5.0):
            raise RuntimeError("Indicator window initialization timed out.")
        if self._thread_error is not None:
            raise RuntimeError("Indicator window initialization failed.") from self._thread_error

    def _on_ui_thread(self):
        return int(threading.get_ident()) == int(self._thread_id or 0)

    def _enqueue(self, callback):
        try:
            indicator_dispatch_queue.put(callback)
            self.wake_dispatch()
        except Exception:
            logger.debug("Indicator callback queueing failed.", exc_info=True)

    def wake_dispatch(self):
        try:
            hwnd = int(self.hwnd or 0)
        except Exception:
            hwnd = 0
        if hwnd:
            try:
                _user32.PostMessageW(wintypes.HWND(hwnd), self.WM_DISPATCH, 0, 0)
            except Exception:
                pass

    def _clear_render_caches(self):
        with self._render_cache_lock:
            self._surface_cache.clear()
            self._rendered_surface_cache.clear()

    def _cache_rendered_surface(self, signature, rendered):
        ordered_cache_set(
            self._rendered_surface_cache,
            signature,
            rendered,
            8,
            lock=self._render_cache_lock,
        )

    def _get_cached_rendered_surface(self, signature):
        return ordered_cache_get(
            self._rendered_surface_cache,
            signature,
            lock=self._render_cache_lock,
        )

    def _request_render(self, snapshot):
        signature = snapshot.get("signature")
        with self._render_request_lock:
            if signature == self._render_pending_signature or signature == self._render_inflight_signature:
                return
            self._render_pending_snapshot = dict(snapshot)
            self._render_pending_signature = signature
            self._render_request_event.set()

    def _update_screen_metrics(self):
        if os.name != "nt":
            return
        try:
            self._screen_width = max(640, int(ctypes.windll.user32.GetSystemMetrics(0)))
            self._screen_height = max(480, int(ctypes.windll.user32.GetSystemMetrics(1)))
        except Exception:
            self._screen_width = 1920
            self._screen_height = 1080

    def _apply_size_metrics(self):
        self.base_size = int(INDICATOR_BLOB_SIZES.get(indicator_blob_size_key, INDICATOR_BLOB_SIZES["medium"]))
        self.collapsed_padding = max(4, int(round(self.base_size * 0.22)))
        self.expanded_chip_padding = max(6, int(round(self.base_size * 0.24)))
        self.collapsed_width = self.base_size + (self.collapsed_padding * 3)
        self.collapsed_height = self.collapsed_width
        self.panel_corner_radius = max(18, int(self.base_size * 1.05))
        self.panel_padding = max(14, int(self.base_size * 0.78))
        self.gap = max(12, int(self.base_size * 0.72))
        self.chip_corner_radius = max(8, compute_indicator_chip_corner_radius(self.base_size + self.expanded_chip_padding))
        size_key = normalize_indicator_blob_size(indicator_blob_size_key)
        body_font_min = {
            "very_small": 12,
            "small": 14,
            "medium": 15,
            "large": 16,
        }.get(size_key, 15)
        char_font_min = {
            "very_small": 10,
            "small": 12,
            "medium": 13,
            "large": 14,
        }.get(size_key, 13)
        self.body_font = get_ui_image_font(max(body_font_min, int(round(self.base_size * 0.78))), bold=False)
        self.char_font = get_ui_image_font(max(char_font_min, int(round(self.base_size * 0.62))), bold=True)
        self.control_hint_text = self._build_control_hint_text()
        self.max_panel_width = max(340, min(560, int(self._screen_width * 0.34)))

    def _work_area(self):
        return get_window_monitor_work_area(self.hwnd, self._screen_width, self._screen_height)

    def _anchor_side(self):
        layout = INDICATOR_POSITIONS.get(normalize_indicator_position(indicator_position_key), INDICATOR_POSITIONS["bottom_right"])
        return "left" if layout["x"] == "left" else "right"

    def _panel_text(self):
        if self.answer_preview and self._panel_requested():
            return self.answer_preview
        if self.state == "cooldown":
            return tr("indicator.cooldown", language=ui_language, seconds=self._cooldown_seconds_remaining())
        return self.control_hint_text if self.state == "idle" else ""

    def _build_control_hint_text(self):
        lines = []
        for action in HOTKEY_ACTION_ORDER:
            lines.append(f"{hotkey_binding_label(command_hotkeys.get(action, ''))} {hotkey_action_label(action, language=ui_language)}")
        lines.append(tr("auth.hotkey.settings", language=ui_language))
        return "\n".join(line for line in lines if line)

    def _measure_layout(self, text, wrap_width):
        return layout_wrapped_text(text, self.body_font, wrap_width, spacing=self.TEXT_SPACING)

    def _panel_requested(self):
        return bool(self.panel_pinned or self.hover_inside)

    def _desired_size(self):
        if not self._panel_requested() or not (self.answer_preview or self.state in {"idle", "cooldown"}):
            return self.collapsed_width, self.collapsed_height
        chip_size = self.base_size + self.expanded_chip_padding
        chip_space = chip_size + self.gap
        wrap_width = max(240, min(self.max_panel_width - chip_space - (self.panel_padding * 2) - 20, 380))
        layout = self._measure_layout(self._panel_text(), wrap_width)
        width = int(min(self.max_panel_width, max(self.collapsed_width + 180, chip_space + wrap_width + (self.panel_padding * 2) + 18)))
        bottom_reserve = max(18, int(self.panel_padding * 0.9)) + (18 if self.answer_preview else 0)
        desired_height = int(max(self.collapsed_height + 44, int(layout["height"]) + (self.panel_padding * 2) + bottom_reserve))
        work_left, work_top, work_right, work_bottom = self._work_area()
        usable_height = max(1, int(work_bottom) - int(work_top) - (INDICATOR_MARGIN_Y * 2))
        max_height = int(max(self.collapsed_height + 44, usable_height * INDICATOR_PANEL_MAX_HEIGHT_RATIO))
        return width, int(min(desired_height, max_height))

    def _chip_rect(self, expanded, snapshot=None):
        source = snapshot if isinstance(snapshot, dict) else {}
        base_size = int(source.get("base_size", self.base_size))
        expanded_chip_padding = int(source.get("expanded_chip_padding", self.expanded_chip_padding))
        current_width = int(source.get("current_width", self.current_width))
        current_height = int(source.get("current_height", self.current_height))
        panel_padding = int(source.get("panel_padding", self.panel_padding))
        anchor_side = str(source.get("anchor_side", self._anchor_side()))
        chip_size = max(base_size + (expanded_chip_padding if expanded else 0), base_size + 4)
        if not expanded:
            chip_x = max(2, int((current_width - chip_size) / 2))
            chip_y = max(2, int((current_height - chip_size) / 2))
            return chip_x, chip_y, chip_size
        y = panel_padding + 2
        x = panel_padding + 2 if anchor_side == "left" else current_width - panel_padding - chip_size - 2
        return x, y, chip_size

    def _chip_corner_radius_for_size(self, chip_size):
        return max(4, min(int(self.chip_corner_radius), compute_indicator_chip_corner_radius(chip_size)))

    def _cooldown_seconds_remaining(self):
        if self.cooldown_until <= 0:
            return 0
        return max(0, int(math.ceil(self.cooldown_until - time.monotonic())))

    def _display_char(self, snapshot=None):
        source = snapshot if isinstance(snapshot, dict) else {}
        state_name = str(source.get("state", self.state))
        if state_name == "cooldown":
            remaining = int(source.get("cooldown_seconds", self._cooldown_seconds_remaining()))
            if remaining > 0:
                return str(remaining)
        return str(source.get("current_char", self.current_char) or "")

    def _state_palette(self, state_name=None):
        active_state = str(state_name or self.state)
        if active_state == "processing":
            return {"surface_fill": "#16110A", "surface_outline": "#FFB05A", "surface_inner": "#4B2D09", "chip_fill": "#FF7A00", "chip_outline": "#FFD54A", "chip_inner": "#FFF1A8", "chip_text": "#1D1103", "text": "#FFF6E8", "highlight_text": "#FFD54A", "progress_fill": "#FF9B1F", "progress_track": "#4F3310"}
        if active_state == "cooldown":
            return {"surface_fill": "#1A1107", "surface_outline": "#FFB347", "surface_inner": "#573211", "chip_fill": "#FF9322", "chip_outline": "#FFE08B", "chip_inner": "#FFF3BF", "chip_text": "#211304", "text": "#FFF7EC", "highlight_text": "#FFE08B", "progress_fill": "#FFB347", "progress_track": "#5A3715"}
        if active_state == "ready":
            return {"surface_fill": "#081810", "surface_outline": "#00F08A", "surface_inner": "#123C26", "chip_fill": "#00D85D", "chip_outline": "#8EFFB8", "chip_inner": "#D8FFE4", "chip_text": "#04120A", "text": "#ECFFF4", "highlight_text": "#8EFFB8", "progress_fill": "#00F08A", "progress_track": "#114028"}
        if active_state == "paused":
            return {"surface_fill": "#091421", "surface_outline": "#53A7FF", "surface_inner": "#173B62", "chip_fill": "#257DFF", "chip_outline": "#A6D2FF", "chip_inner": "#DCECFF", "chip_text": "#03111F", "text": "#EDF6FF", "highlight_text": "#A6D2FF", "progress_fill": "#53A7FF", "progress_track": "#173B62"}
        return {"surface_fill": "#091523", "surface_outline": "#2C4765", "surface_inner": "#18324E", "chip_fill": "#567393", "chip_outline": "#BFD3E8", "chip_inner": "#E1ECF8", "chip_text": "#06111B", "text": "#EAF3FF", "highlight_text": "#D7E8FA", "progress_fill": "#7AA7D7", "progress_track": "#20344E"}

    def _set_timer(self, timer_id, delay_ms):
        if not self.hwnd:
            return
        self._kill_timer(timer_id)
        normalized = max(1, int(delay_ms or 1))
        if _user32.SetTimer(wintypes.HWND(int(self.hwnd)), int(timer_id), int(normalized), None):
            self._timer_delays[int(timer_id)] = normalized

    def _kill_timer(self, timer_id):
        self._timer_delays.pop(int(timer_id), None)
        if not self.hwnd:
            return
        try:
            _user32.KillTimer(wintypes.HWND(int(self.hwnd)), int(timer_id))
        except Exception:
            pass

    def _set_state(self, state_name):
        self.state = str(state_name or "idle")
        self._sync_size()
        self._last_render_signature = None
        if not self.hidden:
            self._redraw(force=True)
        self._schedule_frame_tick()

    def _sync_size(self):
        target_width, target_height = self._desired_size()
        self.target_width = int(target_width)
        self.target_height = int(target_height)
        self._set_geometry(self.target_width, self.target_height)

    def _set_geometry(self, width, height):
        work_left, work_top, work_right, work_bottom = self._work_area()
        max_width = max(1, int(work_right) - int(work_left) - (INDICATOR_MARGIN_X * 2))
        max_height = max(1, int(work_bottom) - int(work_top) - (INDICATOR_MARGIN_Y * 2))
        self.current_width = int(min(max(1, int(width)), max_width))
        self.current_height = int(min(max(1, int(height)), max_height))
        x, y = compute_indicator_origin(work_left, work_top, work_right, work_bottom, self.current_width, self.current_height, indicator_position_key)
        self.current_x = int(x)
        self.current_y = int(y)

    def _apply_capture_privacy(self):
        global indicator_capture_protected
        if not self.hwnd:
            indicator_capture_protected = False
            return False
        indicator_capture_protected = bool(set_window_capture_excluded(self.hwnd, enabled=is_capture_privacy_active()))
        return indicator_capture_protected

    def _apply_native_state(self):
        if not self.hwnd:
            return
        try:
            _user32.SetWindowPos(
                wintypes.HWND(int(self.hwnd)),
                HWND_TOPMOST,
                int(self.current_x),
                int(self.current_y),
                int(self.current_width),
                int(self.current_height),
                SWP_NOACTIVATE | SWP_NOOWNERZORDER | SWP_NOSENDCHANGING,
            )
        except Exception:
            logger.debug("Indicator native window update failed.", exc_info=True)
        self._apply_capture_privacy()

    def _schedule_native_tick(self):
        if not self.hidden:
            self._set_timer(self.TIMER_NATIVE, INDICATOR_NATIVE_HEARTBEAT_MS)

    def _schedule_frame_tick(self):
        needs_tick = bool((self.state == "cooldown" and self.cooldown_until > 0) or self.answer_preview_expires_at > 0)
        if not needs_tick:
            self._kill_timer(self.TIMER_FRAME)
            return
        delay_ms = 150 if self.state == "cooldown" else 200
        if self.answer_preview_expires_at > 0:
            remaining_ms = int(max(0.0, (self.answer_preview_expires_at - time.monotonic()) * 1000.0))
            delay_ms = max(100, min(remaining_ms or delay_ms, 250))
        self._set_timer(self.TIMER_FRAME, delay_ms)

    def _frame_tick(self):
        if self.answer_preview_expires_at > 0 and time.monotonic() >= self.answer_preview_expires_at:
            self.clear_answer_preview()
            return
        if self.state == "cooldown" and self.cooldown_until > 0:
            if time.monotonic() >= self.cooldown_until:
                self.clear_cooldown()
                return
            if not self.hidden:
                self._redraw(force=True)
        self._schedule_frame_tick()

    def _draw_chip_center_text(self, draw, text, fill, chip_x, chip_y, chip_size, font=None):
        active_font = font or self.char_font
        bbox = active_font.getbbox(str(text))
        text_width = max(0, int(bbox[2] - bbox[0]))
        text_height = max(0, int(bbox[3] - bbox[1]))
        draw.text(
            (
                int(chip_x + ((chip_size - text_width) / 2)),
                int(chip_y + ((chip_size - text_height) / 2) - bbox[1]),
            ),
            str(text),
            fill=fill,
            font=active_font,
        )

    def _build_render_snapshot(self):
        cooldown_seconds = self._cooldown_seconds_remaining()
        panel_requested = self._panel_requested()
        panel_text = str(self._panel_text() or "")
        state_name = str(self.state)
        snapshot = {
            "current_width": int(self.current_width),
            "current_height": int(self.current_height),
            "state": state_name,
            "current_char": str(self.current_char or ""),
            "answer_preview": str(self.answer_preview or ""),
            "answer_progress_index": int(self.answer_progress_index),
            "panel_scroll_offset": int(self.panel_scroll_offset),
            "panel_pinned": bool(self.panel_pinned),
            "hover_inside": bool(self.hover_inside),
            "panel_requested": bool(panel_requested),
            "panel_text": panel_text,
            "cooldown_seconds": int(cooldown_seconds),
            "base_size": int(self.base_size),
            "expanded_chip_padding": int(self.expanded_chip_padding),
            "panel_padding": int(self.panel_padding),
            "panel_corner_radius": int(self.panel_corner_radius),
            "chip_corner_radius": int(self.chip_corner_radius),
            "gap": int(self.gap),
            "body_font": self.body_font,
            "char_font": self.char_font,
            "anchor_side": str(self._anchor_side()),
        }
        snapshot["expanded"] = bool(
            snapshot["panel_requested"]
            and (snapshot["answer_preview"] or state_name in {"idle", "cooldown"})
        )
        snapshot["display_char"] = self._display_char(snapshot)
        signature = (
            snapshot["current_width"],
            snapshot["current_height"],
            snapshot["state"],
            snapshot["current_char"],
            snapshot["answer_preview"],
            snapshot["panel_text"],
            snapshot["answer_progress_index"],
            snapshot["panel_scroll_offset"],
            snapshot["panel_pinned"],
            snapshot["hover_inside"],
            snapshot["cooldown_seconds"],
            snapshot["base_size"],
            snapshot["expanded"],
        )
        snapshot["signature"] = signature
        return snapshot

    def _render_thread_main(self):
        set_current_thread_low_priority()
        while not self._render_stop_event.is_set():
            if not self._render_request_event.wait(0.25):
                continue
            if self._render_stop_event.is_set():
                break
            while not self._render_stop_event.is_set():
                with self._render_request_lock:
                    snapshot = self._render_pending_snapshot
                    signature = self._render_pending_signature
                    self._render_pending_snapshot = None
                    self._render_pending_signature = None
                    if snapshot is None:
                        self._render_request_event.clear()
                        self._render_inflight_signature = None
                        break
                    self._render_inflight_signature = signature
                try:
                    rendered = self._render_image(snapshot)
                except Exception:
                    logger.debug("Indicator background render failed.", exc_info=True)
                    rendered = None
                finally:
                    with self._render_request_lock:
                        if self._render_inflight_signature == signature:
                            self._render_inflight_signature = None
                        if self._render_pending_snapshot is None:
                            self._render_request_event.clear()
                if rendered is None:
                    continue
                self._cache_rendered_surface(signature, rendered)
                self._enqueue(lambda obj, render_signature=signature: obj._apply_render_result(render_signature))

    def _render_base_surface(self, snapshot):
        cache_key = (
            bool(snapshot["expanded"]),
            int(snapshot["current_width"]),
            int(snapshot["current_height"]),
            str(snapshot["state"]),
            str(snapshot["display_char"]),
            int(snapshot["base_size"]),
            int(snapshot["expanded_chip_padding"]),
            int(snapshot["panel_padding"]),
            str(snapshot["anchor_side"]),
        )
        cached = ordered_cache_get(self._surface_cache, cache_key, lock=self._render_cache_lock)
        if cached is not None:
            return cached
        expanded = bool(snapshot["expanded"])
        palette = self._state_palette(snapshot["state"])
        image = PIL.Image.new(
            "RGBA",
            (max(1, int(snapshot["current_width"])), max(1, int(snapshot["current_height"]))),
            (0, 0, 0, 0),
        )
        draw = PIL.ImageDraw.Draw(image)
        chip_x, chip_y, chip_size = self._chip_rect(expanded, snapshot=snapshot)
        display_char = str(snapshot["display_char"] or "")
        if expanded:
            draw.rounded_rectangle(
                (1, 1, int(snapshot["current_width"]) - 2, int(snapshot["current_height"]) - 2),
                radius=int(snapshot["panel_corner_radius"]),
                fill=palette["surface_fill"],
                outline=palette["surface_outline"],
                width=1,
            )
            draw.rounded_rectangle(
                (2, 2, int(snapshot["current_width"]) - 3, int(snapshot["current_height"]) - 3),
                radius=max(6, int(snapshot["panel_corner_radius"]) - 2),
                outline=palette["surface_inner"],
                width=1,
            )
        draw.rounded_rectangle((chip_x, chip_y, chip_x + chip_size - 1, chip_y + chip_size - 1), radius=self._chip_corner_radius_for_size(chip_size), fill=palette["chip_fill"], outline=palette["chip_outline"] if expanded else None, width=1)
        if display_char:
            self._draw_chip_center_text(
                draw,
                display_char.upper(),
                palette["chip_text"],
                chip_x,
                chip_y,
                chip_size,
                font=snapshot.get("char_font"),
            )
        elif snapshot["state"] == "paused":
            bar_width = max(2, int(chip_size * 0.14))
            gap = max(2, int(chip_size * 0.12))
            x_mid = chip_x + int(chip_size / 2)
            y1 = chip_y + int(chip_size * 0.24)
            y2 = chip_y + int(chip_size * 0.76)
            draw.rounded_rectangle((x_mid - gap - bar_width, y1, x_mid - gap - 1, y2), radius=max(1, int(bar_width / 2)), fill=palette["chip_text"])
            draw.rounded_rectangle((x_mid + gap, y1, x_mid + gap + bar_width - 1, y2), radius=max(1, int(bar_width / 2)), fill=palette["chip_text"])
        else:
            inner = max(3, int(round(chip_size * 0.23)))
            if chip_size >= 20:
                draw.rounded_rectangle((chip_x + inner, chip_y + inner, chip_x + chip_size - inner - 1, chip_y + chip_size - inner - 1), radius=max(4, self._chip_corner_radius_for_size(max(6, chip_size - (inner * 2)))), outline=palette["chip_inner"], width=1)
        ordered_cache_set(self._surface_cache, cache_key, image, 48, lock=self._render_cache_lock)
        return image

    def _render_image(self, snapshot):
        expanded = bool(snapshot["expanded"])
        palette = self._state_palette(snapshot["state"])
        chip_x, chip_y, chip_size = self._chip_rect(expanded, snapshot=snapshot)
        image = self._render_base_surface(snapshot).copy()
        draw = PIL.ImageDraw.Draw(image)
        panel_scroll_max = 0
        panel_scroll_offset = int(snapshot["panel_scroll_offset"])
        if expanded and snapshot["panel_text"]:
            text_width = max(220, int(snapshot["current_width"]) - (int(snapshot["panel_padding"]) * 2) - chip_size - int(snapshot["gap"]) - 18)
            bottom_reserve = max(18, int(int(snapshot["panel_padding"]) * 0.9)) + (18 if snapshot["answer_preview"] else 0)
            text_view_height = max(56, int(snapshot["current_height"]) - (int(snapshot["panel_padding"]) * 2) - bottom_reserve)
            layout = layout_wrapped_text(
                snapshot["panel_text"],
                snapshot.get("body_font"),
                text_width,
                spacing=self.TEXT_SPACING,
            )
            panel_scroll_max = max(0, int(layout["height"]) - text_view_height)
            panel_scroll_offset = min(max(0, panel_scroll_offset), panel_scroll_max)
            text_x = chip_x + chip_size + int(snapshot["gap"]) if snapshot["anchor_side"] == "left" else int(snapshot["panel_padding"])
            base_y = int(snapshot["panel_padding"]) + 2 - panel_scroll_offset
            line_step = int(layout["line_height"] + layout["spacing"])
            view_top = int(snapshot["panel_padding"]) + 2
            view_bottom = view_top + text_view_height
            preview_text = str(snapshot["answer_preview"] or "")
            typed_index = int(snapshot["answer_progress_index"])
            for line_index, line in enumerate(layout["lines"]):
                y = base_y + (line_index * line_step)
                if y + layout["line_height"] < view_top:
                    continue
                if y > view_bottom:
                    break
                draw.text((text_x, y), str(line["text"] or ""), fill=palette["text"], font=snapshot.get("body_font"))
                if preview_text and typed_index > int(line["start"]):
                    prefix = preview_text[int(line["start"]): min(int(line["end"]), typed_index)].rstrip()
                    if prefix:
                        draw.text((text_x, y), prefix, fill=palette["highlight_text"], font=snapshot.get("body_font"))
            if snapshot["answer_preview"]:
                total = len(snapshot["answer_preview"])
                fraction = max(0.0, min(1.0, float(snapshot["answer_progress_index"]) / float(total or 1)))
                bar_width = max(80, int(snapshot["current_width"]) - (int(snapshot["panel_padding"]) * 2))
                bar_height = max(5, int(round(int(snapshot["base_size"]) * 0.24)))
                bar_left = int(snapshot["panel_padding"])
                bar_top = int(snapshot["current_height"]) - max(12, int(int(snapshot["panel_padding"]) * 0.72)) - bar_height
                draw.rounded_rectangle((bar_left, bar_top, bar_left + bar_width, bar_top + bar_height), radius=max(2, int(bar_height / 2)), fill=palette["progress_track"])
                fill_width = int(round(bar_width * fraction))
                if fill_width > 0:
                    draw.rounded_rectangle((bar_left, bar_top, bar_left + fill_width, bar_top + bar_height), radius=max(2, int(bar_height / 2)), fill=palette["progress_fill"])
            if panel_scroll_max > 0:
                track_top = int(snapshot["panel_padding"]) + 2
                track_right = int(snapshot["current_width"]) - max(6, int(int(snapshot["panel_padding"]) * 0.5))
                track_left = track_right - 3
                track_bottom = track_top + text_view_height
                draw.rounded_rectangle((track_left, track_top, track_right, track_bottom), radius=2, fill=palette["progress_track"])
                thumb_height = max(18, int((text_view_height / max(1, int(layout["height"]))) * text_view_height))
                thumb_travel = max(1, text_view_height - thumb_height)
                thumb_top = track_top + int((panel_scroll_offset / max(1, panel_scroll_max)) * thumb_travel)
                draw.rounded_rectangle((track_left, thumb_top, track_right, thumb_top + thumb_height), radius=2, fill=palette["progress_fill"])
        return image, panel_scroll_max, panel_scroll_offset

    def _apply_render_result(self, signature):
        if self.hidden or not self.hwnd or signature != self._last_render_signature:
            return
        rendered = self._get_cached_rendered_surface(signature)
        if rendered is None:
            return
        image, panel_scroll_max, panel_scroll_offset = rendered
        self.panel_scroll_max = int(panel_scroll_max)
        self.panel_scroll_offset = int(panel_scroll_offset)
        self._apply_native_state()
        update_layered_window_image(self.hwnd, image, self.current_x, self.current_y)

    def _redraw(self, force=False):
        if self.hidden or not self.hwnd:
            return
        snapshot = self._build_render_snapshot()
        signature = snapshot["signature"]
        if not force and signature == self._last_render_signature:
            return
        self._last_render_signature = signature
        self._apply_native_state()
        rendered = self._get_cached_rendered_surface(signature)
        if rendered is not None:
            image, panel_scroll_max, panel_scroll_offset = rendered
            self.panel_scroll_max = int(panel_scroll_max)
            self.panel_scroll_offset = int(panel_scroll_offset)
            update_layered_window_image(self.hwnd, image, self.current_x, self.current_y)
            return
        self._request_render(snapshot)

    def _process_dispatch_queue(self):
        while True:
            try:
                callback = indicator_dispatch_queue.get_nowait()
            except queue.Empty:
                break
            try:
                callback(self)
            except Exception:
                logger.debug("Indicator callback failed.", exc_info=True)

    def _pointer_inside(self):
        if self.hidden:
            return False
        point = wintypes.POINT()
        return bool(_user32.GetCursorPos(ctypes.byref(point))) and self.current_x <= int(point.x) < (self.current_x + self.current_width) and self.current_y <= int(point.y) < (self.current_y + self.current_height)

    def _collapse_if_possible(self):
        if self.hidden or self.hover_inside or self.panel_pinned or self._pointer_inside():
            return
        self._sync_size()
        self._redraw(force=True)

    def _scroll_panel(self, direction):
        if self.panel_scroll_max <= 0:
            return 0
        line_height = max(12, image_font_line_height(self.body_font))
        next_offset = min(max(0, self.panel_scroll_offset + (direction * line_height * INDICATOR_PANEL_SCROLL_LINES)), self.panel_scroll_max)
        if next_offset == self.panel_scroll_offset:
            return 0
        self.panel_scroll_offset = next_offset
        self._redraw(force=True)
        return 1

    def _should_redraw_progress(self, text_changed, typed_index):
        if self.hidden or not self._panel_requested():
            return False
        total_chars = len(self.answer_preview)
        if total_chars <= 0 or text_changed or typed_index <= 0 or typed_index >= total_chars or typing_hook is None:
            self.progress_rendered_at = time.monotonic()
            self.progress_rendered_index = int(typed_index)
            return True
        now = time.monotonic()
        if int(typed_index) - int(self.progress_rendered_index) < INDICATOR_TYPING_PANEL_RENDER_MIN_STEP and (now - float(self.progress_rendered_at)) < INDICATOR_TYPING_PANEL_RENDER_MIN_INTERVAL:
            return False
        self.progress_rendered_at = now
        self.progress_rendered_index = int(typed_index)
        return True

    def _thread_main(self):
        self._thread_id = threading.get_ident()
        try:
            hinstance = _kernel32.GetModuleHandleW(None)
            wnd_class = WNDCLASSEXW()
            wnd_class.cbSize = ctypes.sizeof(WNDCLASSEXW)
            wnd_class.style = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS
            wnd_class.lpfnWndProc = self._wndproc
            wnd_class.hInstance = hinstance
            wnd_class.lpszClassName = self._class_name
            try:
                wnd_class.hCursor = _user32.LoadCursorW(None, wintypes.LPCWSTR(IDC_ARROW))
            except Exception:
                wnd_class.hCursor = None
            if not _user32.RegisterClassExW(ctypes.byref(wnd_class)):
                raise ctypes.WinError(ctypes.get_last_error())
            self.hwnd = int(_user32.CreateWindowExW(WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE, self._class_name, APP_NAME, WS_POPUP, 0, 0, self.current_width, self.current_height, None, None, hinstance, None) or 0)
            if not self.hwnd:
                raise ctypes.WinError(ctypes.get_last_error())
            self._sync_size()
            _user32.ShowWindow(wintypes.HWND(int(self.hwnd)), SW_HIDE)
            self._hwnd_ready.set()
            msg = MSG()
            while True:
                result = _user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
                if result == 0:
                    break
                if result == -1:
                    raise ctypes.WinError(ctypes.get_last_error())
                _user32.TranslateMessage(ctypes.byref(msg))
                _user32.DispatchMessageW(ctypes.byref(msg))
        except Exception as exc:
            self._thread_error = exc
            self._hwnd_ready.set()
            indicator_debug("indicator.native_thread.exception", traceback=traceback.format_exc())
        finally:
            self._render_stop_event.set()
            self._render_request_event.set()
            self.hwnd = 0

    def _wndproc_impl(self, hwnd, msg, wparam, lparam):
        if msg == self.WM_DISPATCH:
            self._process_dispatch_queue()
            return 0
        if msg == WM_TIMER:
            self._kill_timer(int(wparam))
            if int(wparam) == self.TIMER_FRAME:
                self._frame_tick()
            elif int(wparam) == self.TIMER_NATIVE:
                self._apply_native_state()
                self._schedule_native_tick()
            elif int(wparam) == self.TIMER_COLLAPSE:
                self._collapse_if_possible()
            elif int(wparam) == self.TIMER_CLICK:
                self.panel_pinned = not self.panel_pinned
                if not self.panel_pinned and not self._pointer_inside():
                    self.hover_inside = False
                self._sync_size()
                self._redraw(force=True)
            return 0
        if msg == WM_MOUSEMOVE:
            self.hover_inside = True
            self._sync_size()
            self._redraw(force=True)
            if not self._mouse_tracking:
                track = TRACKMOUSEEVENT()
                track.cbSize = ctypes.sizeof(TRACKMOUSEEVENT)
                track.dwFlags = TME_LEAVE
                track.hwndTrack = wintypes.HWND(int(hwnd))
                track.dwHoverTime = 0
                self._mouse_tracking = bool(_user32.TrackMouseEvent(ctypes.byref(track)))
            return 0
        if msg == WM_MOUSELEAVE:
            self.hover_inside = False
            self._mouse_tracking = False
            self._set_timer(self.TIMER_COLLAPSE, 150)
            return 0
        if msg == WM_MOUSEWHEEL:
            raw = int((int(wparam) >> 16) & 0xFFFF)
            delta = raw - 0x10000 if raw & 0x8000 else raw
            return self._scroll_panel(-1 if delta > 0 else 1 if delta < 0 else 0)
        if msg == WM_LBUTTONDOWN:
            self._set_timer(self.TIMER_CLICK, 180)
            return 0
        if msg == WM_LBUTTONDBLCLK:
            self._kill_timer(self.TIMER_CLICK)
            Thread(target=lambda: open_settings_menu(hide_indicator_temporarily=True), daemon=True, name="indicator-open-settings").start()
            return 0
        if msg == WM_MOUSEACTIVATE:
            return MA_NOACTIVATE
        if msg in {WM_DISPLAYCHANGE, WM_SETTINGCHANGE, WM_DPICHANGED}:
            self.refresh_preferences()
            return 0
        if msg == WM_DESTROY:
            global indicator_capture_protected
            indicator_capture_protected = False
            self._render_stop_event.set()
            self._render_request_event.set()
            set_indicator_runtime_state(active=False, hidden=True)
            _user32.PostQuitMessage(0)
            return 0
        return _user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def set_command_mode(self, mode):
        if not self._on_ui_thread():
            self._enqueue(lambda obj: obj.set_command_mode(mode))
            return
        self.command_mode = "toprow" if str(mode or "").strip().lower() == "toprow" else "numpad"
        self.control_hint_text = self._build_control_hint_text()
        self._clear_render_caches()
        self._last_render_signature = None
        self._sync_size()
        if not self.hidden:
            self._redraw(force=True)

    def refresh_preferences(self):
        if not self._on_ui_thread():
            self._enqueue(lambda obj: obj.refresh_preferences())
            return
        self._update_screen_metrics()
        self.command_mode = str(command_key_mode).strip().lower() or "numpad"
        self._apply_size_metrics()
        self._clear_render_caches()
        self._sync_size()
        if not self.hidden:
            self._redraw(force=True)

    def set_idle(self):
        if not self._on_ui_thread():
            self._enqueue(lambda obj: obj.set_idle())
            return
        self.current_char = ""
        self._set_state("idle")

    def set_processing(self):
        if not self._on_ui_thread():
            self._enqueue(lambda obj: obj.set_processing())
            return
        self.current_char = ""
        self.hover_inside = False
        self._set_state("processing")

    def set_ready(self):
        if not self._on_ui_thread():
            self._enqueue(lambda obj: obj.set_ready())
            return
        self.current_char = ""
        self._set_state("ready")

    def set_paused(self):
        if not self._on_ui_thread():
            self._enqueue(lambda obj: obj.set_paused())
            return
        self.current_char = ""
        self._set_state("paused")

    def show_answer_char(self, value):
        if not self._on_ui_thread():
            self._enqueue(lambda obj: obj.show_answer_char(value))
            return
        self.current_char = (value or "").strip()[:1]
        self._set_state("ready")

    def set_answer_progress(self, value, typed_count=0):
        if not self._on_ui_thread():
            self._enqueue(lambda obj: obj.set_answer_progress(value, typed_count))
            return
        text = str(value or "").strip()
        typed_index = max(0, min(len(text), int(typed_count or 0)))
        text_changed = text != self.answer_preview
        self.answer_preview = text
        self.answer_progress_index = typed_index
        self.answer_preview_expires_at = time.monotonic() + ANSWER_PREVIEW_RETENTION_SECONDS if text and typed_index >= len(text) else 0.0
        if text_changed:
            self.panel_scroll_offset = 0
            self._sync_size()
        if not self.hidden and self._should_redraw_progress(text_changed, typed_index):
            self._redraw(force=True)
        self._schedule_frame_tick()

    def clear_answer_preview(self):
        if not self._on_ui_thread():
            self._enqueue(lambda obj: obj.clear_answer_preview())
            return
        self.answer_preview = ""
        self.answer_progress_index = 0
        self.answer_preview_expires_at = 0.0
        self.panel_scroll_offset = 0
        self.panel_scroll_max = 0
        self._sync_size()
        if not self.hidden:
            self._redraw(force=True)
        self._schedule_frame_tick()

    def set_cooldown(self, seconds):
        if not self._on_ui_thread():
            self._enqueue(lambda obj: obj.set_cooldown(seconds))
            return
        timeout = max(0.0, float(seconds or 0.0))
        if timeout <= 0:
            self.clear_cooldown()
            return
        self.current_char = ""
        self.cooldown_until = time.monotonic() + timeout
        self._set_state("cooldown")

    def clear_cooldown(self):
        if not self._on_ui_thread():
            self._enqueue(lambda obj: obj.clear_cooldown())
            return
        self.cooldown_until = 0.0
        self.current_char = ""
        if self.state == "cooldown":
            self._set_state("idle")

    def refresh_capture_privacy(self):
        if not self._on_ui_thread():
            self._enqueue(lambda obj: obj.refresh_capture_privacy())
            return
        self._apply_capture_privacy()

    def hide(self):
        global indicator_capture_protected
        if not self._on_ui_thread():
            self._enqueue(lambda obj: obj.hide())
            return
        if self.hidden:
            return
        indicator_capture_protected = False
        if self.hwnd:
            set_window_capture_excluded(self.hwnd, enabled=False)
            _user32.ShowWindow(wintypes.HWND(int(self.hwnd)), SW_HIDE)
        self.hidden = True
        set_indicator_runtime_state(active=True, hidden=True)

    def show(self):
        if not self._on_ui_thread():
            self._enqueue(lambda obj: obj.show())
            return
        if not self.hwnd:
            return
        self.hidden = False
        set_indicator_runtime_state(active=True, hidden=False)
        self._sync_size()
        _user32.ShowWindow(wintypes.HWND(int(self.hwnd)), SW_SHOWNOACTIVATE)
        self._redraw(force=True)
        self._schedule_frame_tick()
        self._schedule_native_tick()

    def run(self):
        self._thread.join()


class StatusIndicator:
    def __init__(self):
        raise RuntimeError("Legacy indicator implementation is disabled.")

    def _apply_size_metrics(self):
        self.base_size = int(INDICATOR_BLOB_SIZES.get(indicator_blob_size_key, INDICATOR_BLOB_SIZES["medium"]))
        self.collapsed_padding = max(4, int(round(self.base_size * 0.22)))
        self.expanded_chip_padding = max(6, int(round(self.base_size * 0.24)))
        self.collapsed_width = self.base_size + (self.collapsed_padding * 3)
        self.collapsed_height = self.collapsed_width
        self.square_corner_radius = max(10, compute_indicator_chip_corner_radius(self.collapsed_width + 4))
        self.panel_corner_radius = max(18, int(self.base_size * 1.05))
        self.panel_padding = max(14, int(self.base_size * 0.78))
        self.gap = max(12, int(self.base_size * 0.72))
        self.chip_corner_radius = max(8, compute_indicator_chip_corner_radius(self.base_size + self.expanded_chip_padding))

    def _is_pointer_inside(self):
        try:
            px = int(self.root.winfo_pointerx())
            py = int(self.root.winfo_pointery())
            x1 = int(self.root.winfo_rootx())
            y1 = int(self.root.winfo_rooty())
            x2 = x1 + int(self.current_width)
            y2 = y1 + int(self.current_height)
            return x1 <= px < x2 and y1 <= py < y2
        except Exception:
            return False

    def _anchor_side(self):
        layout = INDICATOR_POSITIONS.get(normalize_indicator_position(indicator_position_key), INDICATOR_POSITIONS["bottom_right"])
        return "left" if layout["x"] == "left" else "right"

    def _panel_text(self):
        if self.answer_preview and self._should_show_panel():
            return self.answer_preview
        if self.state == "cooldown":
            return tr("indicator.cooldown", language=ui_language, seconds=self._cooldown_seconds_remaining())
        return self.control_hint_text if self.state == "idle" else ""

    def _build_control_hint_text(self):
        lines = []
        for action in HOTKEY_ACTION_ORDER:
            lines.append(
                f"{hotkey_binding_label(command_hotkeys.get(action, ''))} {hotkey_action_label(action, language=ui_language)}"
            )
        lines.append(tr("auth.hotkey.settings", language=ui_language))
        return "\n".join(line for line in lines if line)

    def _measure_text_box(self, text, wrap_width):
        if not text:
            return 0, 0
        cache_key = (
            str(text),
            int(max(80, int(wrap_width))),
            int(self.body_font.actual("size")),
        )
        cached = self._text_measure_cache.get(cache_key)
        if cached is not None:
            return cached
        try:
            item = self.canvas.create_text(
                0,
                0,
                text=text,
                font=self.body_font,
                anchor="nw",
                width=max(80, int(wrap_width)),
                justify="left",
            )
            bbox = self.canvas.bbox(item)
            self.canvas.delete(item)
            if not bbox:
                return 0, 0
            result = (max(0, int(bbox[2] - bbox[0])), max(0, int(bbox[3] - bbox[1])))
            self._text_measure_cache[cache_key] = result
            if len(self._text_measure_cache) > 160:
                try:
                    self._text_measure_cache.pop(next(iter(self._text_measure_cache)))
                except Exception:
                    pass
            return result
        except Exception:
            return 0, 0

    def _desired_panel_size(self):
        text = self._panel_text()
        if not text:
            return self.collapsed_width, self.collapsed_height
        chip_size = self.base_size + self.expanded_chip_padding
        chip_space = chip_size + self.gap
        wrap_width = max(240, min(self.max_panel_width - chip_space - (self.panel_padding * 2) - 20, 380))
        _, text_height = self._measure_text_box(text, wrap_width)
        width = int(min(self.max_panel_width, max(self.collapsed_width + 180, chip_space + wrap_width + (self.panel_padding * 2) + 18)))
        bottom_reserve = max(18, int(self.panel_padding * 0.9)) + (18 if self.answer_preview else 0)
        desired_height = int(max(self.collapsed_height + 44, text_height + (self.panel_padding * 2) + bottom_reserve))
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        work_left, work_top, work_right, work_bottom = get_work_area_bounds(screen_width, screen_height)
        usable_height = max(1, int(work_bottom) - int(work_top) - (INDICATOR_MARGIN_Y * 2))
        max_height = int(max(self.collapsed_height + 44, usable_height * INDICATOR_PANEL_MAX_HEIGHT_RATIO))
        height = int(min(desired_height, max_height))
        return width, height

    def _desired_size(self):
        if self._should_show_panel() and (self.answer_preview or self.state in {"idle", "cooldown"}):
            return self._desired_panel_size()
        return self.collapsed_width, self.collapsed_height

    def _panel_is_requested(self):
        # Keep expansion user-driven: hover/click pin only.
        return bool(self.panel_pinned or self.hover_inside)

    def _should_show_panel(self):
        return self._panel_is_requested()

    def _is_expanded(self):
        return self.current_width > self.collapsed_width + 4 or self.current_height > self.collapsed_height + 4

    def _render_signature(self, antialias):
        panel_text = str(self._panel_text() or "")
        panel_requested = bool(self._panel_is_requested())
        text_signature = (len(panel_text), panel_text[:48], panel_text[-48:] if len(panel_text) > 48 else "")
        cooldown_bucket = self._cooldown_seconds_remaining()
        return (
            int(self.current_width),
            int(self.current_height),
            bool(self._is_expanded()),
            str(self.state),
            str(self.current_char),
            int(self.answer_progress_index) if panel_requested else -1,
            int(self.panel_scroll_offset) if panel_requested else 0,
            text_signature,
            int(antialias),
            int(cooldown_bucket),
            bool(self.panel_pinned),
        )

    def _chip_corner_radius_for_size(self, chip_size):
        return max(4, min(int(self.chip_corner_radius), compute_indicator_chip_corner_radius(chip_size)))

    def _set_window_bg(self, color):
        background = self.transparent_color or str(color or self.window_bg)
        if background == self._active_window_bg:
            return
        self._active_window_bg = background
        try:
            self.root.configure(bg=background)
        except Exception:
            pass
        try:
            self.canvas.configure(bg=background)
        except Exception:
            pass

    def _draw_chip(self, x1, y1, x2, y2, fill, outline, antialias=2, width=1):
        draw_rounded_canvas_rect(
            self.canvas,
            x1,
            y1,
            x2,
            y2,
            self._chip_corner_radius_for_size(min((x2 - x1) + 1, (y2 - y1) + 1)),
            fill=fill,
            outline=outline,
            width=width,
            antialias=antialias,
        )

    def _draw_active_rings(self, x1, y1, x2, y2, accent_color, antialias=2):
        return

    def _set_state(self, state_name):
        self.state = state_name
        self.ready_pulse_started_at = time.monotonic() if state_name == "ready" else 0.0
        self._sync_target_size()
        self._last_render_signature = None
        if not self.hidden:
            self._redraw(force=True)
        self._schedule_frame_tick()

    def _cancel_size_animation(self):
        if self.animation_after_id is None:
            return
        try:
            self.root.after_cancel(self.animation_after_id)
        except Exception:
            pass
        self.animation_after_id = None
        self.animation_started_at = 0.0

    def _start_size_animation(self):
        start_width = int(self.current_width)
        start_height = int(self.current_height)
        self._cancel_size_animation()
        self.animation_from_width = start_width
        self.animation_from_height = start_height
        self.animation_started_at = time.monotonic()
        self.animation_after_id = self.root.after(0, self._animate_step)

    def _sync_target_size(self, animate=None):
        target_width, target_height = self._desired_size()
        self.target_width = target_width
        self.target_height = target_height
        geometry_changed = int(self.current_width) != int(target_width) or int(self.current_height) != int(target_height)
        if animate is None:
            target_is_panel = target_width > self.collapsed_width + 4 or target_height > self.collapsed_height + 4
            current_is_panel = self.current_width > self.collapsed_width + 4 or self.current_height > self.collapsed_height + 4
            animate = bool(geometry_changed and (target_is_panel or current_is_panel))
        if geometry_changed and animate:
            self._start_size_animation()
        elif geometry_changed:
            self._cancel_size_animation()
            self._set_geometry(target_width, target_height)
            self._schedule_native_refresh(force=True)
        else:
            self._cancel_size_animation()
        if geometry_changed:
            self._last_render_signature = None

    def _ensure_animation(self):
        self._sync_target_size(animate=True)

    def _animate_step(self):
        self.animation_after_id = None
        if self.animation_started_at <= 0.0:
            self._sync_target_size(animate=False)
            if not self.hidden:
                self._redraw(force=True)
            return
        elapsed_ms = (time.monotonic() - self.animation_started_at) * 1000.0
        progress = max(0.0, min(1.0, elapsed_ms / float(max(1, self.animation_duration_ms))))
        eased = 1.0 - ((1.0 - progress) ** 3)
        next_width = int(round(self.animation_from_width + ((self.target_width - self.animation_from_width) * eased)))
        next_height = int(round(self.animation_from_height + ((self.target_height - self.animation_from_height) * eased)))
        self._set_geometry(next_width, next_height)
        if not self.hidden:
            self._redraw(force=True)
        if progress < 1.0 and (next_width != self.target_width or next_height != self.target_height):
            self.animation_after_id = self.root.after(16, self._animate_step)
            return
        self.animation_started_at = 0.0
        self._set_geometry(self.target_width, self.target_height)
        self._schedule_native_refresh(force=True)
        if not self.hidden:
            self._redraw(force=True)

    def _needs_frame_tick(self):
        return bool(
            (self.state == "cooldown" and self.cooldown_until > 0)
            or self.answer_preview_expires_at > 0
        )

    def _next_frame_delay_ms(self):
        if self.state == "cooldown":
            return 150
        if self.answer_preview_expires_at > 0:
            remaining_ms = int(max(0.0, (self.answer_preview_expires_at - time.monotonic()) * 1000.0))
            return max(100, min(remaining_ms or 250, 250))
        return 200

    def _schedule_frame_tick(self):
        if self.frame_after_id is not None or not self._needs_frame_tick():
            return
        self.frame_after_id = self.root.after(self._next_frame_delay_ms(), self._frame_tick)

    def _next_dispatch_delay_ms(self, processed=0):
        if processed >= 48:
            return 6
        if self.answer_preview or self.panel_pinned or self.hover_inside:
            return 10
        if self.state in {"processing", "ready", "paused", "cooldown"}:
            return 18
        if self.hidden:
            return 96
        return 42

    def _schedule_dispatch_tick(self, delay_ms=16):
        if self.dispatch_after_id is not None:
            return
        self.dispatch_after_id = self.root.after(max(1, int(delay_ms or 16)), self._dispatch_tick)

    def _dispatch_tick(self):
        self.dispatch_after_id = None
        processed = 0
        while processed < 48:
            try:
                callback = indicator_dispatch_queue.get_nowait()
            except queue.Empty:
                break
            try:
                callback(self)
            except Exception:
                logger.debug("Indicator callback failed.", exc_info=True)
            processed += 1
        try:
            if self.root.winfo_exists():
                self._schedule_dispatch_tick(self._next_dispatch_delay_ms(processed))
        except Exception:
            pass

    def _frame_tick(self):
        self.frame_after_id = None
        if self.answer_preview_expires_at > 0 and time.monotonic() >= self.answer_preview_expires_at:
            self.clear_answer_preview()
            return
        if self.state == "cooldown" and self.cooldown_until > 0:
            if time.monotonic() >= self.cooldown_until:
                self.clear_cooldown()
                return
            if not self.hidden:
                self._redraw(force=True)
        self._schedule_frame_tick()

    def _set_geometry(self, width, height):
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        work_left, work_top, work_right, work_bottom = get_work_area_bounds(screen_width, screen_height)
        max_width = max(1, int(work_right) - int(work_left) - (INDICATOR_MARGIN_X * 2))
        max_height = max(1, int(work_bottom) - int(work_top) - (INDICATOR_MARGIN_Y * 2))
        # Clamp geometry to the visible work area so the panel never overflows the full screen.
        next_width = int(min(max(1, width), max_width))
        next_height = int(min(max(1, height), max_height))
        x, y = compute_indicator_origin(work_left, work_top, work_right, work_bottom, next_width, next_height, indicator_position_key)
        size_changed = (
            self.current_width != next_width
            or self.current_height != next_height
        )
        geometry_changed = size_changed or self.current_x != x or self.current_y != y
        self.current_width = next_width
        self.current_height = next_height
        self.current_x = int(x)
        self.current_y = int(y)
        if not geometry_changed:
            return
        self.root.geometry(f"{self.current_width}x{self.current_height}+{self.current_x}+{self.current_y}")
        if size_changed:
            self.canvas.configure(width=self.current_width, height=self.current_height)
        self._last_native_signature = None
        if not self.hidden:
            self._schedule_native_refresh()

    def _apply_capture_privacy(self, hwnd):
        global indicator_capture_protected
        normalized_hwnd = int(hwnd or 0)
        if not normalized_hwnd:
            indicator_capture_protected = False
            return False
        if not is_capture_privacy_active():
            indicator_capture_protected = False
            set_window_capture_excluded(normalized_hwnd, enabled=False)
            return False
        try:
            indicator_capture_protected = bool(set_window_capture_excluded(normalized_hwnd, enabled=True))
        except Exception:
            indicator_capture_protected = False
        return indicator_capture_protected

    def refresh_capture_privacy(self):
        self._last_native_signature = None
        self._schedule_native_refresh(force=True)

    def _native_corner_radius(self):
        if os.name != "nt":
            return 0
        if self._is_expanded():
            return int(self.panel_corner_radius)
        return int(max(self.square_corner_radius, int(round(self.current_width * 0.36))))

    def _schedule_native_refresh(self, delay_ms=24, force=False):
        if self.hidden:
            self.native_refresh_force_pending = False
            return
        if force:
            self.native_refresh_force_pending = True
        if self.native_refresh_after_id is not None:
            return
        self.native_refresh_after_id = self.root.after(max(0, int(delay_ms or 0)), self._apply_native_window_state)

    def _apply_native_window_state(self):
        self.native_refresh_after_id = None
        if self.hidden:
            self.native_refresh_force_pending = False
            return
        force = bool(self.native_refresh_force_pending)
        self.native_refresh_force_pending = False
        try:
            if not self.root.winfo_exists():
                return
            hwnd = int(self.root.winfo_id() or 0)
            if not hwnd:
                return
            native_signature = (
                bool(is_capture_privacy_active()),
            )
            if not force and native_signature == self._last_native_signature:
                self._schedule_native_heartbeat()
                return
            self._apply_capture_privacy(hwnd)
            self._last_native_signature = native_signature
            self._schedule_native_heartbeat()
        except Exception:
            logger.debug("Indicator native window sync failed.", exc_info=True)

    def _cancel_native_heartbeat(self):
        if self.native_heartbeat_after_id is None:
            return
        try:
            self.root.after_cancel(self.native_heartbeat_after_id)
        except Exception:
            pass
        self.native_heartbeat_after_id = None

    def _schedule_native_heartbeat(self):
        if self.hidden or self.native_heartbeat_after_id is not None:
            return
        self.native_heartbeat_after_id = self.root.after(INDICATOR_NATIVE_HEARTBEAT_MS, self._native_heartbeat_tick)

    def _native_heartbeat_tick(self):
        self.native_heartbeat_after_id = None
        if self.hidden:
            return
        self._schedule_native_refresh(force=True)

    def _on_window_map(self, _event=None):
        indicator_debug("indicator.window.map", hidden=self.hidden)
        if self.hidden:
            return
        self._schedule_native_refresh(delay_ms=30, force=True)

    def _on_window_unmap(self, _event=None):
        indicator_debug("indicator.window.unmap", hidden=self.hidden)

    def _on_focus_in(self, _event=None):
        indicator_debug("indicator.window.focus_in", hidden=self.hidden)

    def _on_focus_out(self, _event=None):
        indicator_debug("indicator.window.focus_out", hidden=self.hidden)

    def _on_destroy(self, _event=None):
        global indicator_capture_protected
        for attr_name in (
            "frame_after_id",
            "collapse_after_id",
            "animation_after_id",
            "click_after_id",
            "dispatch_after_id",
            "native_refresh_after_id",
            "native_heartbeat_after_id",
        ):
            after_id = getattr(self, attr_name, None)
            if after_id:
                try:
                    self.root.after_cancel(after_id)
                except Exception:
                    pass
            setattr(self, attr_name, None)
        self.animation_started_at = 0.0
        indicator_capture_protected = False
        set_indicator_runtime_state(active=False, hidden=True)

    def _state_palette(self):
        if self.state == "processing":
            return {
                "surface_fill": "#191005",
                "surface_outline": "#FF9B1F",
                "surface_inner": "#4B2D09",
                "chip_fill": "#FF7A00",
                "chip_outline": "#FFD54A",
                "chip_inner": "#FFF1A8",
                "chip_text": "#1D1103",
                "text": "#FFF6E8",
                "highlight_text": "#FFD54A",
                "muted_text": "#FFD18B",
                "progress_fill": "#FF9B1F",
                "progress_track": "#4F3310",
            }
        if self.state == "cooldown":
            return {
                "surface_fill": "#1A1107",
                "surface_outline": "#FFB347",
                "surface_inner": "#573211",
                "chip_fill": "#FF9322",
                "chip_outline": "#FFE08B",
                "chip_inner": "#FFF3BF",
                "chip_text": "#211304",
                "text": "#FFF7EC",
                "highlight_text": "#FFE08B",
                "muted_text": "#FFD399",
                "progress_fill": "#FFB347",
                "progress_track": "#5A3715",
            }
        if self.state == "ready":
            return {
                "surface_fill": "#081810",
                "surface_outline": "#00F08A",
                "surface_inner": "#123C26",
                "chip_fill": "#00D85D",
                "chip_outline": "#8EFFB8",
                "chip_inner": "#D8FFE4",
                "chip_text": "#04120A",
                "text": "#ECFFF4",
                "highlight_text": "#8EFFB8",
                "muted_text": "#92FFC2",
                "progress_fill": "#00F08A",
                "progress_track": "#114028",
            }
        if self.state == "paused":
            return {
                "surface_fill": "#091421",
                "surface_outline": "#53A7FF",
                "surface_inner": "#173B62",
                "chip_fill": "#257DFF",
                "chip_outline": "#A6D2FF",
                "chip_inner": "#DCECFF",
                "chip_text": "#03111F",
                "text": "#EDF6FF",
                "highlight_text": "#A6D2FF",
                "muted_text": "#A8C8EB",
                "progress_fill": "#53A7FF",
                "progress_track": "#173B62",
            }
        return {
            "surface_fill": "#091523",
            "surface_outline": "#2C4765",
            "surface_inner": "#18324E",
            "chip_fill": "#567393",
            "chip_outline": "#BFD3E8",
            "chip_inner": "#E1ECF8",
            "chip_text": "#06111B",
            "text": "#EAF3FF",
            "highlight_text": "#D7E8FA",
            "muted_text": "#AAC0D8",
            "progress_fill": "#7AA7D7",
            "progress_track": "#20344E",
        }

    def _chip_rect(self, expanded):
        chip_size = max(self.base_size + (self.expanded_chip_padding if expanded else 0), self.base_size + 4)
        chip_side = self._anchor_side()
        if not expanded:
            chip_x = max(2, int((self.current_width - chip_size) / 2))
            chip_y = max(2, int((self.current_height - chip_size) / 2))
            return chip_x, chip_y, chip_size
        y = self.panel_padding + 2
        if expanded and chip_side == "left":
            x = self.panel_padding + 2
        else:
            x = self.current_width - self.panel_padding - chip_size - 2
        return x, y, chip_size

    def _render_indicator_surface(self, expanded, palette):
        palette_signature = tuple((key, str(value)) for key, value in sorted(palette.items()))
        cache_key = (
            bool(expanded),
            int(self.current_width),
            int(self.current_height),
            str(self.state),
            str(self.current_char),
            palette_signature,
        )
        cached = self._surface_cache.get(cache_key)
        if cached is not None:
            return cached

        scale = 4 if expanded else 8
        width_px = max(1, int(self.current_width))
        height_px = max(1, int(self.current_height))
        image = PIL.Image.new("RGBA", (width_px * scale, height_px * scale), (0, 0, 0, 0))
        draw = PIL.ImageDraw.Draw(image)
        outline_width = max(1, scale)
        if expanded:
            surface_radius = self.panel_corner_radius * scale
            outer_margin = scale
            draw.rounded_rectangle(
                (
                    outer_margin,
                    outer_margin,
                    (width_px * scale) - outer_margin - 1,
                    (height_px * scale) - outer_margin - 1,
                ),
                radius=max(4 * scale, surface_radius - scale),
                fill=palette["surface_fill"],
                outline=palette["surface_outline"],
                width=outline_width,
            )
            if width_px > 12 and height_px > 12:
                inset = scale * 2
                inner_radius = max(4 * scale, surface_radius - (3 * scale))
                draw.rounded_rectangle(
                    (
                        inset,
                        inset,
                        (width_px * scale) - inset - 1,
                        (height_px * scale) - inset - 1,
                    ),
                    radius=inner_radius,
                    outline=palette["surface_inner"],
                    width=outline_width,
                )

            chip_x, chip_y, chip_size = self._chip_rect(True)
            chip_left = chip_x * scale
            chip_top = chip_y * scale
            chip_right = ((chip_x + chip_size) * scale) - 1
            chip_bottom = ((chip_y + chip_size) * scale) - 1
            chip_radius = self._chip_corner_radius_for_size(chip_size) * scale
            draw.rounded_rectangle(
                (chip_left, chip_top, chip_right, chip_bottom),
                radius=chip_radius,
                fill=palette["chip_fill"],
                outline=palette["chip_outline"],
                width=outline_width,
            )
            display_char = self._display_char()
            if self.state == "paused" and not display_char:
                bar_width = max(2, int(chip_size * 0.14)) * scale
                gap = max(2, int(chip_size * 0.12)) * scale
                x_mid = chip_left + int((chip_size * scale) / 2)
                y1 = chip_top + int(chip_size * scale * 0.24)
                y2 = chip_top + int(chip_size * scale * 0.76)
                draw.rounded_rectangle(
                    (x_mid - gap - bar_width, y1, x_mid - gap - 1, y2),
                    radius=max(scale, int(bar_width / 2)),
                    fill=palette["chip_text"],
                )
                draw.rounded_rectangle(
                    (x_mid + gap, y1, x_mid + gap + bar_width - 1, y2),
                    radius=max(scale, int(bar_width / 2)),
                    fill=palette["chip_text"],
                )
            elif chip_size >= 20 and not display_char:
                inner_inset = max(3, int(round(chip_size * 0.23))) * scale
                inner_size = max(6, chip_size - (max(3, int(round(chip_size * 0.23))) * 2))
                draw.rounded_rectangle(
                    (
                        chip_left + inner_inset,
                        chip_top + inner_inset,
                        chip_right - inner_inset,
                        chip_bottom - inner_inset,
                    ),
                    radius=self._chip_corner_radius_for_size(inner_size) * scale,
                    outline=palette["chip_inner"],
                    width=outline_width,
                )
        else:
            chip_margin = 0
            chip_x = 0
            chip_y = 0
            chip_size = width_px
            display_char = self._display_char()
            chip_radius = max(self._chip_corner_radius_for_size(width_px + 2), int(round(width_px * 0.36))) * scale
            draw.rounded_rectangle(
                (
                    chip_margin,
                    chip_margin,
                    (width_px * scale) - chip_margin - 1,
                    (height_px * scale) - chip_margin - 1,
                ),
                radius=max(chip_radius - scale, 5 * scale),
                fill=palette["chip_fill"],
            )
            inset = max(scale * 2, int(round(scale * 1.75)))
            if display_char:
                pass
            elif self.state == "paused":
                bar_width = max(2, int(width_px * 0.12)) * scale
                gap = max(2, int(width_px * 0.10)) * scale
                x_mid = int((width_px * scale) / 2)
                y1 = int(height_px * scale * 0.26)
                y2 = int(height_px * scale * 0.74)
                draw.rounded_rectangle(
                    (x_mid - gap - bar_width, y1, x_mid - gap - 1, y2),
                    radius=max(scale, int(bar_width / 2)),
                    fill=palette["chip_text"],
                )
                draw.rounded_rectangle(
                    (x_mid + gap, y1, x_mid + gap + bar_width - 1, y2),
                    radius=max(scale, int(bar_width / 2)),
                    fill=palette["chip_text"],
                )
            else:
                border_radius = max(4 * scale, chip_radius - (inset * 2))
                draw.rounded_rectangle(
                    (
                        inset,
                        inset,
                        (width_px * scale) - inset - 1,
                        (height_px * scale) - inset - 1,
                    ),
                    radius=border_radius,
                    outline=palette["chip_outline"],
                    width=max(scale, int(round(scale * 0.95))),
                )
                inner_inset = inset + max(scale, int(round(scale * 0.9)))
                draw.rounded_rectangle(
                    (
                        inner_inset,
                        inner_inset,
                        (width_px * scale) - inner_inset - 1,
                        (height_px * scale) - inner_inset - 1,
                    ),
                    radius=max(4 * scale, chip_radius - (inner_inset * 2)),
                    outline=palette["chip_inner"],
                    width=max(1, int(round(scale * 0.55))),
                )

        resampling = getattr(getattr(PIL.Image, "Resampling", PIL.Image), "LANCZOS", PIL.Image.LANCZOS)
        image = image.resize((width_px, height_px), resampling)
        rendered = (image, chip_x, chip_y, chip_size, display_char)
        self._surface_cache[cache_key] = rendered
        if len(self._surface_cache) > 48:
            try:
                self._surface_cache.pop(next(iter(self._surface_cache)))
            except Exception:
                pass
        return rendered

    def _draw_chip_content(self, chip_x, chip_y, chip_size, palette, display_char, expanded):
        chip_x2 = chip_x + chip_size - 1
        chip_y2 = chip_y + chip_size - 1
        self._draw_chip(chip_x, chip_y, chip_x2, chip_y2, palette["chip_fill"], palette["chip_outline"], antialias=2, width=1)
        if display_char:
            self.canvas.create_text(
                chip_x + (chip_size / 2),
                chip_y + (chip_size / 2),
                text=display_char.upper(),
                fill=palette["chip_text"],
                font=self.char_font,
            )
            return
        if self.state == "paused":
            bar_width = max(2, int(chip_size * 0.14))
            gap = max(2, int(chip_size * 0.12))
            x_mid = chip_x + (chip_size / 2)
            y1 = chip_y + int(chip_size * 0.24)
            y2 = chip_y + int(chip_size * 0.76)
            self.canvas.create_rectangle(x_mid - gap - bar_width, y1, x_mid - gap, y2, fill=palette["chip_text"], outline="")
            self.canvas.create_rectangle(x_mid + gap, y1, x_mid + gap + bar_width, y2, fill=palette["chip_text"], outline="")
            return
        if not expanded or chip_size < 20:
            return
        inner_inset = max(3, int(round(chip_size * 0.23)))
        draw_rounded_canvas_rect(
            self.canvas,
            chip_x + inner_inset,
            chip_y + inner_inset,
            chip_x2 - inner_inset,
            chip_y2 - inner_inset,
            self._chip_corner_radius_for_size(max(6, chip_size - (inner_inset * 2))),
            fill="",
            outline=palette["chip_inner"],
            width=1,
            antialias=2,
        )

    def _redraw(self, antialias=2, force=False):
        expanded = self._is_expanded()
        effective_antialias = 4
        render_signature = self._render_signature(effective_antialias)
        if not force and render_signature == self._last_render_signature:
            return
        self._last_render_signature = render_signature

        self.canvas.delete("all")
        self.canvas._eae_image_refs = []
        palette = self._state_palette()
        self._set_window_bg(palette["surface_fill"] if expanded else palette["chip_fill"])
        surface_ref, chip_x, chip_y, chip_size, display_char = self._render_indicator_surface(expanded, palette)
        self.canvas._eae_image_refs.append(surface_ref)
        self.canvas.create_image(0, 0, image=surface_ref, anchor="nw")
        text = self._panel_text()
        if display_char:
            self.canvas.create_text(
                chip_x + (chip_size / 2),
                chip_y + (chip_size / 2),
                text=display_char.upper(),
                fill=palette["chip_text"],
                font=self.char_font,
            )
        self.panel_scroll_max = 0
        if expanded and text:
            chip_side = self._anchor_side()
            text_width = max(220, self.current_width - (self.panel_padding * 2) - chip_size - self.gap - 18)
            bottom_reserve = max(18, int(self.panel_padding * 0.9)) + (18 if self.answer_preview else 0)
            text_view_height = max(56, self.current_height - (self.panel_padding * 2) - bottom_reserve)
            _, text_height = self._measure_text_box(text, text_width)
            self.panel_scroll_max = max(0, int(text_height - text_view_height))
            if self.panel_scroll_offset > self.panel_scroll_max:
                self.panel_scroll_offset = self.panel_scroll_max
            if self.panel_scroll_offset < 0:
                self.panel_scroll_offset = 0
            if chip_side == "left":
                text_x = chip_x + chip_size + self.gap
            else:
                text_x = self.panel_padding
            text_y = (self.panel_padding + 2) - int(self.panel_scroll_offset)
            self.canvas.create_text(
                text_x,
                text_y,
                text=text,
                fill=palette["text"],
                font=self.body_font,
                anchor="nw",
                justify="left",
                width=text_width,
            )
            can_draw_highlight = bool(
                self.answer_preview
                and self.answer_progress_index > 0
                and not (
                    typing_hook is not None
                    and len(self.answer_preview) > INDICATOR_TYPING_HIGHLIGHT_MAX_CHARS
                )
            )
            if can_draw_highlight:
                self.canvas.create_text(
                    text_x,
                    text_y,
                    text=self.answer_preview[: self.answer_progress_index],
                    fill=palette["highlight_text"],
                    font=self.body_font,
                    anchor="nw",
                    justify="left",
                    width=text_width,
                )
            if self.answer_preview:
                total = len(self.answer_preview)
                if total > 0:
                    fraction = max(0.0, min(1.0, float(self.answer_progress_index) / float(total)))
                    bar_width = max(80, self.current_width - (self.panel_padding * 2))
                    bar_height = max(5, int(round(self.base_size * 0.24)))
                    bar_left = self.panel_padding
                    bar_top = self.current_height - max(12, int(self.panel_padding * 0.72)) - bar_height
                    bar_right = bar_left + bar_width
                    bar_bottom = bar_top + bar_height
                    self.canvas.create_rectangle(
                        bar_left,
                        bar_top,
                        bar_right,
                        bar_bottom,
                        fill=palette["progress_track"],
                        outline="",
                    )
                    fill_width = int(round(bar_width * fraction))
                    if fill_width > 0:
                        self.canvas.create_rectangle(
                            bar_left,
                            bar_top,
                            bar_left + fill_width,
                            bar_bottom,
                            fill=palette["progress_fill"],
                            outline="",
                        )
            if self.panel_scroll_max > 0:
                track_top = self.panel_padding + 2
                track_bottom = track_top + text_view_height
                track_right = self.current_width - max(6, int(self.panel_padding * 0.5))
                track_left = track_right - 3
                self.canvas.create_rectangle(
                    track_left,
                    track_top,
                    track_right,
                    track_bottom,
                    fill=palette["progress_track"],
                    outline="",
                )
                thumb_height = max(18, int((text_view_height / max(1, text_height)) * text_view_height))
                thumb_travel = max(1, text_view_height - thumb_height)
                thumb_top = track_top + int((self.panel_scroll_offset / max(1, self.panel_scroll_max)) * thumb_travel)
                self.canvas.create_rectangle(
                    track_left,
                    thumb_top,
                    track_right,
                    thumb_top + thumb_height,
                    fill=palette["progress_fill"],
                    outline="",
                )
        if self.answer_preview:
            self.progress_rendered_index = int(self.answer_progress_index)
            self.progress_rendered_at = time.monotonic()
        else:
            self.progress_rendered_index = -1
            self.progress_rendered_at = 0.0

    def _cancel_scheduled_collapse(self):
        if self.collapse_after_id is None:
            return
        try:
            self.root.after_cancel(self.collapse_after_id)
        except Exception:
            pass
        self.collapse_after_id = None

    def _schedule_collapse(self):
        self._cancel_scheduled_collapse()
        self.collapse_after_id = self.root.after(150, self._collapse_if_possible)

    def _collapse_if_possible(self):
        self.collapse_after_id = None
        if self.hidden or self.hover_inside or self.panel_pinned:
            return
        if self._is_pointer_inside():
            return
        self.target_width = self.collapsed_width
        self.target_height = self.collapsed_height
        self._sync_target_size()
        self._redraw(force=True)

    def _scroll_panel(self, delta_pixels):
        if self.panel_scroll_max <= 0:
            return False
        next_offset = int(min(max(0, self.panel_scroll_offset + int(delta_pixels)), self.panel_scroll_max))
        if next_offset == self.panel_scroll_offset:
            return False
        self.panel_scroll_offset = next_offset
        self._redraw(force=False)
        return True

    def _on_mouse_wheel(self, event):
        if self.hidden or not self._is_expanded() or not self._panel_is_requested() or self.panel_scroll_max <= 0:
            return None
        if not self.hover_inside and not self._is_pointer_inside():
            return None
        direction = 0
        wheel_delta = int(getattr(event, "delta", 0) or 0)
        if wheel_delta:
            direction = -1 if wheel_delta > 0 else 1
        else:
            event_num = int(getattr(event, "num", 0) or 0)
            if event_num == 4:
                direction = -1
            elif event_num == 5:
                direction = 1
        if direction == 0:
            return None
        line_height = max(12, int(self.body_font.metrics("linespace")))
        delta_pixels = direction * line_height * INDICATOR_PANEL_SCROLL_LINES
        if self._scroll_panel(delta_pixels):
            return "break"
        return None

    def _on_hover_enter(self, _event):
        if self.hidden:
            return
        self.hover_inside = True
        self._cancel_scheduled_collapse()
        if self.state in {"idle", "cooldown"} or self.answer_preview:
            self._sync_target_size()
            self._redraw(force=True)

    def _on_hover_leave(self, _event):
        if self.hidden:
            return
        self.hover_inside = False
        self._schedule_collapse()

    def _on_click_toggle(self, _event):
        if self.hidden:
            return
        if self.click_after_id is not None:
            try:
                self.root.after_cancel(self.click_after_id)
            except Exception:
                pass
        self.click_after_id = self.root.after(180, self._apply_single_click)

    def _apply_single_click(self):
        self.click_after_id = None
        if not (self.answer_preview or self.state in {"idle", "cooldown"}):
            return
        self.panel_pinned = not self.panel_pinned
        if self.panel_pinned:
            self.hover_inside = True
            self._cancel_scheduled_collapse()
            self._sync_target_size()
            self._redraw(force=True)
        else:
            if not self._is_pointer_inside():
                self.hover_inside = False
            self._collapse_if_possible()

    def _on_double_click(self, _event=None):
        if self.click_after_id is not None:
            try:
                self.root.after_cancel(self.click_after_id)
            except Exception:
                pass
            self.click_after_id = None
        Thread(target=lambda: open_settings_menu(hide_indicator_temporarily=True), daemon=True).start()

    def _should_redraw_progress(self, text_changed, typed_index):
        if not self._panel_is_requested() or self.hidden:
            return False
        total_chars = len(self.answer_preview)
        if total_chars <= 0:
            self.progress_rendered_at = 0.0
            self.progress_rendered_index = -1
            return True
        if text_changed or typed_index <= 0 or typed_index >= total_chars:
            self.progress_rendered_at = time.monotonic()
            self.progress_rendered_index = int(typed_index)
            return True
        if typing_hook is None:
            self.progress_rendered_at = time.monotonic()
            self.progress_rendered_index = int(typed_index)
            return True
        now = time.monotonic()
        step_delta = int(typed_index) - int(self.progress_rendered_index)
        time_delta = now - float(self.progress_rendered_at)
        if (
            step_delta < INDICATOR_TYPING_PANEL_RENDER_MIN_STEP
            and time_delta < INDICATOR_TYPING_PANEL_RENDER_MIN_INTERVAL
        ):
            return False
        self.progress_rendered_at = now
        self.progress_rendered_index = int(typed_index)
        return True

    def set_command_mode(self, mode):
        self.command_mode = "toprow" if str(mode or "").strip().lower() == "toprow" else "numpad"
        self.control_hint_text = self._build_control_hint_text()
        self._text_measure_cache.clear()
        self._surface_cache.clear()
        self._sync_target_size()
        self._last_render_signature = None
        if not self.hidden:
            self._redraw(force=True)

    def refresh_preferences(self):
        self.command_mode = str(command_key_mode).strip().lower() or "numpad"
        self._apply_size_metrics()
        self.control_hint_text = self._build_control_hint_text()
        self.body_font.configure(size=max(9, int(round(self.base_size * 0.55))))
        self.char_font.configure(size=max(8, int(round(self.base_size * 0.42))))
        self.max_panel_width = max(340, min(560, int(self.root.winfo_screenwidth() * 0.34)))
        self._last_render_signature = None
        self._text_measure_cache.clear()
        self._surface_cache.clear()
        self._sync_target_size(animate=False)
        self._set_geometry(self.target_width, self.target_height)
        self._schedule_native_refresh(force=True)
        if not self.hidden:
            self._redraw(force=True)
        self._schedule_frame_tick()

    def set_idle(self):
        self.current_char = ""
        self._set_state("idle")

    def set_processing(self):
        self.current_char = ""
        self._set_state("processing")
        self.hover_inside = False
        self._collapse_if_possible()

    def set_ready(self):
        self.current_char = ""
        self._set_state("ready")

    def set_paused(self):
        self.current_char = ""
        self._set_state("paused")

    def show_answer_char(self, value):
        self.current_char = (value or "").strip()[:1]
        self._set_state("ready")

    def set_answer_preview(self, value):
        self.set_answer_progress(value, 0)

    def set_answer_progress(self, value, typed_count=0):
        text = str(value or "").strip()
        typed_index = max(0, min(len(text), int(typed_count or 0)))
        if text == self.answer_preview and typed_index == self.answer_progress_index:
            return
        text_changed = text != self.answer_preview
        self.answer_preview = text
        self.answer_progress_index = typed_index
        self.answer_preview_expires_at = time.monotonic() + ANSWER_PREVIEW_RETENTION_SECONDS if text and typed_index >= len(text) else 0.0
        if text_changed:
            self.panel_scroll_offset = 0
            self._sync_target_size()
        # Skip heavy redraws unless the panel is actually visible to the user.
        if not self.hidden and self._should_redraw_progress(text_changed, typed_index):
            self._redraw(force=False)
        if self.answer_preview_expires_at > 0:
            self._schedule_frame_tick()

    def clear_answer_preview(self):
        if not self.answer_preview and self.answer_progress_index == 0:
            return
        self.answer_preview = ""
        self.answer_progress_index = 0
        self.answer_preview_expires_at = 0.0
        self.panel_scroll_offset = 0
        self.panel_scroll_max = 0
        self.progress_rendered_at = 0.0
        self.progress_rendered_index = -1
        self._sync_target_size()
        if not self.hidden:
            self._redraw(force=False)
        self._schedule_frame_tick()

    def _cooldown_seconds_remaining(self):
        if self.cooldown_until <= 0:
            return 0
        return max(0, int(math.ceil(self.cooldown_until - time.monotonic())))

    def _display_char(self):
        if self.state == "cooldown":
            remaining = self._cooldown_seconds_remaining()
            if remaining > 0:
                return str(remaining)
        return str(self.current_char or "")

    def set_cooldown(self, seconds):
        timeout = max(0.0, float(seconds or 0.0))
        if timeout <= 0:
            self.clear_cooldown()
            return
        self.current_char = ""
        self.cooldown_until = time.monotonic() + timeout
        self._set_state("cooldown")
        self._schedule_frame_tick()

    def clear_cooldown(self):
        if self.cooldown_until <= 0 and self.state != "cooldown":
            return
        self.cooldown_until = 0.0
        self.current_char = ""
        if self.state == "cooldown":
            self._set_state("idle")
        elif not self.hidden:
            self._redraw(force=True)
        self._schedule_frame_tick()

    def hide(self):
        global indicator_capture_protected
        if not self.hidden:
            self._cancel_scheduled_collapse()
            self._cancel_size_animation()
            self._cancel_native_heartbeat()
            if self.native_refresh_after_id is not None:
                try:
                    self.root.after_cancel(self.native_refresh_after_id)
                except Exception:
                    pass
                self.native_refresh_after_id = None
            self.native_refresh_force_pending = False
            indicator_capture_protected = False
            self.root.withdraw()
            self.hidden = True
            set_indicator_runtime_state(active=True, hidden=True)

    def show(self):
        if self.hidden:
            self.root.deiconify()
            self.root.attributes("-topmost", True)
            self.hidden = False
            set_indicator_runtime_state(active=True, hidden=False)
            self._last_render_signature = None
            self._last_native_signature = None
            self._redraw(force=True)
            self._schedule_frame_tick()
            self._schedule_native_refresh(delay_ms=30, force=True)
            self._schedule_native_heartbeat()

    def run(self):
        self.root.mainloop()


def init_indicator():
    global indicator, indicator_dispatch_queue
    indicator_ready_event.clear()
    indicator_dispatch_queue = queue.SimpleQueue()
    set_indicator_runtime_state(active=False, hidden=True)
    indicator_debug("indicator.init.entry")
    try:
        indicator = Win32StatusIndicator()
        set_indicator_runtime_state(active=True, hidden=True)
        indicator.set_command_mode(command_key_mode)
        if indicator_manual_hidden or privacy_forced_hidden:
            indicator.hide()
        else:
            indicator.show()
        indicator_ready_event.set()
        indicator_debug("indicator.init.ready")
        indicator_debug("indicator.startup_visibility_sync.success", hidden=indicator_manual_hidden)
        indicator.run()
        indicator_ready_event.clear()
        indicator = None
        set_indicator_runtime_state(active=False, hidden=True)
        indicator_debug("indicator.mainloop.exit")
    except Exception:
        indicator_ready_event.clear()
        indicator = None
        set_indicator_runtime_state(active=False, hidden=True)
        indicator_debug("indicator.init.exception", traceback=traceback.format_exc())
        raise


def indicator_call(func):
    local_indicator = indicator
    if not local_indicator or not indicator_ready_event.is_set():
        return
    try:
        indicator_dispatch_queue.put(func)
        if hasattr(local_indicator, "wake_dispatch"):
            local_indicator.wake_dispatch()
    except Exception:
        logger.debug("Indicator callback queueing failed.", exc_info=True)


def reset_indicator_progress_dispatch_state():
    global indicator_progress_pending_text, indicator_progress_pending_index, indicator_progress_dispatch_scheduled
    with indicator_progress_lock:
        indicator_progress_pending_text = ""
        indicator_progress_pending_index = 0
        indicator_progress_dispatch_scheduled = False


def _flush_indicator_progress_dispatch(local_indicator):
    global indicator_progress_dispatch_scheduled
    with indicator_progress_lock:
        payload = indicator_progress_pending_text
        payload_index = indicator_progress_pending_index
        indicator_progress_dispatch_scheduled = False
    try:
        local_indicator.set_answer_progress(payload, payload_index)
    except Exception:
        logger.debug("Indicator progress callback failed.", exc_info=True)


def indicator_set_idle():
    indicator_call(lambda obj: obj.set_idle())


def indicator_set_processing():
    indicator_call(lambda obj: obj.set_processing())


def indicator_set_ready():
    indicator_call(lambda obj: obj.set_ready())


def indicator_set_paused():
    indicator_call(lambda obj: obj.set_paused())


def indicator_set_cooldown(seconds):
    indicator_call(lambda obj: obj.set_cooldown(seconds) if hasattr(obj, "set_cooldown") else None)


def indicator_clear_cooldown():
    indicator_call(lambda obj: obj.clear_cooldown() if hasattr(obj, "clear_cooldown") else None)


def indicator_show_answer_char(value):
    indicator_call(lambda obj: obj.show_answer_char(value))


def indicator_set_answer_progress(value, typed_count):
    global indicator_progress_pending_text, indicator_progress_pending_index, indicator_progress_dispatch_scheduled
    local_indicator = indicator
    if not local_indicator or not indicator_ready_event.is_set():
        return
    payload = str(value or "")
    payload_index = int(max(0, typed_count or 0))
    if payload_index > len(payload):
        payload_index = len(payload)
    with indicator_progress_lock:
        indicator_progress_pending_text = payload
        indicator_progress_pending_index = payload_index
        if indicator_progress_dispatch_scheduled:
            return
        indicator_progress_dispatch_scheduled = True
    indicator_call(_flush_indicator_progress_dispatch)


def indicator_clear_answer_preview():
    reset_indicator_progress_dispatch_state()
    indicator_call(lambda obj: obj.clear_answer_preview())


def indicator_set_command_mode(mode):
    indicator_call(lambda obj: obj.set_command_mode(mode))


def indicator_hide():
    indicator_debug("indicator.hide.requested")
    indicator_call(lambda obj: obj.hide())


def indicator_show():
    if privacy_forced_hidden:
        indicator_debug("indicator.show.blocked", reason="privacy_forced_hidden")
        return
    indicator_debug("indicator.show.requested")
    indicator_call(lambda obj: obj.show())


def set_indicator_manual_visibility(hidden):
    global indicator_manual_hidden
    indicator_manual_hidden = bool(hidden)
    indicator_debug("indicator.manual_visibility", hidden=indicator_manual_hidden)
    if hidden:
        indicator_hide()
    else:
        indicator_show()


def get_status_text():
    with session_lock:
        return session_status_text


def build_tray_image():
    image = PIL.Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = PIL.ImageDraw.Draw(image)
    draw.rounded_rectangle((14, 14, 50, 50), radius=10, fill="#040404", outline="#22D05D", width=4)
    return image


def tray_status_label(_):
    return tr("tray.status", status=get_status_text())


def tray_open_ui(icon, item):
    open_settings_menu()


def tray_toggle_indicator(icon, item):
    toggle_indicator_visibility()


def tray_capture_privacy_label(_):
    if is_capture_privacy_active():
        return tr("tray.capture_disable")
    return tr("tray.capture_enable")


def tray_toggle_capture_privacy(icon, item):
    _ = icon
    _ = item
    toggle_capture_privacy()


def tray_check_updates(icon, item):
    _ = icon
    _ = item
    Thread(target=lambda: check_for_updates(manual=True), daemon=True).start()


def tray_exit(icon, item):
    exit_program(trigger_uninstall=False)


def run_tray_icon():
    global tray_icon
    pystray_module = get_pystray_module()
    if pystray_module is None:
        return
    tray_icon = pystray_module.Icon(
        "EyesAndEars",
        build_tray_image(),
        "EyesAndEars",
        pystray_module.Menu(
            pystray_module.MenuItem(tr("tray.open"), tray_open_ui),
            pystray_module.MenuItem(tray_status_label, None, enabled=False),
            pystray_module.MenuItem(tr("tray.toggle"), tray_toggle_indicator),
            pystray_module.MenuItem(tray_capture_privacy_label, tray_toggle_capture_privacy),
            pystray_module.MenuItem(tr("tray.check_updates"), tray_check_updates),
            pystray_module.MenuItem(tr("tray.quit"), tray_exit),
        ),
    )
    tray_icon.run()


def block_hotkey(action, seconds=0.25):
    hotkey_block_until[action] = time.monotonic() + seconds


def hotkey_blocked(action):
    return time.monotonic() < hotkey_block_until[action]


def hotkey_block_seconds(action):
    if action == "paste_all":
        return 0.9
    if action == "repeat_prev":
        return 0.45
    return 0.25


def is_character_like_key(name):
    key_name = str(name or "").strip().lower()
    if not key_name:
        return False
    if len(key_name) == 1:
        return True
    return key_name in {"space"}


def get_mouse_position():
    if os.name != "nt":
        return None
    try:
        point = wintypes.POINT()
        if _user32.GetCursorPos(ctypes.byref(point)):
            return int(point.x), int(point.y)
    except Exception:
        pass
    return None


def get_event_scan_code(event):
    try:
        return int(getattr(event, "scan_code", -1))
    except Exception:
        return -1


def event_matches_command_mode(event, mode=None):
    local_mode = str(mode or command_key_mode).strip().lower()
    keypad_flag = getattr(event, "is_keypad", None)
    if keypad_flag is None:
        return True
    is_keypad = bool(keypad_flag)
    if local_mode == "toprow":
        return not is_keypad
    return is_keypad


def get_numpad_action(event):
    return get_hotkey_action(event)


def system_modifier_pressed():
    if os.name == "nt":
        try:
            vk_codes = (0x11, 0x12, 0x5B, 0x5C)  # Ctrl, Alt, Left Win, Right Win
            return any(bool(_user32.GetAsyncKeyState(code) & 0x8000) for code in vk_codes)
        except Exception:
            pass
    try:
        return bool(
            keyboard.is_pressed("alt")
            or keyboard.is_pressed("ctrl")
            or keyboard.is_pressed("win")
        )
    except Exception:
        return False


def safe_keyboard_unhook(hook):
    if hook is None:
        return
    try:
        if callable(hook):
            hook()
            return
    except Exception:
        pass
    try:
        keyboard.unhook(hook)
    except Exception:
        pass


def stop_command_mode_probe():
    global command_mode_probe_hook
    if command_mode_probe_hook is None:
        return
    safe_keyboard_unhook(command_mode_probe_hook)
    command_mode_probe_hook = None


def on_command_mode_probe(event):
    global command_probe_window_start, command_probe_attempt_count, command_probe_last_scan, command_numpad_seen
    if command_hotkeys_customized:
        stop_command_mode_probe()
        return
    if command_key_mode != "numpad":
        return
    if event.event_type != "down":
        return
    if typing_hook is not None or post_type_guard_active or is_processing or has_pending_answer():
        return
    if system_modifier_pressed():
        return
    scan_code = get_event_scan_code(event)
    if scan_code in NUMPAD_SCAN_TO_ACTION and event_matches_command_mode(event, "numpad"):
        command_numpad_seen = True
        stop_command_mode_probe()
        return
    if scan_code not in TOPROW_SCAN_TO_ACTION:
        return
    if not event_matches_command_mode(event, "toprow"):
        return
    now = time.monotonic()
    if (
        command_probe_window_start <= 0
        or (now - command_probe_window_start) > 9.0
        or command_probe_last_scan != scan_code
    ):
        command_probe_window_start = now
        command_probe_attempt_count = 0
        command_probe_last_scan = scan_code
    command_probe_attempt_count += 1
    if command_probe_attempt_count >= 3 and not command_numpad_seen:
        set_command_key_mode("toprow")
        command_probe_window_start = 0.0
        command_probe_attempt_count = 0
        command_probe_last_scan = -1


def start_command_mode_probe():
    global command_mode_probe_hook
    if command_mode_probe_hook is not None:
        return
    if command_hotkeys_customized:
        return
    if command_key_mode != "numpad":
        return
    try:
        command_mode_probe_hook = keyboard.hook(on_command_mode_probe, suppress=False)
    except Exception:
        command_mode_probe_hook = None


def unhook_command_key_handlers():
    global command_key_hooks
    if not command_key_hooks:
        return
    for hook in command_key_hooks:
        safe_keyboard_unhook(hook)
    command_key_hooks = []


def dispatch_hotkey_action(action, event=None):
    try:
        if action == "primary":
            handle_primary_hotkey()
        elif action == "indicator":
            handle_indicator_hotkey()
        elif action == "clear_ctx":
            handle_clear_ctx_hotkey()
        elif action == "paste_all":
            handle_paste_all_hotkey()
        elif action == "repeat_prev":
            handle_repeat_prev_hotkey()
        elif action == "exit":
            handle_exit_hotkey(event=event)
    except Exception:
        indicator_debug("hotkey.dispatch.exception", action=str(action or ""), traceback=traceback.format_exc())
        logger.exception("Hotkey dispatch failed for action '%s'.", action)


def on_command_key_event(event, action=None, binding_key=""):
    try:
        if event is None:
            return True
        if getattr(event, "event_type", "") != "down":
            return True
        if system_modifier_pressed():
            return True
        if binding_key and not hotkey_event_matches_binding(event, binding_key):
            return True
        if not action:
            action = get_hotkey_action(event)
        if not action:
            return True
        dispatch_hotkey_action(action, event=event)
        return False
    except Exception:
        indicator_debug("hotkey.event.exception", traceback=traceback.format_exc())
        logger.exception("Hotkey event handler failed.")
        return True


def safe_keyboard_write(text, delay=0):
    payload = str(text or "")
    if not payload:
        return True
    try:
        keyboard.write(payload, delay=delay)
        return True
    except Exception:
        indicator_debug("keyboard.write.exception", length=len(payload), traceback=traceback.format_exc())
        logger.exception("keyboard.write failed.")
        return False


def register_command_key_handlers(mode=None):
    global command_key_hooks, command_key_mode
    local_mode = str(mode or command_key_mode).strip().lower()
    if local_mode not in {"numpad", "toprow"}:
        local_mode = "numpad"
    unhook_command_key_handlers()
    if typing_hook is not None or post_type_guard_active:
        return
    try:
        hooks = []
        registered_bindings = set()
        for action in HOTKEY_ACTION_ORDER:
            binding_key = str(command_hotkeys.get(action, "") or "").strip().lower()
            if not binding_key or binding_key in registered_bindings:
                continue
            if is_reserved_system_hotkey_binding(binding_key):
                continue
            binding = ALLOWED_HOTKEY_BINDINGS.get(binding_key)
            scan_code = int((binding or {}).get("scan_code", 0) or 0)
            if scan_code <= 0:
                continue
            registered_bindings.add(binding_key)
            hooks.append(
                keyboard.on_press_key(
                    scan_code,
                    lambda event, action=action, binding_key=binding_key: on_command_key_event(
                        event,
                        action=action,
                        binding_key=binding_key,
                    ),
                    suppress=True,
                )
            )
        command_key_hooks = hooks
    except Exception:
        command_key_hooks = []
    command_key_mode = local_mode


def detect_initial_command_key_mode():
    forced_top = str(os.environ.get("EAE_FORCE_TOP_ROW_HOTKEYS", "")).strip().lower() in {"1", "true", "yes", "on"}
    if forced_top:
        return "toprow"
    if os.name != "nt":
        return "toprow"
    try:
        keyboard_type = int(ctypes.windll.user32.GetKeyboardType(0))
        if keyboard_type not in {4, 7}:
            return "toprow"
    except Exception:
        return "numpad"
    return "numpad"


def set_command_key_mode(mode):
    global command_key_mode, command_hotkeys
    local_mode = "toprow" if str(mode).strip().lower() == "toprow" else "numpad"
    command_key_mode = local_mode
    if not command_hotkeys_customized:
        command_hotkeys = get_default_command_hotkeys(local_mode)
    register_command_key_handlers(local_mode)
    if local_mode != "numpad" or command_hotkeys_customized:
        stop_command_mode_probe()
    indicator_set_command_mode(local_mode)


def on_post_type_guard_event(event):
    # This hook runs with suppress=True, so return True unless we intentionally
    # consume a control action.
    if event.event_type != "down":
        return True
    if system_modifier_pressed():
        return True
    action = get_numpad_action(event)
    if action:
        dispatch_hotkey_action(action, event=event)
        return False
    deactivate_post_type_guard()
    return True


def post_type_guard_watch_loop():
    while True:
        with post_type_guard_lock:
            if not post_type_guard_active:
                return
            local_until = float(post_type_guard_until)
            origin = post_type_guard_mouse
        remaining = local_until - time.monotonic()
        if remaining <= 0:
            deactivate_post_type_guard()
            return
        wait_seconds = min(0.20, max(0.05, remaining))
        if post_type_guard_stop.wait(wait_seconds):
            return
        if time.monotonic() >= local_until:
            deactivate_post_type_guard()
            return
        if origin is not None:
            current = get_mouse_position()
            if current is not None and current != origin:
                deactivate_post_type_guard()
                return


def activate_post_type_guard(seconds=POST_TYPE_GUARD_SECONDS):
    global post_type_guard_hook, post_type_guard_active, post_type_guard_until, post_type_guard_mouse, post_type_guard_thread
    timeout = float(seconds or 0)
    if timeout <= 0:
        return
    with post_type_guard_lock:
        post_type_guard_until = time.monotonic() + timeout
        post_type_guard_mouse = get_mouse_position()
        if post_type_guard_active:
            indicator_set_cooldown(timeout)
            return
        post_type_guard_active = True
        post_type_guard_stop.clear()
    indicator_set_cooldown(timeout)
    unhook_command_key_handlers()
    try:
        post_type_guard_hook = keyboard.hook(on_post_type_guard_event, suppress=True)
    except Exception:
        with post_type_guard_lock:
            post_type_guard_active = False
        register_command_key_handlers(command_key_mode)
        return
    post_type_guard_thread = Thread(target=post_type_guard_watch_loop, daemon=True)
    post_type_guard_thread.start()


def deactivate_post_type_guard():
    global post_type_guard_hook, post_type_guard_active, post_type_guard_mouse, post_type_guard_thread
    hook_to_remove = None
    with post_type_guard_lock:
        if not post_type_guard_active:
            return
        post_type_guard_active = False
        post_type_guard_stop.set()
        post_type_guard_mouse = None
        hook_to_remove = post_type_guard_hook
        post_type_guard_hook = None
        post_type_guard_thread = None
    indicator_clear_cooldown()
    if hook_to_remove is not None:
        safe_keyboard_unhook(hook_to_remove)
    if typing_hook is None:
        register_command_key_handlers(command_key_mode)


def clear_typing_pressed_state():
    with typing_pressed_lock:
        typing_pressed_scancodes.clear()


def reset_progress_ui_state():
    global progress_ui_last_update, progress_ui_last_index
    with progress_ui_lock:
        progress_ui_last_update = 0.0
        progress_ui_last_index = -1


def push_indicator_progress(answer_text, typed_count, force=False):
    global progress_ui_last_update, progress_ui_last_index
    text_value = str(answer_text or "")
    index_value = int(max(0, typed_count or 0))
    if index_value > len(text_value):
        index_value = len(text_value)
    should_send = True
    now = time.monotonic()
    with progress_ui_lock:
        if not force and index_value < len(text_value):
            step_delta = index_value - int(progress_ui_last_index)
            time_delta = now - float(progress_ui_last_update)
            if step_delta <= 0:
                should_send = False
            elif step_delta < PROGRESS_UI_MIN_STEP and time_delta < PROGRESS_UI_MIN_INTERVAL:
                should_send = False
        if should_send:
            progress_ui_last_update = now
            progress_ui_last_index = index_value
    if should_send:
        indicator_set_answer_progress(text_value, index_value)


def enable_typing_mode():
    global typing_hook
    deactivate_post_type_guard()
    unhook_command_key_handlers()
    clear_typing_pressed_state()
    if typing_hook is None:
        typing_hook = keyboard.hook(on_smart_type, suppress=True)


def disable_typing_mode():
    global typing_hook
    if typing_hook:
        safe_keyboard_unhook(typing_hook)
        typing_hook = None
    clear_typing_pressed_state()
    if not post_type_guard_active:
        register_command_key_handlers(command_key_mode)


def has_pending_answer():
    return bool(current_answer) and current_index < len(current_answer)


def bump_answer_epoch():
    global answer_epoch
    with answer_epoch_lock:
        answer_epoch += 1
        return answer_epoch


def get_answer_epoch():
    with answer_epoch_lock:
        return answer_epoch


def clear_answer_state(invalidate=True):
    global current_answer, current_index, is_paused, pause_pending
    with write_lock:
        current_answer = ""
        current_index = 0
        is_paused = False
        pause_pending = False
    reset_progress_ui_state()
    reset_indicator_progress_dispatch_state()
    clear_typing_pressed_state()
    if invalidate:
        bump_answer_epoch()


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
    next_hidden = not bool(indicator_manual_hidden)
    if not next_hidden:
        set_indicator_manual_visibility(False)
        if not has_pending_answer() and not is_processing:
            indicator_clear_answer_preview()
            indicator_set_idle()
    else:
        set_indicator_manual_visibility(True)


def handle_primary_hotkey():
    if hotkey_blocked("primary"):
        return
    block_hotkey("primary", hotkey_block_seconds("primary"))
    handle_primary_action()


def handle_indicator_hotkey():
    if hotkey_blocked("indicator"):
        return
    block_hotkey("indicator", hotkey_block_seconds("indicator"))
    toggle_indicator_visibility()


def is_ctrl_modifier_pressed():
    try:
        return bool(
            keyboard.is_pressed("ctrl")
            or keyboard.is_pressed("left ctrl")
            or keyboard.is_pressed("right ctrl")
        )
    except Exception:
        return False


def handle_clear_ctx_hotkey():
    if hotkey_blocked("clear_ctx"):
        return
    block_hotkey("clear_ctx", hotkey_block_seconds("clear_ctx"))
    run_clear_ctx_action()


def run_clear_ctx_action():
    deactivate_post_type_guard()
    clear_answer_state()
    reset_api_context()
    disable_typing_mode()
    indicator_set_idle()


def handle_paste_all_hotkey():
    if hotkey_blocked("paste_all"):
        return
    block_hotkey("paste_all", hotkey_block_seconds("paste_all"))
    run_paste_all_action()


def paste_text_fast(text, keep_clipboard_text=""):
    payload = str(text or "")
    if not payload:
        return False
    try:
        pyperclip.copy(payload)
        keyboard.send("ctrl+v")
        if keep_clipboard_text:
            time.sleep(0.03)
            pyperclip.copy(keep_clipboard_text)
        return True
    except Exception:
        return False


def run_paste_all_action():
    global current_index
    disable_typing_mode()
    with write_lock:
        if not current_answer or current_index >= len(current_answer):
            return
        remaining = current_answer[current_index:]
        full_answer = current_answer
    pasted = paste_text_fast(remaining, keep_clipboard_text=full_answer)
    if not pasted:
        if not safe_keyboard_write(remaining):
            indicator_set_idle()
            clear_answer_state()
            return
    with write_lock:
        current_index = len(full_answer)
    push_indicator_progress(full_answer, len(full_answer), force=True)
    indicator_set_idle()
    clear_answer_state()
    activate_post_type_guard(POST_TYPE_GUARD_SECONDS)


def handle_repeat_prev_hotkey():
    if hotkey_blocked("repeat_prev"):
        return
    block_hotkey("repeat_prev", hotkey_block_seconds("repeat_prev"))
    run_repeat_prev_action()


def run_repeat_prev_action():
    global current_answer, current_index, is_paused, pause_pending
    deactivate_post_type_guard()
    with write_lock:
        answer_to_repeat = str(last_answer or "")
    if not answer_to_repeat:
        return
    bump_answer_epoch()
    disable_typing_mode()
    push_indicator_progress(answer_to_repeat, 0, force=True)
    with write_lock:
        current_answer = answer_to_repeat
        current_index = 0
        is_paused = False
        pause_pending = False
    indicator_set_ready()
    enable_typing_mode()


def handle_exit_hotkey(event=None):
    if hotkey_blocked("exit"):
        return
    block_hotkey("exit", hotkey_block_seconds("exit"))
    _ = event
    exit_program(trigger_uninstall=False)


def clean_response_text(text):
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
    with processing_lock:
        if is_processing:
            return
        is_processing = True
    request_epoch = get_answer_epoch()
    deactivate_post_type_guard()
    try:
        is_paused = False
        disable_typing_mode()
        indicator_set_processing()
        screenshot = PIL.ImageGrab.grab()
        try:
            raw_text = infer_via_api_key(screenshot)
        finally:
            try:
                screenshot.close()
            except Exception:
                pass
        final_text = clean_response_text(raw_text)
        if not final_text:
            raise RuntimeError("No response text returned.")

        if request_epoch != get_answer_epoch():
            indicator_set_idle()
            return

        with write_lock:
            if request_epoch != get_answer_epoch():
                indicator_set_idle()
                return
            last_answer = final_text
            current_answer = final_text
            current_index = 0

        push_indicator_progress(final_text, 0, force=True)
        pyperclip.copy(final_text)
        if len(final_text) == 1:
            disable_typing_mode()
            push_indicator_progress(final_text, len(final_text), force=True)
            indicator_show_answer_char(final_text)
            clear_answer_state()
            activate_post_type_guard(POST_TYPE_GUARD_SECONDS)
            return
        if pause_pending:
            pause_pending = False
            is_paused = True
            indicator_set_paused()
        else:
            indicator_set_ready()
            enable_typing_mode()
    except Exception as exc:
        if is_temporary_genai_busy_error(exc):
            logger.warning("Screenshot processing temporarily unavailable: %s", exc)
        else:
            logger.exception("Screenshot processing failed.")
        issue_kind = classify_api_runtime_issue(exc)
        if issue_kind:
            try:
                refresh_api_key_via_startup_ui(issue_kind)
            except Exception:
                logger.exception("API key recovery flow failed.")
        indicator_set_idle()
        clear_answer_state()
    finally:
        with processing_lock:
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
    candidate = str(raw_value).strip()
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{1,127}", candidate):
        return candidate
    return ""


def sanitize_package_query(raw_value):
    candidate = " ".join(str(raw_value or "").split()).strip()
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._ -]{1,127}", candidate):
        return candidate
    return ""


def parse_version_tuple(raw_value):
    numbers = [int(part) for part in re.findall(r"\d+", str(raw_value or ""))]
    if not numbers:
        return (0,)
    return tuple(numbers)


def is_newer_version(candidate_version, current_version):
    candidate = parse_version_tuple(candidate_version)
    current = parse_version_tuple(current_version)
    max_len = max(len(candidate), len(current))
    candidate += (0,) * (max_len - len(candidate))
    current += (0,) * (max_len - len(current))
    return candidate > current


def fetch_latest_release_metadata():
    global update_metadata_cache, update_metadata_cache_at
    now = time.monotonic()
    with update_state_lock:
        if (
            isinstance(update_metadata_cache, dict)
            and (now - update_metadata_cache_at) < UPDATE_METADATA_CACHE_TTL_SECONDS
        ):
            return dict(update_metadata_cache)
    session = get_http_session()
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": f"{APP_NAME}/{APP_VERSION}",
    }
    response = session.get(DEFAULT_RELEASES_API_URL, headers=headers, timeout=(2.0, 5.0), allow_redirects=False)
    response.raise_for_status()
    payload = response.json()
    assets = payload.get("assets") if isinstance(payload, dict) else []
    assets = assets if isinstance(assets, list) else []
    exe_asset = next(
        (
            asset for asset in assets
            if isinstance(asset, dict)
            and str(asset.get("name", "")).lower().endswith(".exe")
            and str(asset.get("browser_download_url", "")).strip()
        ),
        None,
    )
    metadata = {
        "version": str(payload.get("tag_name", "") if isinstance(payload, dict) else "").strip().lstrip("vV"),
        "release_url": str(payload.get("html_url", "") if isinstance(payload, dict) else "").strip() or DEFAULT_RELEASES_PAGE_URL,
        "download_url": str((exe_asset or {}).get("browser_download_url", "")).strip(),
        "asset_name": str((exe_asset or {}).get("name", "")).strip(),
    }
    with update_state_lock:
        update_metadata_cache = dict(metadata)
        update_metadata_cache_at = now
    return metadata


def powershell_single_quote(value):
    return "'" + str(value or "").replace("'", "''") + "'"


def cleanup_data_dir_command():
    candidate_paths = []
    try:
        candidate_paths.append(get_app_data_dir().resolve())
    except Exception:
        pass
    try:
        candidate_paths.append((resolve_install_root() / ".eyesandears").resolve())
    except Exception:
        pass
    unique_targets = []
    seen = set()
    for path_value in candidate_paths:
        target_text = str(path_value).strip()
        target_key = target_text.lower()
        if not target_text or target_key in seen:
            continue
        seen.add(target_key)
        unique_targets.append(target_text)
    if not unique_targets:
        return ""
    return "\n".join(
        f'if exist "{target_text}" rmdir /s /q "{target_text}"'
        for target_text in unique_targets
    )


def build_update_relaunch_command():
    if not getattr(sys, "frozen", False):
        return f'start "" "{Path(sys.executable).resolve()}" "{Path(__file__).resolve()}"'
    executable_path = Path(sys.executable).resolve()
    windows_apps_candidate = Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WindowsApps" / f"{APP_NAME}.exe"
    if windows_apps_candidate.exists():
        return f'start "" "{windows_apps_candidate}"'
    return f'start "" "{executable_path}"'


def winget_is_available():
    if os.name != "nt":
        return False
    try:
        result = subprocess.run(
            ["where", "winget"],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
        return result.returncode == 0 and bool(result.stdout.strip())
    except Exception:
        return False


def schedule_winget_upgrade_and_restart():
    package_id = resolve_winget_package_id()
    if not package_id or not winget_is_available():
        return False
    relaunch_command = build_update_relaunch_command()
    update_script = Path(tempfile.gettempdir()) / f"eyesandears-upgrade-{secrets.token_hex(8)}.cmd"
    script_text = (
        "@echo off\n"
        f"timeout /t {SELF_UNINSTALL_DELAY_SECONDS} /nobreak >nul\n"
        f'winget upgrade --id "{package_id}" --exact --silent --disable-interactivity --accept-source-agreements --accept-package-agreements\n'
        f"{relaunch_command}\n"
        'del /f /q "%~f0"\n'
    )
    update_script.write_text(script_text, encoding="utf-8")
    subprocess.Popen(
        ["cmd", "/c", str(update_script)],
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        close_fds=True,
    )
    return True


def schedule_direct_exe_update(download_url, asset_name=""):
    if not download_url:
        return False
    try:
        _parsed_dl = urlparse(download_url)
    except Exception:
        logger.warning("schedule_direct_exe_update: invalid download URL.")
        return False
    if _parsed_dl.scheme != "https":
        logger.warning("schedule_direct_exe_update blocked non-HTTPS download URL.")
        return False
    _dl_host = str(_parsed_dl.netloc or "").lower()
    _allowed_dl_hosts = ("github.com", "objects.githubusercontent.com", "codeload.github.com")
    if not any(_dl_host == h or _dl_host.endswith("." + h) for h in _allowed_dl_hosts):
        logger.warning("schedule_direct_exe_update blocked untrusted download host: %s", _dl_host)
        return False
    executable_path = Path(sys.executable if getattr(sys, "frozen", False) else __file__).resolve()
    target_path = executable_path
    if target_path.suffix.lower() != ".exe" or "windowsapps" in str(target_path).lower():
        safe_name = str(asset_name or f"{APP_NAME}-{int(time.time())}.exe").strip() or f"{APP_NAME}-{int(time.time())}.exe"
        target_path = Path(tempfile.gettempdir()) / safe_name
    relaunch_command = f'start "" "{target_path}"'
    update_script = Path(tempfile.gettempdir()) / f"eyesandears-download-update-{secrets.token_hex(8)}.cmd"
    script_text = (
        "@echo off\n"
        f"timeout /t {SELF_UNINSTALL_DELAY_SECONDS} /nobreak >nul\n"
        "powershell -NoProfile -ExecutionPolicy Bypass -Command "
        f"\"$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -Uri {powershell_single_quote(download_url)} -OutFile {powershell_single_quote(str(target_path))}\"\n"
        f"if exist \"{target_path}\" {relaunch_command}\n"
        'del /f /q "%~f0"\n'
    )
    update_script.write_text(script_text, encoding="utf-8")
    subprocess.Popen(
        ["cmd", "/c", str(update_script)],
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        close_fds=True,
    )
    return True


def schedule_app_update(download_url="", asset_name="", prefer_winget=True):
    if prefer_winget and schedule_winget_upgrade_and_restart():
        return True
    return schedule_direct_exe_update(download_url, asset_name=asset_name)


def install_update_and_restart(metadata, silent=False):
    global update_in_progress
    if not isinstance(metadata, dict):
        return False
    with update_state_lock:
        if update_in_progress:
            return False
        update_in_progress = True
    latest_version = str(metadata.get("version", "") or "").strip()
    download_url = str(metadata.get("download_url", "") or "").strip()
    asset_name = str(metadata.get("asset_name", "") or "").strip()
    try:
        scheduled = schedule_app_update(download_url, asset_name=asset_name, prefer_winget=True)
        if not scheduled:
            if not silent:
                show_styled_message(APP_NAME, tr("update.failed", detail="No installer source was available."), is_error=True, parent=None)
            return False
        if not silent:
            show_styled_message(APP_NAME, tr("update.available", version=latest_version or "latest"), is_error=False, parent=None)
        exit_program(trigger_uninstall=False)
        return True
    finally:
        with update_state_lock:
            update_in_progress = False


def check_for_updates(manual=False):
    try:
        metadata = fetch_latest_release_metadata()
    except Exception as exc:
        logger.warning("Update check failed.", exc_info=True)
        if manual:
            show_styled_message(APP_NAME, tr("update.failed", detail=exc), is_error=True, parent=None)
        return False

    latest_version = str(metadata.get("version", "") or "").strip()
    if not latest_version or not is_newer_version(latest_version, APP_VERSION):
        if manual:
            show_styled_message(APP_NAME, tr("update.current"), is_error=False, parent=None)
        return False
    return install_update_and_restart(metadata, silent=not manual)


def maybe_auto_update_on_startup():
    global update_check_started
    if not AUTO_UPDATE_ENABLED or os.name != "nt" or not getattr(sys, "frozen", False):
        return
    # Avoid unsolicited update/relaunch behavior for portable/manual EXE test runs.
    if not resolve_winget_package_id():
        return
    with update_state_lock:
        if update_check_started:
            return
        update_check_started = True
    try:
        check_for_updates(manual=False)
    finally:
        with update_state_lock:
            update_check_started = False


def resolve_winget_package_id():
    if DEFAULT_WINGET_PACKAGE_ID:
        return sanitize_package_id(DEFAULT_WINGET_PACKAGE_ID)
    return sanitize_package_id(detect_winget_package_id_from_path())


def schedule_manual_winget_uninstall(package_query="EyesAndEars"):
    query = sanitize_package_query(package_query) or "EyesAndEars"
    package_id = resolve_winget_package_id()
    if not winget_is_available():
        return False
    cleanup_command = cleanup_data_dir_command()
    uninstall_script = Path(tempfile.gettempdir()) / f"eyesandears-manual-uninstall-{secrets.token_hex(8)}.cmd"
    script_lines = [
        "@echo off",
        f"timeout /t {SELF_UNINSTALL_DELAY_SECONDS} /nobreak >nul",
    ]
    if package_id:
        script_lines.extend(
            [
                f"winget uninstall --id \"{package_id}\" --exact --purge --silent --disable-interactivity --accept-source-agreements",
                "if errorlevel 1 (",
                f"  winget uninstall --name \"{query}\" --exact --purge --silent --disable-interactivity --accept-source-agreements",
                ")",
            ]
        )
    else:
        script_lines.append(
            f"winget uninstall --name \"{query}\" --exact --purge --silent --disable-interactivity --accept-source-agreements"
        )
    if cleanup_command:
        script_lines.append(cleanup_command)
    script_lines.append('del /f /q "%~f0"')
    script_text = "\n".join(script_lines) + "\n"
    uninstall_script.write_text(script_text, encoding="utf-8")
    subprocess.Popen(
        ["cmd", "/c", str(uninstall_script)],
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        close_fds=True,
    )
    return True


def schedule_self_uninstall(package_query="EyesAndEars"):
    query = sanitize_package_query(package_query) or "EyesAndEars"
    package_id = resolve_winget_package_id()
    if not winget_is_available():
        return False
    cleanup_command = cleanup_data_dir_command()
    uninstall_script = Path(tempfile.gettempdir()) / f"eyesandears-self-uninstall-{secrets.token_hex(8)}.cmd"
    script_lines = [
        "@echo off",
        f"timeout /t {SELF_UNINSTALL_DELAY_SECONDS} /nobreak >nul",
    ]
    if package_id:
        script_lines.extend(
            [
                f"winget uninstall --id \"{package_id}\" --exact --purge --silent --disable-interactivity --accept-source-agreements",
                "if errorlevel 1 (",
                f"  winget uninstall --name \"{query}\" --exact --purge --silent --disable-interactivity --accept-source-agreements",
                ")",
            ]
        )
    else:
        script_lines.append(
            f"winget uninstall --name \"{query}\" --exact --purge --silent --disable-interactivity --accept-source-agreements"
        )
    if cleanup_command:
        script_lines.append(cleanup_command)
    script_lines.append('del /f /q "%~f0"')
    script_text = "\n".join(script_lines) + "\n"
    uninstall_script.write_text(script_text, encoding="utf-8")
    subprocess.Popen(
        ["cmd", "/c", str(uninstall_script)],
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        close_fds=True,
    )
    return True


def exit_program(trigger_uninstall=False):
    global tray_icon
    profile_mark("process.exit", trigger_uninstall=bool(trigger_uninstall))
    privacy_guard_stop_event.set()
    set_privacy_required_by_process(False)
    stop_command_mode_probe()
    try:
        end_remote_session()
    except BaseException:
        pass
    set_session_status(tr("status.stopped"), active=False)
    deactivate_post_type_guard()
    disable_typing_mode()
    unhook_command_key_handlers()
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
    try:
        if RUNTIME_PROFILER is not None:
            RUNTIME_PROFILER.close()
    except Exception:
        pass
    os._exit(0)


def on_smart_type(event):
    global current_index
    try:
        # This hook also runs with suppress=True. Return False only when we
        # intentionally replace a keypress with answer typing behavior.
        scan_code = get_event_scan_code(event)
        if system_modifier_pressed():
            if getattr(event, "event_type", "") == "up" and scan_code > 0:
                with typing_pressed_lock:
                    typing_pressed_scancodes.discard(scan_code)
            return True
        action = get_numpad_action(event)
        if action:
            if event.event_type == "down":
                dispatch_hotkey_action(action, event=event)
            elif event.event_type == "up" and scan_code > 0:
                with typing_pressed_lock:
                    typing_pressed_scancodes.discard(scan_code)
            return False
        if event.event_type == "up":
            if scan_code > 0:
                with typing_pressed_lock:
                    was_tracked = scan_code in typing_pressed_scancodes
                    typing_pressed_scancodes.discard(scan_code)
                if was_tracked:
                    return False
            return True
        if event.event_type != "down":
            return True
        key_name = str(getattr(event, "name", "") or "").strip().lower()
        if not is_character_like_key(key_name):
            return True
        if scan_code > 0:
            with typing_pressed_lock:
                if scan_code in typing_pressed_scancodes:
                    return False
                typing_pressed_scancodes.add(scan_code)
        if not current_answer or current_index >= len(current_answer):
            return False
        if not write_lock.acquire(blocking=False):
            return False
        try:
            # Re-check inside the lock: another thread may have cleared the answer
            # between the outer check above and acquiring the lock here.
            if not current_answer or current_index >= len(current_answer):
                return False
            char = current_answer[current_index]
            if not safe_keyboard_write(char, delay=0):
                disable_typing_mode()
                clear_answer_state()
                indicator_set_idle()
                return False
            current_index += 1
            progress_index = current_index
            progress_answer = current_answer
        finally:
            write_lock.release()
        push_indicator_progress(progress_answer, progress_index, force=(progress_index >= len(progress_answer)))
        if current_index >= len(progress_answer):
            disable_typing_mode()
            clear_answer_state()
            activate_post_type_guard(POST_TYPE_GUARD_SECONDS)
        return False
    except Exception:
        indicator_debug("typing.flow.exception", traceback=traceback.format_exc())
        logger.exception("Typing flow failed.")
        disable_typing_mode()
        clear_answer_state()
        indicator_set_idle()
        return False


def _run_post_ready_tasks():
    try:
        with profile_span("main.start_privacy_guard"):
            start_privacy_guard()
    except Exception:
        logger.debug("Privacy guard startup failed.", exc_info=True)
    try:
        if get_pystray_module() is not None:
            Thread(target=run_tray_icon, daemon=True, name="tray-icon").start()
    except Exception:
        logger.debug("Tray startup failed.", exc_info=True)
    if AUTO_UPDATE_ENABLED:
        def _delayed_auto_update():
            time.sleep(20.0)
            maybe_auto_update_on_startup()

        Thread(target=_delayed_auto_update, daemon=True, name="auto-update").start()


def run_indicator_runtime():
    for attempt in (1, 2):
        indicator_debug("indicator.init.attempt", attempt=attempt)
        try:
            with profile_span("indicator.init", attempt=attempt):
                init_indicator()
            indicator_debug("indicator.init.attempt.success", attempt=attempt)
            return
        except Exception:
            indicator_debug("indicator.init.attempt.failure", attempt=attempt, traceback=traceback.format_exc())
            logger.exception("Indicator initialization failed (attempt %s).", attempt)
            if attempt >= 2:
                raise
            time.sleep(0.35)


def main():
    with profile_span("main.startup"):
        global indicator_manual_hidden
        indicator_debug(
            "main.startup.begin",
            indicator_default_visible=INDICATOR_VISIBLE_BY_DEFAULT,
            strict_privacy_fallback=STRICT_PRIVACY_FALLBACK,
            capture_privacy_enabled=is_capture_privacy_active(),
        )
        apply_ui_theme_preference(os.environ.get("EAE_THEME", ui_theme_preference))
        ensure_ui_crisp_mode()
        hide_console_window()
        startup_progress_update("startup.launching")
        startup_progress_update("startup.restoring")
        with profile_span("main.resolve_auth_settings"):
            if not resolve_auth_settings():
                startup_progress_close()
                return
        startup_progress_update("startup.checking_auth")
        with profile_span("main.initialize_auth_mode"):
            if not initialize_auth_mode():
                startup_progress_close()
                return

        with profile_span("main.final_remote_preferences_sync"):
            try:
                remote_payload, _remote_updated_at = pull_remote_preferences()
                if isinstance(remote_payload, dict):
                    apply_remote_preferences_payload(remote_payload)
            except Exception:
                logger.debug("Final remote preference sync before indicator init failed.", exc_info=True)

        startup_progress_update("startup.starting_indicator")
        indicator_manual_hidden = not INDICATOR_VISIBLE_BY_DEFAULT

        with profile_span("main.hotkeys_init", mode=command_key_mode):
            set_command_key_mode(command_key_mode)
            start_command_mode_probe()
        startup_progress_update("startup.ready")
        startup_progress_close()
        _run_post_ready_tasks()
        profile_mark("main.ready")
    run_indicator_runtime()


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == STARTUP_SPLASH_SUBPROCESS_FLAG:
        try:
            raise SystemExit(run_startup_splash_subprocess(sys.argv[2]))
        except Exception:
            logger.exception("Startup splash subprocess failed.")
            raise SystemExit(1)
    if len(sys.argv) >= 4 and sys.argv[1] == AUTH_SHELL_SUBPROCESS_FLAG:
        try:
            raise SystemExit(run_auth_shell_subprocess(sys.argv[2], sys.argv[3]))
        except Exception:
            logger.exception("Auth shell subprocess failed.")
            raise SystemExit(1)
    try:
        main()
    except KeyboardInterrupt:
        try:
            exit_program(trigger_uninstall=False)
        except Exception:
            raise SystemExit(0)
    except Exception:
        logger.exception("Fatal runtime error.")
        raise SystemExit(1)
