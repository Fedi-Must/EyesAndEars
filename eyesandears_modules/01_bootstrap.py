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

