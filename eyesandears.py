import base64
import csv
import ctypes
import hashlib
import ipaddress
import io
import json
import logging
import math
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
import warnings
import webbrowser
from ctypes import wintypes
from datetime import datetime, timezone
from pathlib import Path
from threading import Event, Lock, Thread, current_thread
import tkinter as tk
import tkinter.font as tkfont
from urllib.parse import urlparse

import keyboard
import PIL.Image
import PIL.ImageDraw
import PIL.ImageGrab
import PIL.ImageTk
import pyperclip
import requests

try:
    import pystray
except Exception:
    pystray = None

try:
    import psutil
except Exception:
    psutil = None

try:
    import winreg
except Exception:
    winreg = None

try:
    import webview
except Exception:
    webview = None

APP_NAME = "EyesAndEars"
APP_VERSION = "2.2.0"
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s [%(name)s] %(message)s")
logger = logging.getLogger(APP_NAME)

CONFIG_FILE_NAME = "config.json"
HARDCODED_SERVER_URL = os.environ.get(
    "EAE_SERVER_URL",
    "https://eyesandears-platform-vercel.vercel.app",
).strip()
DEFAULT_SERVER_URL = HARDCODED_SERVER_URL.strip().rstrip("/")
DEFAULT_WEBSITE_URL = os.environ.get("EAE_WEBSITE_URL", DEFAULT_SERVER_URL).strip().rstrip("/") or DEFAULT_SERVER_URL
FREE_MODEL_NAME = "gemini-2.5-flash"
DEFAULT_MODEL_NAME = FREE_MODEL_NAME
DEFAULT_WINGET_PACKAGE_ID = os.environ.get("EYESANDEARS_WINGET_ID", "").strip()
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
HTTP_SESSION = requests.Session()
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
CRYPTPROTECT_UI_FORBIDDEN = 0x01
FAST_UPLOAD_JPEG_QUALITY = 82
ANSWER_PREVIEW_RETENTION_SECONDS = 5.0
TRUSTED_TIME_TIMEOUT_SECONDS = 8
PRO_AUTH_FAILURE_WINDOW_SECONDS = 30 * 60
PRO_AUTH_LOCKOUT_BASE_SECONDS = 30
PRO_AUTH_FIRST_LOCKOUT_FAILURE = 3
PRO_AUTH_HARD_LOCKOUT_FAILURE = 9
PRO_AUTH_HARD_LOCKOUT_SECONDS = 24 * 60 * 60
PRO_AUTH_HIDDEN_DIR_NAME = ".runtime"
PRO_AUTH_HIDDEN_FILE_NAME = "session.idx"
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x2000
WM_NCLBUTTONDOWN = 0x00A1
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
PROGRESS_UI_MIN_INTERVAL = 0.035
PROGRESS_UI_MIN_STEP = 2
PROCESS_SNAPSHOT_CACHE_SECONDS = 4.0

auth_mode = "license"
server_url = DEFAULT_SERVER_URL
license_code = ""
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
license_hint = ""
heartbeat_interval_seconds = 20
heartbeat_timeout_seconds = 90
startup_preflight_license_auth = None

local_model = None
local_chat_session = None
api_backend_name = "none"

heartbeat_stop_event = Event()
heartbeat_thread = None
update_state_lock = Lock()
update_check_started = False
update_in_progress = False

tray_icon = None
indicator = None
privacy_guard_thread = None
privacy_guard_stop_event = Event()
privacy_forced_hidden = False
indicator_manual_hidden = False
indicator_capture_protected = False
startup_progress_window = None
settings_window_lock = Lock()
settings_window_open = False
config_file_lock = Lock()
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
HIDE_INDICATOR_FROM_CAPTURE = os.environ.get("EAE_HIDE_INDICATOR_FROM_CAPTURE", "").strip().lower() not in {"0", "false", "no", "off"}
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
INDICATOR_READY_BURST_SECONDS = 0.54
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
        "startup.connecting_pro": "Connecting to Pro mode",
        "startup.initializing_model": "Initializing AI backend",
        "startup.starting_indicator": "Starting indicator",
        "startup.ready": "Ready",
        "startup.detail.launching": "Loading interface",
        "startup.detail.restoring": "Restoring saved settings and secure secrets",
        "startup.detail.opening_setup": "Waiting for your setup choices",
        "startup.detail.checking_auth": "Validating the selected access mode",
        "startup.detail.connecting_pro": "Connecting your subscription session",
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
        "auth.mode.pro": "Pro mode",
        "auth.mode.pro.help": "Use your secret key",
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
        "auth.section.pro": "Connect with your secret key",
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
        "auth.pro.label": "Secret key",
        "auth.pro.placeholder": "Enter your secret key",
        "auth.pro.note": "The server endpoint stays managed inside the app.",
        "auth.pro.model": "Preferred Pro model",
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
        "auth.validation.pro.empty": "Enter your secret key.",
        "auth.status.free": "Free mode checks your API key locally on this device.",
        "auth.status.pro": "Pro mode signs you in with your subscription session.",
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
        "status.mode.pro": "Pro mode",
        "status.status": "Status",
        "status.server": "Server",
        "status.user": "User",
        "status.code": "Code",
        "status.backend": "Backend",
        "status.model": "Model",
        "status.api_key": "API key",
        "status.pro_model": "Preferred Pro model",
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
        "error.auth_failed": "Authentication request failed ({status_code}). {detail}",
        "error.auth_denied": "Authentication denied.",
        "error.pro_lockout_wait": "Too many incorrect secret key attempts. Try again in {seconds} seconds.",
        "error.pro_lockout_locked": "Too many incorrect secret key attempts. This device is locked for {seconds} seconds.",
        "error.pro_time_unavailable": "Couldn't verify trusted online time. Check your connection and try again.",
        "error.api_empty": "API key is empty.",
        "error.no_sdk": "Could not initialize API mode.\n{detail}",
        "error.api_credits": "Your API key ran out of credits.\nAdd credits or enter a new key.",
        "error.api_invalid": "Your API key is invalid or expired.\nEnter a valid Gemini API key.",
        "error.api_init": "Could not initialize API mode.\n{detail}",
        "error.api_required": "API mode needs a valid Gemini API key.",
        "error.api_select_mode": "Select Free mode and enter a valid Gemini API key.",
        "error.session_inactive": "Session inactive. Restart the app and sign in again.",
        "error.license_retry": "Retry Pro mode sign-in?",
        "status.code_active": "Pro mode active",
        "status.code_disconnected": "Pro mode disconnected: {detail}",
        "status.code_session_lost": "Pro mode session lost",
        "status.code_network_error": "Pro mode disconnected",
        "status.code_expired": "Pro mode session expired. Restart the app.",
        "status.code_inactive": "Pro mode inactive - sign-in required",
        "status.api_active": "Free mode active ({backend})",
        "status.api_invalid": "Free mode inactive - invalid API key",
        "status.api_credits": "Free mode inactive - credits exhausted",
        "status.api_required": "Free mode inactive - API key required",
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
        "startup.connecting_pro": "Connexion au mode Pro",
        "startup.initializing_model": "Initialisation du moteur IA",
        "startup.starting_indicator": "Demarrage de l'indicateur",
        "startup.ready": "Pret",
        "startup.detail.launching": "Chargement de l'interface",
        "startup.detail.restoring": "Restauration des reglages et secrets securises",
        "startup.detail.opening_setup": "En attente de vos choix de configuration",
        "startup.detail.checking_auth": "Validation du mode d'acces selectionne",
        "startup.detail.connecting_pro": "Connexion de votre session d'abonnement",
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
        "auth.mode.pro": "Mode Pro",
        "auth.mode.pro.help": "Utiliser votre cle secrete",
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
        "auth.section.pro": "Connexion avec votre cle secrete",
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
        "auth.pro.label": "Cle secrete",
        "auth.pro.placeholder": "Entrez votre cle secrete",
        "auth.pro.note": "Le point d'acces serveur reste gere dans l'application.",
        "auth.pro.model": "Modele Pro prefere",
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
        "auth.validation.pro.empty": "Entrez votre cle secrete.",
        "auth.status.free": "Le mode gratuit verifie votre cle API localement sur cet appareil.",
        "auth.status.pro": "Le mode Pro ouvre votre session d'abonnement.",
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
        "status.mode.pro": "Mode Pro",
        "status.status": "Statut",
        "status.server": "Serveur",
        "status.user": "Utilisateur",
        "status.code": "Code",
        "status.backend": "Moteur",
        "status.model": "Modele",
        "status.api_key": "Cle API",
        "status.pro_model": "Modele Pro prefere",
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
        "error.auth_failed": "La demande d'authentification a echoue ({status_code}). {detail}",
        "error.auth_denied": "Authentification refusee.",
        "error.pro_lockout_wait": "Trop de tentatives incorrectes pour la cle secrete. Reessayez dans {seconds} secondes.",
        "error.pro_lockout_locked": "Trop de tentatives incorrectes pour la cle secrete. Cet appareil est bloque pour {seconds} secondes.",
        "error.pro_time_unavailable": "Impossible de verifier l'heure en ligne. Verifiez votre connexion puis reessayez.",
        "error.api_empty": "La cle API est vide.",
        "error.no_sdk": "Impossible d'initialiser le mode API.\n{detail}",
        "error.api_credits": "Votre cle API n'a plus de credits.\nAjoutez des credits ou entrez une nouvelle cle.",
        "error.api_invalid": "Votre cle API est invalide ou expiree.\nEntrez une cle Gemini valide.",
        "error.api_init": "Impossible d'initialiser le mode API.\n{detail}",
        "error.api_required": "Le mode gratuit a besoin d'une cle API Gemini valide.",
        "error.api_select_mode": "Selectionnez le mode gratuit et entrez une cle API Gemini valide.",
        "error.session_inactive": "Session inactive. Redemarrez l'application et reconnectez-vous.",
        "error.license_retry": "Reessayer la connexion au mode Pro ?",
        "status.code_active": "Mode Pro actif",
        "status.code_disconnected": "Mode Pro deconnecte : {detail}",
        "status.code_session_lost": "Session Pro perdue",
        "status.code_network_error": "Mode Pro deconnecte",
        "status.code_expired": "La session Pro a expire. Redemarrez l'application.",
        "status.code_inactive": "Mode Pro inactif - connexion requise",
        "status.api_active": "Mode gratuit actif ({backend})",
        "status.api_invalid": "Mode gratuit inactif - cle API invalide",
        "status.api_credits": "Mode gratuit inactif - credits epuises",
        "status.api_required": "Mode gratuit inactif - cle API requise",
        "status.stopped": "Arrete",
        "status.not_authenticated": "Non authentifie",
        "indicator.cooldown": "Saisie terminee. Les commandes reviennent dans {seconds}s.",
    },
}

DEFAULT_PRO_MODEL_OPTIONS = [
    {
        "id": "pro-auto",
        "label": "Auto",
        "description": "Use the server default Pro model.",
    },
    {
        "id": "gemini-3-flash-preview",
        "label": "Gemini 3 Flash Preview",
        "description": "Current fastest Gemini 3 preview for Pro users.",
    },
    {
        "id": "gemini-3.1-flash-lite-preview",
        "label": "Gemini 3.1 Flash-Lite Preview",
        "description": "Lowest-latency Gemini 3.1 option for lightweight Pro work.",
    },
    {
        "id": "gemini-3.1-pro-preview",
        "label": "Gemini 3.1 Pro Preview",
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
        "label": "Gemini 2.5 Pro",
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
    if os.name != "nt" or winreg is None:
        return False
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
        ) as key:
            apps_use_light_theme, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
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


apply_ui_theme_preference(os.environ.get("EAE_THEME", ui_theme_preference))


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


PRO_MODEL_OPTIONS = load_pro_model_catalog()


def normalize_pro_model(value):
    candidate = str(value or "").strip()
    for item in PRO_MODEL_OPTIONS:
        if candidate == item["id"]:
            return candidate
    return str(PRO_MODEL_OPTIONS[0]["id"])


selected_pro_model_key = normalize_pro_model(selected_pro_model_key)


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
    remaining = [key for key in ALLOWED_HOTKEY_BINDINGS if key not in defaults.values()]
    for action in HOTKEY_ACTION_ORDER:
        candidate = str(source.get(action, "") or "").strip().lower()
        if candidate in ALLOWED_HOTKEY_BINDINGS and candidate not in used:
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


def build_hotkey_summary(language=None):
    parts = []
    for action in HOTKEY_ACTION_ORDER:
        parts.append(f"{hotkey_binding_label(command_hotkeys.get(action, ''))} {hotkey_action_label(action, language=language)}")
    return "  |  ".join(part for part in parts if part)


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


def soft_validate_license_code(value):
    if not str(value or "").strip():
        return "auth.validation.pro.empty"
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


def clear_startup_preflight_license_auth():
    global startup_preflight_license_auth
    startup_preflight_license_auth = None


def cache_startup_preflight_license_auth(license_value, device_value, data):
    global startup_preflight_license_auth
    if not isinstance(data, dict):
        startup_preflight_license_auth = None
        return
    startup_preflight_license_auth = {
        "license_code": str(license_value or "").strip(),
        "device_id": str(device_value or "").strip(),
        "data": dict(data),
    }


def consume_startup_preflight_license_auth(license_value, device_value):
    global startup_preflight_license_auth
    cached = startup_preflight_license_auth if isinstance(startup_preflight_license_auth, dict) else None
    if not cached:
        return None
    if (
        str(cached.get("license_code", "")).strip() != str(license_value or "").strip()
        or str(cached.get("device_id", "")).strip() != str(device_value or "").strip()
    ):
        return None
    startup_preflight_license_auth = None
    data = cached.get("data")
    return dict(data) if isinstance(data, dict) else None


def perform_license_auth_request(license_value, device_value):
    payload = {
        "license_code": str(license_value or "").strip(),
        "device_id": str(device_value or "").strip(),
        "device_name": os.environ.get("COMPUTERNAME", os.environ.get("HOSTNAME", "Windows")),
        "app_version": APP_VERSION,
    }
    try:
        response = request_json("POST", "/api/v1/client/authenticate", json_payload=payload, timeout=20)
    except Exception as exc:
        logger.warning("License authentication request failed.", exc_info=True)
        return False, tr("error.connect_server", detail=exc), None, "network_error"

    data = decode_json_response(response, "License authentication")
    if data is None:
        return False, tr("error.server_non_json", status_code=response.status_code), None, "server_non_json"
    if not response.ok:
        message = data.get("detail") if isinstance(data, dict) else ""
        logger.warning("License authentication failed with status %s.", response.status_code)
        return False, tr("error.auth_failed", status_code=response.status_code, detail=message), None, "http_error"
    if not data.get("success"):
        denial_message = str(data.get("message", tr("error.auth_denied")) or "").strip()
        logger.info("License authentication denied by server.")
        if license_message_is_lockout(denial_message):
            return False, denial_message, None, "lockout"
        if license_message_is_invalid_secret(denial_message):
            return False, denial_message, None, "invalid_secret"
        return False, denial_message or tr("error.auth_denied"), None, "denied"
    return True, tr("startup.ready"), data, "ok"


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
PRO_AUTH_RUNTIME_DIR = APP_DATA_DIR / PRO_AUTH_HIDDEN_DIR_NAME
PRO_AUTH_LOCK_FILE = PRO_AUTH_RUNTIME_DIR / PRO_AUTH_HIDDEN_FILE_NAME

if os.name == "nt":
    HRESULT = getattr(wintypes, "HRESULT", ctypes.c_long)
    WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
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
    _user32.ReleaseCapture.argtypes = []
    _user32.ReleaseCapture.restype = wintypes.BOOL
    _user32.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    _user32.SendMessageW.restype = wintypes.LPARAM
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


def apply_tk_scaling(window):
    if window is None:
        return
    try:
        dpi = float(window.winfo_fpixels("1i"))
        if dpi <= 0:
            return
        scale = max(1.0, dpi / 72.0)
        window.tk.call("tk", "scaling", scale)
    except Exception:
        pass


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
    if os.name != "nt" or window is None:
        return False
    try:
        if not window.winfo_exists():
            return False
        window.update_idletasks()
        return set_window_capture_excluded(window.winfo_id(), enabled=enabled)
    except Exception:
        logger.debug("Window capture privacy application failed.", exc_info=True)
        return False


def is_capture_privacy_active():
    return bool(capture_privacy_enabled)


def schedule_window_privacy_refresh(window, refresh_ms=1800):
    if os.name != "nt" or window is None:
        return
    if getattr(window, "_eae_privacy_refresh_enabled", False):
        return
    window._eae_privacy_refresh_enabled = True
    window._eae_privacy_refresh_after_id = None

    def _cancel(_event=None):
        after_id = getattr(window, "_eae_privacy_refresh_after_id", None)
        if after_id:
            try:
                window.after_cancel(after_id)
            except Exception:
                pass
        window._eae_privacy_refresh_after_id = None

    def _tick():
        try:
            if not window.winfo_exists():
                return
            apply_capture_privacy_to_window(window, enabled=is_capture_privacy_active())
            window._eae_privacy_refresh_after_id = window.after(refresh_ms, _tick)
        except Exception:
            pass

    try:
        window.bind("<Destroy>", _cancel, add="+")
    except Exception:
        pass
    try:
        window._eae_privacy_refresh_after_id = window.after(80, _tick)
    except Exception:
        pass


def configure_private_window(window, *, dark=False, translucent=False, refresh_ms=1800):
    apply_win11_window_style(window, dark=dark, translucent=translucent)
    apply_capture_privacy_to_window(window, enabled=is_capture_privacy_active())
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


def apply_window_ellipse_region(window):
    if os.name != "nt" or window is None:
        return False
    try:
        if not window.winfo_exists():
            return False
        window.update_idletasks()
        width = int(max(1, window.winfo_width()))
        height = int(max(1, window.winfo_height()))
        region = _gdi32.CreateEllipticRgn(0, 0, width + 1, height + 1)
        if not region:
            return False
        hwnd = wintypes.HWND(window.winfo_id())
        applied = bool(_user32.SetWindowRgn(hwnd, region, True))
        if not applied:
            _gdi32.DeleteObject(region)
        return applied
    except Exception:
        return False


def draw_canvas_ellipse(canvas, x1, y1, x2, y2, **kwargs):
    fill = kwargs.get("fill", "")
    outline = kwargs.get("outline", "")
    line_width = int(max(1, kwargs.get("width", 1)))
    antialias = int(max(1, kwargs.get("antialias", 1)))
    x1 = int(x1)
    y1 = int(y1)
    x2 = int(x2)
    y2 = int(y2)
    if x2 <= x1 or y2 <= y1:
        return []

    if antialias > 1:
        width_px = int(max(1, x2 - x1 + 1))
        height_px = int(max(1, y2 - y1 + 1))
        aa_width = width_px * antialias
        aa_height = height_px * antialias
        aa_line = max(1, line_width * antialias)
        cache = getattr(canvas, "_eae_ellipse_cache", None)
        if cache is None:
            cache = {}
            canvas._eae_ellipse_cache = cache
        cache_key = (width_px, height_px, fill, outline, line_width, antialias)
        image_ref = cache.get(cache_key)
        if image_ref is None:
            img = PIL.Image.new("RGBA", (aa_width, aa_height), (0, 0, 0, 0))
            drawer = PIL.ImageDraw.Draw(img)
            shape = (0, 0, aa_width - 1, aa_height - 1)
            if fill and outline:
                drawer.ellipse(shape, fill=fill, outline=outline, width=aa_line)
            elif fill:
                drawer.ellipse(shape, fill=fill)
            elif outline:
                drawer.ellipse(shape, outline=outline, width=aa_line)
            resampling = getattr(getattr(PIL.Image, "Resampling", PIL.Image), "BILINEAR", PIL.Image.BILINEAR)
            img = img.resize((width_px, height_px), resampling)
            image_ref = PIL.ImageTk.PhotoImage(img, master=canvas)
            cache[cache_key] = image_ref
            if len(cache) > 32:
                try:
                    cache.pop(next(iter(cache)))
                except Exception:
                    pass
        refs = getattr(canvas, "_eae_image_refs", None)
        if refs is None:
            refs = []
            canvas._eae_image_refs = refs
        refs.append(image_ref)
        return [canvas.create_image(x1, y1, image=image_ref, anchor="nw")]

    return [
        canvas.create_oval(
            x1,
            y1,
            x2,
            y2,
            fill=fill,
            outline=outline,
            width=line_width,
        )
    ]


def draw_rounded_canvas_rect(canvas, x1, y1, x2, y2, radius, **kwargs):
    fill = kwargs.get("fill", "")
    outline = kwargs.get("outline", "")
    line_width = int(max(1, kwargs.get("width", 1)))
    antialias = int(max(1, kwargs.get("antialias", 1)))
    x1 = int(x1)
    y1 = int(y1)
    x2 = int(x2)
    y2 = int(y2)
    if x2 <= x1 or y2 <= y1:
        return []

    radius = int(max(0, min(radius, (x2 - x1) // 2, (y2 - y1) // 2)))
    if antialias > 1:
        width_px = int(max(1, x2 - x1 + 1))
        height_px = int(max(1, y2 - y1 + 1))
        aa_width = width_px * antialias
        aa_height = height_px * antialias
        aa_radius = radius * antialias
        aa_line = max(1, line_width * antialias)
        cache = getattr(canvas, "_eae_rr_cache", None)
        if cache is None:
            cache = {}
            canvas._eae_rr_cache = cache
        cache_key = (width_px, height_px, radius, fill, outline, line_width, antialias)
        image_ref = cache.get(cache_key)
        if image_ref is None:
            img = PIL.Image.new("RGBA", (aa_width, aa_height), (0, 0, 0, 0))
            drawer = PIL.ImageDraw.Draw(img)
            shape = (0, 0, aa_width - 1, aa_height - 1)
            if fill and outline:
                drawer.rounded_rectangle(shape, radius=aa_radius, fill=fill, outline=outline, width=aa_line)
            elif fill:
                drawer.rounded_rectangle(shape, radius=aa_radius, fill=fill)
            elif outline:
                drawer.rounded_rectangle(shape, radius=aa_radius, outline=outline, width=aa_line)
            resampling = getattr(getattr(PIL.Image, "Resampling", PIL.Image), "BILINEAR", PIL.Image.BILINEAR)
            img = img.resize((width_px, height_px), resampling)
            image_ref = PIL.ImageTk.PhotoImage(img, master=canvas)
            cache[cache_key] = image_ref
            if len(cache) > 32:
                try:
                    cache.pop(next(iter(cache)))
                except Exception:
                    pass
        refs = getattr(canvas, "_eae_image_refs", None)
        if refs is None:
            refs = []
            canvas._eae_image_refs = refs
        refs.append(image_ref)
        return [canvas.create_image(x1, y1, image=image_ref, anchor="nw")]

    def _draw_fill(rx1, ry1, rx2, ry2, rr, color):
        if rr <= 0:
            return [canvas.create_rectangle(rx1, ry1, rx2, ry2, fill=color, outline="")]
        items = []
        items.append(canvas.create_rectangle(rx1 + rr, ry1, rx2 - rr, ry2, fill=color, outline=""))
        items.append(canvas.create_rectangle(rx1, ry1 + rr, rx2, ry2 - rr, fill=color, outline=""))
        items.append(canvas.create_arc(rx1, ry1, rx1 + rr * 2, ry1 + rr * 2, start=90, extent=90, style=tk.PIESLICE, fill=color, outline=""))
        items.append(canvas.create_arc(rx2 - rr * 2, ry1, rx2, ry1 + rr * 2, start=0, extent=90, style=tk.PIESLICE, fill=color, outline=""))
        items.append(canvas.create_arc(rx1, ry2 - rr * 2, rx1 + rr * 2, ry2, start=180, extent=90, style=tk.PIESLICE, fill=color, outline=""))
        items.append(canvas.create_arc(rx2 - rr * 2, ry2 - rr * 2, rx2, ry2, start=270, extent=90, style=tk.PIESLICE, fill=color, outline=""))
        return items

    items = []
    if fill:
        items.extend(_draw_fill(x1, y1, x2, y2, radius, fill))
    if outline:
        if radius <= 0:
            items.append(canvas.create_rectangle(x1, y1, x2, y2, outline=outline, width=line_width))
        else:
            items.append(canvas.create_arc(x1, y1, x1 + radius * 2, y1 + radius * 2, start=90, extent=90, style=tk.ARC, outline=outline, width=line_width))
            items.append(canvas.create_arc(x2 - radius * 2, y1, x2, y1 + radius * 2, start=0, extent=90, style=tk.ARC, outline=outline, width=line_width))
            items.append(canvas.create_arc(x1, y2 - radius * 2, x1 + radius * 2, y2, start=180, extent=90, style=tk.ARC, outline=outline, width=line_width))
            items.append(canvas.create_arc(x2 - radius * 2, y2 - radius * 2, x2, y2, start=270, extent=90, style=tk.ARC, outline=outline, width=line_width))
            items.append(canvas.create_line(x1 + radius, y1, x2 - radius, y1, fill=outline, width=line_width))
            items.append(canvas.create_line(x1 + radius, y2, x2 - radius, y2, fill=outline, width=line_width))
            items.append(canvas.create_line(x1, y1 + radius, x1, y2 - radius, fill=outline, width=line_width))
            items.append(canvas.create_line(x2, y1 + radius, x2, y2 - radius, fill=outline, width=line_width))
    return items


def apply_win11_window_style(window, dark=False, translucent=False):
    if os.name != "nt":
        return
    try:
        window.update_idletasks()
        hwnd = wintypes.HWND(window.winfo_id())
        rounded = ctypes.c_int(DWMWCP_ROUND)
        backdrop = ctypes.c_int(DWMSBT_TRANSIENTWINDOW if translucent else DWMSBT_MAINWINDOW)
        mica_enabled = ctypes.c_int(1 if translucent else 0)
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
            DWMWA_MICA_EFFECT,
            ctypes.byref(mica_enabled),
            ctypes.sizeof(mica_enabled),
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
    with config_file_lock:
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
    payload = json.dumps(record, indent=2)
    temp_path = APP_DATA_DIR / f"{CONFIG_FILE_NAME}.{secrets.token_hex(8)}.tmp"
    with config_file_lock:
        temp_path.write_text(payload, encoding="utf-8")
        try:
            os.replace(temp_path, CONFIG_FILE)
        finally:
            try:
                if temp_path.exists():
                    temp_path.unlink()
            except Exception:
                pass


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
    PRO_AUTH_RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    set_hidden_path_flag(PRO_AUTH_RUNTIME_DIR)
    return PRO_AUTH_RUNTIME_DIR


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
    with pro_auth_guard_lock:
        if not PRO_AUTH_LOCK_FILE.exists():
            return normalize_pro_auth_guard_state()
        try:
            raw_payload = PRO_AUTH_LOCK_FILE.read_text(encoding="utf-8").strip()
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
    ensure_pro_auth_runtime_dir()
    with pro_auth_guard_lock:
        if should_clear:
            try:
                if PRO_AUTH_LOCK_FILE.exists():
                    PRO_AUTH_LOCK_FILE.unlink()
            except Exception:
                pass
            return
        serialized = json.dumps(state, separators=(",", ":"), sort_keys=True)
        if os.name == "nt":
            stored_payload = encrypt_with_dpapi(serialized)
            if not stored_payload:
                raise RuntimeError("Could not protect Pro auth guard state with DPAPI.")
        else:
            stored_payload = base64.b64encode(serialized.encode("utf-8")).decode("ascii")
        temp_path = PRO_AUTH_RUNTIME_DIR / f"{PRO_AUTH_HIDDEN_FILE_NAME}.{secrets.token_hex(6)}.tmp"
        temp_path.write_text(stored_payload, encoding="utf-8")
        try:
            os.replace(temp_path, PRO_AUTH_LOCK_FILE)
            set_hidden_path_flag(PRO_AUTH_LOCK_FILE)
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
    headers = {
        "Accept": "application/json",
        "User-Agent": f"{APP_NAME}/{APP_VERSION}",
    }
    failures = []
    for url in TRUSTED_TIME_URLS:
        try:
            response = HTTP_SESSION.get(url, headers=headers, timeout=TRUSTED_TIME_TIMEOUT_SECONDS, allow_redirects=True)
        except requests.RequestException as exc:
            failures.append(f"{url} ({exc})")
            continue
        if not response.ok:
            failures.append(f"{url} (status {response.status_code})")
            continue
        try:
            payload = response.json()
        except Exception:
            failures.append(f"{url} (non-JSON)")
            continue
        trusted_epoch = extract_trusted_epoch_from_payload(payload)
        if trusted_epoch > 0:
            return trusted_epoch, url
        failures.append(f"{url} (missing time value)")
    if failures:
        logger.warning("Trusted online time lookup failed: %s", "; ".join(failures[:3]))
    raise RuntimeError(tr("error.pro_time_unavailable"))


def license_message_is_lockout(message):
    text = str(message or "").strip().lower()
    return "too many incorrect secret key attempts" in text


def license_message_is_invalid_secret(message):
    text = str(message or "").strip().lower()
    return "incorrect secret key" in text


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
    max_width = max(360, screen_width - 24)
    max_height = max(280, screen_height - 56)
    width = int(max(320, min(int(width), max_width)))
    height = int(max(240, min(int(height), max_height)))
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
    ensure_ui_crisp_mode()
    root = tk.Toplevel(parent) if parent else tk.Tk()
    apply_tk_scaling(root)
    root.title(title)
    root.configure(bg=UI_BG)
    center_window(root, width, height)
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    min_width = min(max(420, min(width, 960)), max(320, screen_width - 24))
    min_height = min(max(280, min(height, 860)), max(240, screen_height - 56))
    root.minsize(min_width, min_height)
    root.resizable(True, True)
    configure_private_window(root, dark=system_dark_theme_enabled, translucent=True)
    try:
        root.attributes("-alpha", 0.985)
    except Exception:
        pass
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


def apply_widget_corner_region(widget, radius=12):
    if os.name != "nt" or widget is None:
        return False
    try:
        if not widget.winfo_exists():
            return False
        widget.update_idletasks()
        width = int(max(1, widget.winfo_width()))
        height = int(max(1, widget.winfo_height()))
        if width <= 2 or height <= 2:
            return False
        radius = int(max(2, min(radius, width // 2, height // 2)))
        region = _gdi32.CreateRoundRectRgn(0, 0, width + 1, height + 1, radius * 2, radius * 2)
        if not region:
            return False
        hwnd = wintypes.HWND(widget.winfo_id())
        applied = bool(_user32.SetWindowRgn(hwnd, region, True))
        if not applied:
            _gdi32.DeleteObject(region)
        return applied
    except Exception:
        return False


def schedule_widget_rounding(widget, radius=12):
    if os.name != "nt" or widget is None:
        return
    widget._eae_round_radius = int(max(2, radius))

    def _apply(_event=None):
        try:
            if widget.winfo_exists():
                apply_widget_corner_region(widget, int(getattr(widget, "_eae_round_radius", radius)))
        except Exception:
            pass

    if not getattr(widget, "_eae_round_bound", False):
        try:
            widget.bind("<Configure>", _apply, add="+")
            widget._eae_round_bound = True
        except Exception:
            pass
    try:
        widget.after(16, _apply)
    except Exception:
        pass


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
        schedule_widget_rounding(widget, radius=14)
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
        schedule_widget_rounding(widget, radius=14)
        return
    widget.configure(
        bg=UI_GHOST_BG,
        fg=UI_TEXT,
        activebackground=UI_GHOST_ACTIVE,
        activeforeground=UI_TEXT,
        highlightbackground=UI_BORDER,
        highlightcolor=UI_BORDER,
    )
    schedule_widget_rounding(widget, radius=14)


class StartupProgressWindow:
    STAGE_ORDER = [
        "startup.launching",
        "startup.restoring",
        "startup.opening_setup",
        "startup.checking_auth",
        "startup.connecting_pro",
        "startup.initializing_model",
        "startup.starting_indicator",
        "startup.ready",
    ]

    def __init__(self):
        ensure_ui_crisp_mode()
        self.root = tk.Tk()
        apply_tk_scaling(self.root)
        self.root.overrideredirect(True)
        self.root.configure(bg=UI_BG)
        self._base_window_width = 540
        self._base_window_height = 384
        self._window_fit_active = False
        center_window(self.root, self._base_window_width, self._base_window_height)
        self.root.resizable(False, False)
        try:
            self.root.attributes("-topmost", True)
        except Exception:
            pass
        self.root.protocol("WM_DELETE_WINDOW", lambda: None)
        self.root.bind("<Escape>", lambda _event: "break")
        self.root.bind("<Configure>", self._on_configure, add="+")
        self.stage_key = "startup.launching"
        self.hidden = False
        self.animation_after_id = None
        self._eye_photo = None
        self._base_title_font_size = 22
        self._base_stage_font_size = 13

        configure_private_window(self.root, dark=system_dark_theme_enabled, translucent=True)
        try:
            self.root.attributes("-alpha", 0.985)
        except Exception:
            pass

        shell = tk.Frame(self.root, bg=UI_BG, bd=0)
        shell.pack(fill="both", expand=True, padx=16, pady=16)

        card = tk.Frame(
            shell,
            bg=UI_CARD_BG,
            highlightbackground=UI_BORDER,
            highlightthickness=1,
            bd=0,
        )
        card.pack(fill="both", expand=True)

        self.inner = tk.Frame(card, bg=UI_CARD_BG, bd=0)
        self.inner.pack(fill="both", expand=True, padx=30, pady=26)

        self.eye_canvas = tk.Canvas(
            self.inner,
            width=220,
            height=116,
            highlightthickness=0,
            bd=0,
            bg=UI_CARD_BG,
        )
        self.eye_canvas.pack(pady=(2, 14))

        self.title_font = tkfont.Font(root=self.root, family=UI_FONT, size=self._base_title_font_size, weight="bold")
        self.stage_font = tkfont.Font(root=self.root, family=UI_FONT, size=self._base_stage_font_size, weight="bold")

        self.title_label = tk.Label(
            self.inner,
            text="",
            bg=UI_CARD_BG,
            fg=UI_TEXT,
            font=self.title_font,
            justify="center",
            anchor="center",
        )
        self.title_label.pack(fill="x")

        self.stage_label = tk.Label(
            self.inner,
            text="",
            bg=UI_CARD_BG,
            fg=UI_TEXT,
            font=self.stage_font,
            justify="center",
            anchor="center",
        )
        self.stage_label.pack(fill="x", pady=(10, 0))

        self.detail_label = tk.Label(
            self.inner,
            text="",
            bg=UI_CARD_BG,
            fg=UI_MUTED,
            font=(UI_FONT, 10),
            justify="center",
            wraplength=320,
            anchor="center",
        )
        self.detail_label.pack(fill="x", pady=(8, 0))

        self.root.update_idletasks()
        self._refresh_layout()
        self._apply_window_rounding()
        self._animate_eye()
        self.set_stage("startup.launching")

    def _on_configure(self, _event=None):
        self._apply_window_rounding()
        self._refresh_layout()

    def _apply_window_rounding(self):
        try:
            apply_window_corner_region(self.root, 26)
        except Exception:
            pass

    def _fit_window_to_content(self):
        if self._window_fit_active:
            return
        self._window_fit_active = True
        try:
            fit_window_to_content(
                self.root,
                min_width=self._base_window_width,
                min_height=self._base_window_height,
                max_width=max(360, int(self.root.winfo_screenwidth()) - 24),
                max_height=max(280, int(self.root.winfo_screenheight()) - 56),
            )
        except Exception:
            pass
        finally:
            self._window_fit_active = False

    def _refresh_layout(self):
        try:
            self.root.update_idletasks()
            available_width = max(260, int(self.inner.winfo_width()) - 8)
        except Exception:
            available_width = 420
        title_wrap = max(280, available_width)
        stage_wrap = max(240, available_width - 24)
        detail_wrap = max(220, available_width - 36)
        try:
            self.title_label.configure(wraplength=title_wrap)
            self.stage_label.configure(wraplength=stage_wrap)
            self.detail_label.configure(wraplength=detail_wrap)
        except Exception:
            pass

        title_text = str(self.title_label.cget("text") or "")
        size = self._base_title_font_size
        while title_text and size > 16:
            try:
                self.title_font.configure(size=size)
                measured = int(self.title_font.measure(title_text))
            except Exception:
                break
            if measured <= title_wrap:
                break
            size -= 1
        try:
            self.title_font.configure(size=size)
        except Exception:
            pass

        stage_text = str(self.stage_label.cget("text") or "")
        stage_size = self._base_stage_font_size
        while stage_text and stage_size > 11:
            try:
                self.stage_font.configure(size=stage_size)
                measured = int(self.stage_font.measure(stage_text))
            except Exception:
                break
            if measured <= stage_wrap:
                break
            stage_size -= 1
        try:
            self.stage_font.configure(size=stage_size)
        except Exception:
            pass

    def _eye_open_ratio(self):
        phase = time.monotonic() % 2.6
        if phase < 1.9:
            return 1.0
        if phase < 2.02:
            return max(0.08, 1.0 - ((phase - 1.9) / 0.12) * 0.92)
        if phase < 2.14:
            return min(1.0, 0.08 + ((phase - 2.02) / 0.12) * 0.92)
        return 1.0

    def _draw_eye(self):
        canvas = self.eye_canvas
        canvas.delete("all")
        width = int(canvas.cget("width"))
        height = int(canvas.cget("height"))
        center_x = width // 2
        center_y = int(height * 0.48)
        open_ratio = self._eye_open_ratio()
        antialias = 4
        aa_width = width * antialias
        aa_height = height * antialias
        image = PIL.Image.new("RGBA", (aa_width, aa_height), (0, 0, 0, 0))
        draw = PIL.ImageDraw.Draw(image)

        def scale(point):
            return (int(point[0] * antialias), int(point[1] * antialias))

        def sample_quadratic(start, control, end, steps=28):
            points = []
            for index in range(steps + 1):
                t = float(index) / float(steps)
                inv = 1.0 - t
                x = (inv * inv * start[0]) + (2.0 * inv * t * control[0]) + (t * t * end[0])
                y = (inv * inv * start[1]) + (2.0 * inv * t * control[1]) + (t * t * end[1])
                points.append(scale((x, y)))
            return points

        def sample_cubic(start, control_a, control_b, end, steps=64):
            points = []
            for index in range(steps + 1):
                t = float(index) / float(steps)
                inv = 1.0 - t
                x = (
                    (inv ** 3) * start[0]
                    + (3.0 * (inv ** 2) * t * control_a[0])
                    + (3.0 * inv * (t ** 2) * control_b[0])
                    + ((t ** 3) * end[0])
                )
                y = (
                    (inv ** 3) * start[1]
                    + (3.0 * (inv ** 2) * t * control_a[1])
                    + (3.0 * inv * (t ** 2) * control_b[1])
                    + ((t ** 3) * end[1])
                )
                points.append(scale((x, y)))
            return points

        def build_eye_curves():
            half_width = float(max(64, (width // 2) - 36))
            lid_height = float(max(7.0, 18.0 * open_ratio))
            lid_sweep = 5.8 + (open_ratio * 1.8)
            left_corner = (center_x - half_width, float(center_y))
            right_corner = (center_x + half_width, float(center_y))
            top_curve = sample_cubic(
                left_corner,
                (center_x - (half_width * 0.58), center_y - lid_height - lid_sweep),
                (center_x + (half_width * 0.58), center_y - lid_height - lid_sweep),
                right_corner,
                steps=72,
            )
            mirror_y = int(center_y * antialias)
            bottom_curve = [(x, (2 * mirror_y) - y) for x, y in top_curve]
            return top_curve, bottom_curve

        outline = (241, 247, 255, 242)
        outline_glow = (96, 170, 255, 28)
        sclera_fill = (247, 250, 255, 20)
        top_curve, bottom_curve = build_eye_curves()
        if open_ratio <= 0.16:
            lid_line = sample_quadratic((34, center_y), (center_x, center_y - 1.6), (width - 34, center_y), steps=36)
            draw.line(lid_line, fill=outline_glow, width=22)
            draw.line(lid_line, fill=outline, width=10)
        else:
            eye_polygon = top_curve + list(reversed(bottom_curve))
            mask = PIL.Image.new("L", (aa_width, aa_height), 0)
            PIL.ImageDraw.Draw(mask).polygon(eye_polygon, fill=255)

            sclera_layer = PIL.Image.new("RGBA", (aa_width, aa_height), (0, 0, 0, 0))
            sclera_draw = PIL.ImageDraw.Draw(sclera_layer)
            sclera_draw.polygon(eye_polygon, fill=sclera_fill)
            sclera_highlight_box = (
                int((center_x - 46) * antialias),
                int((center_y - 18) * antialias),
                int((center_x + 46) * antialias),
                int((center_y + 16) * antialias),
            )
            sclera_draw.ellipse(sclera_highlight_box, fill=(255, 255, 255, 12))
            image.alpha_composite(sclera_layer)

            iris_shift = int(math.sin(time.monotonic() * 0.9) * 4)
            iris_radius = max(10, int(11.5 + (open_ratio * 1.5)))
            pupil_radius = max(4, int(iris_radius * 0.31))
            iris_x = center_x + iris_shift
            iris_y = center_y
            iris_layer = PIL.Image.new("RGBA", (aa_width, aa_height), (0, 0, 0, 0))
            iris_draw = PIL.ImageDraw.Draw(iris_layer)
            shadow_box = (
                int((iris_x - iris_radius - 4) * antialias),
                int((iris_y - iris_radius - 3) * antialias),
                int((iris_x + iris_radius + 4) * antialias),
                int((iris_y + iris_radius + 5) * antialias),
            )
            iris_box = (
                int((iris_x - iris_radius) * antialias),
                int((iris_y - iris_radius) * antialias),
                int((iris_x + iris_radius) * antialias),
                int((iris_y + iris_radius) * antialias),
            )
            iris_ring_radius = max(7, int(iris_radius * 0.66))
            iris_inner_box = (
                int((iris_x - iris_ring_radius) * antialias),
                int((iris_y - iris_ring_radius) * antialias),
                int((iris_x + iris_ring_radius) * antialias),
                int((iris_y + iris_ring_radius) * antialias),
            )
            pupil_box = (
                int((iris_x - pupil_radius) * antialias),
                int((iris_y - pupil_radius) * antialias),
                int((iris_x + pupil_radius) * antialias),
                int((iris_y + pupil_radius) * antialias),
            )
            highlight_box = (
                int((iris_x - iris_radius + 4.6) * antialias),
                int((iris_y - iris_radius + 3.6) * antialias),
                int((iris_x - iris_radius + 9.2) * antialias),
                int((iris_y - iris_radius + 8.2) * antialias),
            )
            iris_draw.ellipse(shadow_box, fill=(6, 18, 34, 34))
            iris_draw.ellipse(iris_box, fill=(55, 132, 244, 255), outline=(24, 58, 112, 255), width=6)
            iris_draw.ellipse(iris_inner_box, fill=(176, 221, 255, 176))
            iris_draw.ellipse(pupil_box, fill=(4, 15, 30, 255))
            iris_draw.ellipse(highlight_box, fill=(255, 255, 255, 236))
            image.alpha_composite(PIL.Image.composite(iris_layer, PIL.Image.new("RGBA", (aa_width, aa_height), (0, 0, 0, 0)), mask))

            lid_shadow = PIL.Image.new("RGBA", (aa_width, aa_height), (0, 0, 0, 0))
            lid_shadow_draw = PIL.ImageDraw.Draw(lid_shadow)
            shadow_depth = int(max(14, 18 * open_ratio) * antialias)
            top_shadow_polygon = top_curve + list(reversed([(x, y + shadow_depth) for x, y in top_curve]))
            lid_shadow_draw.polygon(top_shadow_polygon, fill=(7, 18, 36, 26))
            image.alpha_composite(PIL.Image.composite(lid_shadow, PIL.Image.new("RGBA", (aa_width, aa_height), (0, 0, 0, 0)), mask))

            draw.line(top_curve, fill=outline_glow, width=14)
            draw.line(bottom_curve, fill=outline_glow, width=14)
            draw.line(top_curve, fill=outline, width=8)
            draw.line(bottom_curve, fill=outline, width=8)

        resampling = getattr(getattr(PIL.Image, "Resampling", PIL.Image), "LANCZOS", PIL.Image.LANCZOS)
        image = image.resize((width, height), resampling)
        self._eye_photo = PIL.ImageTk.PhotoImage(image, master=canvas)
        canvas.create_image(0, 0, image=self._eye_photo, anchor="nw")

    def _animate_eye(self):
        self.animation_after_id = None
        try:
            if not self.root.winfo_exists():
                return
            self._draw_eye()
            self.animation_after_id = self.root.after(42, self._animate_eye)
        except Exception:
            self.animation_after_id = None

    def set_stage(self, stage_key):
        if stage_key not in self.STAGE_ORDER:
            stage_key = "startup.launching"
        self.stage_key = stage_key
        self.title_label.configure(text=tr("startup.title"))
        self.stage_label.configure(text=tr(stage_key))
        self.detail_label.configure(text=tr(stage_key.replace("startup.", "startup.detail.")))
        self._refresh_layout()
        self._fit_window_to_content()
        self.refresh()

    def refresh(self):
        try:
            self.root.update_idletasks()
            self.root.update()
        except Exception:
            pass

    def hide(self):
        if self.hidden:
            return
        try:
            self.root.withdraw()
        except Exception:
            return
        self.hidden = True

    def show(self):
        if not self.hidden:
            self.refresh()
            return
        try:
            self.root.deiconify()
            self.root.attributes("-topmost", True)
            self.hidden = False
        except Exception:
            return
        self.refresh()

    def close(self):
        if self.animation_after_id is not None:
            try:
                self.root.after_cancel(self.animation_after_id)
            except Exception:
                pass
            self.animation_after_id = None
        try:
            self.root.destroy()
        except Exception:
            pass


def startup_progress_open():
    global startup_progress_window
    if not startup_loading_screen_enabled:
        return None
    if startup_progress_window is None:
        try:
            startup_progress_window = StartupProgressWindow()
        except Exception:
            startup_progress_window = None
    return startup_progress_window


def startup_progress_update(stage_key):
    window = startup_progress_open()
    if window:
        window.set_stage(stage_key)


def startup_progress_hide():
    window = startup_progress_window
    if window:
        window.hide()


def startup_progress_show():
    window = startup_progress_window
    if window:
        window.show()


def startup_progress_close():
    global startup_progress_window
    window = startup_progress_window
    startup_progress_window = None
    if window:
        window.close()


def startup_progress_wait(duration_seconds, interval_seconds=0.016):
    deadline = time.monotonic() + max(0.0, float(duration_seconds or 0.0))
    while True:
        window = startup_progress_window
        if window:
            window.refresh()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(interval_seconds, remaining))


def run_startup_background_task(task, stage_key=None, interval_seconds=0.016):
    if stage_key:
        startup_progress_update(stage_key)
    result = {"value": None, "error": None}
    completed = Event()

    def _runner():
        try:
            result["value"] = task()
        except Exception as exc:
            result["error"] = exc
        finally:
            completed.set()

    Thread(target=_runner, daemon=True).start()
    while not completed.wait(interval_seconds):
        window = startup_progress_window
        if window:
            window.refresh()

    window = startup_progress_window
    if window:
        window.refresh()
    if result["error"] is not None:
        raise result["error"]
    return result["value"]


def show_styled_message(title, message, is_error=False, ask_retry=False, parent=None):
    result = {"value": False}
    message_text = str(message or "")
    base_height = 320 if ask_retry else 290
    line_count = message_text.count("\n") + 1
    estimated_height = min(620, base_height + max(0, line_count - 4) * 18 + max(0, len(message_text) - 180) // 15)
    root, card = make_dialog_shell(title, 640, estimated_height, parent=parent)

    heading = tr("dialog.heading.retry") if ask_retry else (tr("dialog.heading.error") if is_error else tr("dialog.heading.info"))
    heading_color = UI_DANGER if is_error else UI_TEXT

    header = tk.Frame(card, bg=UI_CARD_BG, bd=0)
    header.pack(fill="x", padx=30, pady=(26, 12))
    tk.Label(header, text=heading, bg=UI_CARD_BG, fg=heading_color, font=(UI_FONT, 22, "bold")).pack(anchor="w")

    content = tk.Frame(card, bg=UI_PANEL_BG, highlightbackground=UI_BORDER, highlightthickness=1, bd=0)
    content.pack(fill="both", expand=True, padx=30, pady=(0, 14))

    badge = tk.Frame(content, bg=UI_GLASS, bd=0)
    badge.pack(anchor="w", padx=16, pady=(16, 0))
    badge_label = tk.Label(
        badge,
        text=APP_NAME,
        bg=UI_GLASS,
        fg="#DCE8FF",
        font=(UI_FONT, 9, "bold"),
        padx=10,
        pady=6,
    )
    badge_label.pack()
    schedule_widget_rounding(badge, radius=14)

    message_label = tk.Label(
        content,
        text=message_text,
        bg=UI_PANEL_BG,
        fg=UI_TEXT,
        font=(UI_FONT, 11),
        justify="left",
        wraplength=540,
    )
    message_label.pack(anchor="w", padx=16, pady=(12, 16))

    button_bar = tk.Frame(card, bg=UI_CARD_BG, bd=0)
    button_bar.pack(fill="x", padx=30, pady=(0, 24))

    def close_with(value=False):
        result["value"] = value
        root.destroy()

    if ask_retry:
        exit_btn = tk.Button(
            button_bar,
            text=tr("dialog.quit"),
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
            text=tr("dialog.retry_login"),
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
            text=tr("dialog.ok"),
            command=lambda: close_with(False),
            relief="flat",
            bd=0,
            padx=20,
            pady=10,
            font=(UI_FONT, 10, "bold"),
            cursor="hand2",
        )
        style_button(close_btn, primary=True)
        close_btn.pack(side="right")

    fit_window_to_content(root, min_width=620, min_height=estimated_height, max_width=860, max_height=640)
    root.minsize(560, 300)
    root.maxsize(max(660, root.winfo_screenwidth() - 24), max(360, root.winfo_screenheight() - 56))

    def _refresh_wrap(_event=None):
        wrap = max(340, root.winfo_width() - 110)
        try:
            message_label.configure(wraplength=wrap)
        except Exception:
            pass

    root.bind("<Configure>", _refresh_wrap, add="+")
    root.after(30, _refresh_wrap)
    root.protocol("WM_DELETE_WINDOW", lambda: close_with(False))
    root.bind("<Escape>", lambda _event: close_with(False))
    if parent:
        try:
            root.grab_set()
            parent.wait_window(root)
        except Exception:
            pass
    else:
        root.mainloop()
    return bool(result["value"])


def prompt_startup_auth_legacy(
    initial_server_url,
    initial_license,
    initial_api_key,
    initial_blob_size="medium",
    initial_mode="api",
    initial_error="",
):
    _ = initial_server_url
    result = {"value": None}
    root, card = make_dialog_shell(tr("auth.window_title"), 920, 760)
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    max_width_limit = max(620, screen_width - 24)
    max_height_limit = max(520, screen_height - 56)
    min_width = min(max(700, int(screen_width * 0.58)), max(720, screen_width - 80))
    min_height = min(max(560, int(screen_height * 0.62)), max(580, screen_height - 90))
    min_width = min(min_width, max_width_limit)
    min_height = min(min_height, max_height_limit)
    preferred_width = min(980, max(min_width, int(screen_width * 0.68)))
    preferred_height = min(820, max(min_height, int(screen_height * 0.74)))
    center_window(root, preferred_width, preferred_height)
    root.minsize(min_width, min_height)
    root.maxsize(max_width_limit, max_height_limit)

    mode_var = tk.StringVar(value="license" if str(initial_mode or "").strip().lower() == "license" else "api")
    language_var = tk.StringVar(value=normalize_language(ui_language))
    blob_size_var = tk.StringVar(value=normalize_indicator_blob_size(initial_blob_size))
    position_var = tk.StringVar(value=normalize_indicator_position(indicator_position_key))
    startup_screen_var = tk.BooleanVar(value=bool(startup_loading_screen_enabled))
    pro_model_var = tk.StringVar(value=normalize_pro_model(selected_pro_model_key))
    license_var = tk.StringVar(value=initial_license or "")
    api_var = tk.StringVar(value=initial_api_key or "")
    show_api_var = tk.BooleanVar(value=False)
    error_var = tk.StringVar(value=str(initial_error or ""))
    subscription_unlocked_var = tk.BooleanVar(value=True)
    subscription_state_var = tk.StringVar(value="")
    wrap_labels = []

    header = tk.Frame(card, bg=UI_CARD_BG, bd=0)
    header.pack(fill="x", padx=30, pady=(24, 10))
    title_label = tk.Label(header, text="", bg=UI_CARD_BG, fg=UI_TEXT, font=(UI_FONT, 31, "bold"), cursor="hand2")
    title_label.pack(anchor="w", pady=(0, 2))
    title_label.bind("<Button-1>", lambda _event: open_default_website(), add="+")
    title_label.bind("<Enter>", lambda _event: title_label.configure(fg=UI_ACCENT), add="+")
    title_label.bind("<Leave>", lambda _event: title_label.configure(fg=UI_TEXT), add="+")
    subtitle_label = tk.Label(
        header,
        text="",
        bg=UI_CARD_BG,
        fg=UI_MUTED,
        font=(UI_FONT, 12),
    )
    subtitle_label.pack(anchor="w")
    hotkey_label = tk.Label(
        header,
        text="",
        bg=UI_CARD_BG,
        fg=UI_MUTED,
        font=(UI_FONT, 9),
    )
    hotkey_label.pack(anchor="w", pady=(6, 0))
    subscription_state_label = tk.Label(
        header,
        textvariable=subscription_state_var,
        bg=UI_CARD_BG,
        fg=UI_MUTED,
        font=(UI_FONT, 9, "bold"),
    )
    subscription_state_label.pack(anchor="w", pady=(6, 0))
    wrap_labels.extend([subtitle_label, hotkey_label, subscription_state_label])

    language_shell = tk.Frame(header, bg=UI_CARD_BG, bd=0)
    language_shell.pack(anchor="e", pady=(10, 0))
    language_title = tk.Label(language_shell, text="", bg=UI_CARD_BG, fg=UI_MUTED, font=(UI_FONT, 9, "bold"))
    language_title.pack(side="left", padx=(0, 8))
    language_buttons = {}
    for lang_key in ("en", "fr"):
        lang_btn = tk.Button(
            language_shell,
            relief="flat",
            bd=0,
            padx=10,
            pady=6,
            font=(UI_FONT, 9, "bold"),
            cursor="hand2",
            command=lambda value=lang_key: (language_var.set(value), refresh_copy(), update_blob_size_ui()),
        )
        lang_btn.pack(side="left", padx=(0, 6))
        language_buttons[lang_key] = lang_btn

    switch_shell = tk.Frame(card, bg=UI_SOFT, highlightbackground=UI_BORDER, highlightthickness=1, bd=0)
    switch_shell.pack(fill="x", padx=30, pady=(0, 12))
    mode_license_btn = tk.Button(
        switch_shell,
        text="",
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
        text="",
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

    blob_settings = tk.Frame(form_content, bg=UI_PANEL_BG, bd=0)
    blob_settings.pack(fill="x", pady=(0, 14))
    blob_title_label = tk.Label(blob_settings, text="", bg=UI_PANEL_BG, fg=UI_TEXT, font=(UI_FONT, 10, "bold"))
    blob_title_label.pack(anchor="w")

    blob_buttons_row = tk.Frame(blob_settings, bg=UI_PANEL_BG, bd=0)
    blob_buttons_row.pack(fill="x", pady=(6, 8))
    position_title_label = tk.Label(blob_settings, text="", bg=UI_PANEL_BG, fg=UI_TEXT, font=(UI_FONT, 10, "bold"))
    position_title_label.pack(anchor="w", pady=(8, 0))
    position_value_label = tk.Label(blob_settings, text="", bg=UI_PANEL_BG, fg=UI_TEXT, font=(UI_FONT, 11, "bold"))
    position_value_label.pack(anchor="w", pady=(4, 8))

    blob_preview_shell = tk.Frame(blob_settings, bg=UI_FIELD_BG, highlightbackground=UI_BORDER, highlightthickness=1, bd=0)
    blob_preview_shell.pack(fill="x")
    blob_preview_canvas = tk.Canvas(
        blob_preview_shell,
        width=320,
        height=190,
        highlightthickness=0,
        bd=0,
        bg=UI_FIELD_BG,
        cursor="hand2",
    )
    blob_preview_canvas.pack(fill="x", padx=8, pady=8)

    startup_title_label = tk.Label(blob_settings, text="", bg=UI_PANEL_BG, fg=UI_TEXT, font=(UI_FONT, 10, "bold"))
    startup_title_label.pack(anchor="w", pady=(12, 0))
    startup_toggle_btn = tk.Button(
        blob_settings,
        text="",
        command=lambda: (startup_screen_var.set(not startup_screen_var.get()), update_startup_screen_ui()),
        relief="flat",
        bd=0,
        padx=12,
        pady=8,
        font=(UI_FONT, 9, "bold"),
        cursor="hand2",
    )
    startup_toggle_btn.pack(anchor="w", pady=(8, 0))
    startup_helper_label = tk.Label(
        blob_settings,
        text="",
        bg=UI_PANEL_BG,
        fg=UI_MUTED,
        font=(UI_FONT, 9),
        justify="left",
        wraplength=520,
    )
    startup_helper_label.pack(anchor="w", pady=(8, 0))
    wrap_labels.append(startup_helper_label)

    blob_size_buttons = {}
    preview_hotspots = {}

    def redraw_blob_preview():
        preview_width = int(max(240, blob_preview_canvas.winfo_width()))
        preview_height = int(max(160, blob_preview_canvas.winfo_height()))
        blob_preview_canvas.delete("all")
        blob_preview_canvas._eae_image_refs = []
        preview_hotspots.clear()
        inner_pad = 1
        draw_rounded_canvas_rect(
            blob_preview_canvas,
            inner_pad,
            inner_pad,
            preview_width - 2,
            preview_height - 2,
            12,
            fill="#000000",
            outline="#0D0D0D",
            antialias=2,
        )
        surface_left = 18
        surface_top = 42
        surface_right = preview_width - 18
        surface_bottom = preview_height - 18
        draw_rounded_canvas_rect(
            blob_preview_canvas,
            surface_left,
            surface_top,
            surface_right,
            surface_bottom,
            24,
            fill="#050505",
            outline="#172332",
            antialias=2,
        )
        current_key = normalize_indicator_blob_size(blob_size_var.get())
        selected_position = normalize_indicator_position(position_var.get())
        blob_size = int(INDICATOR_BLOB_SIZES[current_key])
        hotspot_radius = max(9, int(min(surface_right - surface_left, surface_bottom - surface_top) * 0.035))
        for position_key in INDICATOR_POSITIONS:
            center_x, center_y = compute_preview_anchor_point(
                surface_left,
                surface_top,
                surface_right,
                surface_bottom,
                position_key,
            )
            preview_hotspots[position_key] = (center_x, center_y, hotspot_radius)
            selected_hotspot = position_key == selected_position
            blob_preview_canvas.create_oval(
                center_x - hotspot_radius,
                center_y - hotspot_radius,
                center_x + hotspot_radius,
                center_y + hotspot_radius,
                outline="#22D05D" if selected_hotspot else "#37506F",
                width=2 if selected_hotspot else 1,
                fill="#0A140C" if selected_hotspot else "",
            )
        center_x, center_y = compute_preview_anchor_point(
            surface_left,
            surface_top,
            surface_right,
            surface_bottom,
            selected_position,
        )
        chip_x1 = int(center_x - (blob_size / 2))
        chip_y1 = int(center_y - (blob_size / 2))
        chip_x2 = chip_x1 + blob_size - 1
        chip_y2 = chip_y1 + blob_size - 1
        draw_rounded_canvas_rect(
            blob_preview_canvas,
            chip_x1,
            chip_y1,
            chip_x2,
            chip_y2,
            compute_indicator_chip_corner_radius(blob_size),
            fill="#636A74",
            outline="#98A0AB",
            width=1,
            antialias=1,
        )
        blob_preview_canvas.create_text(
            12,
            10,
            text=f"{tr('auth.preview.title', language=language_var.get())}: {tr(f'position.{selected_position}', language=language_var.get())}",
            fill="#EAF2FF",
            anchor="nw",
            font=(UI_FONT, 9, "bold"),
        )
        blob_preview_canvas.create_text(
            12,
            preview_height - 34,
            text=tr("auth.preview.copy", language=language_var.get()),
            fill="#CBD9F5",
            anchor="w",
            font=(UI_FONT, 9),
            width=max(120, preview_width - 32),
        )

    def set_blob_size(next_size):
        blob_size_var.set(normalize_indicator_blob_size(next_size))
        update_blob_size_ui()

    def on_blob_preview_click(event):
        nearest_key = ""
        nearest_distance = None
        for position_key, (center_x, center_y, radius) in preview_hotspots.items():
            distance = math.hypot(float(event.x - center_x), float(event.y - center_y))
            if nearest_distance is None or distance < nearest_distance:
                nearest_key = position_key
                nearest_distance = distance
            if distance <= max(radius * 1.8, 18):
                nearest_key = position_key
                break
        if nearest_key:
            position_var.set(nearest_key)
            update_blob_size_ui()

    def update_blob_size_ui():
        selected = normalize_indicator_blob_size(blob_size_var.get())
        for size_key, button in blob_size_buttons.items():
            if size_key == selected:
                style_button(button, primary=True)
            else:
                style_button(button, primary=False)
        selected_position = normalize_indicator_position(position_var.get())
        position_value_label.configure(text=tr(f"position.{selected_position}", language=language_var.get()))
        redraw_blob_preview()

    def update_startup_screen_ui():
        enabled = bool(startup_screen_var.get())
        startup_toggle_btn.configure(
            text=tr("auth.startup_screen.enabled", language=language_var.get())
            if enabled
            else tr("auth.startup_screen.disabled", language=language_var.get())
        )
        style_button(startup_toggle_btn, primary=enabled, active=not enabled)

    for size_key in ("very_small", "small", "medium", "large"):
        btn = tk.Button(
            blob_buttons_row,
            text=INDICATOR_BLOB_SIZE_LABELS[size_key],
            command=lambda value=size_key: set_blob_size(value),
            relief="flat",
            bd=0,
            padx=12,
            pady=8,
            font=(UI_FONT, 9, "bold"),
            cursor="hand2",
        )
        style_button(btn, primary=False)
        btn.pack(side="left", padx=(0, 8))
        blob_size_buttons[size_key] = btn

    blob_preview_canvas.bind("<Configure>", lambda _event: redraw_blob_preview())
    blob_preview_canvas.bind("<Button-1>", on_blob_preview_click)

    license_frame = tk.Frame(form_content, bg=UI_PANEL_BG, bd=0)
    api_frame = tk.Frame(form_content, bg=UI_PANEL_BG, bd=0)

    def make_labeled_entry(parent, label_text, var, *, show=None):
        label = tk.Label(parent, text=label_text, bg=UI_PANEL_BG, fg=UI_TEXT, font=(UI_FONT, 10, "bold"))
        label.pack(anchor="w", pady=(0, 6))
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
        return label, entry

    license_label_widget, license_entry = make_labeled_entry(license_frame, "", license_var)
    license_entry.bind("<KeyRelease>", lambda _event: error_var.set(""), add="+")
    license_hint_label = tk.Label(
        license_frame,
        text="",
        bg=UI_PANEL_BG,
        fg=UI_MUTED,
        font=(UI_FONT, 9),
    )
    license_hint_label.pack(anchor="w", pady=(4, 0))
    wrap_labels.append(license_hint_label)
    pro_model_label = tk.Label(license_frame, text="", bg=UI_PANEL_BG, fg=UI_TEXT, font=(UI_FONT, 10, "bold"))
    pro_model_label.pack(anchor="w", pady=(12, 6))
    pro_model_menu = tk.OptionMenu(license_frame, pro_model_var, *(item["id"] for item in PRO_MODEL_OPTIONS))
    pro_model_menu.configure(
        relief="flat",
        bd=0,
        bg=UI_GHOST_BG,
        fg=UI_TEXT,
        activebackground=UI_GHOST_ACTIVE,
        activeforeground=UI_TEXT,
        highlightthickness=0,
        font=(UI_FONT, 10),
    )
    pro_model_menu.pack(fill="x")
    pro_model_menu["menu"].delete(0, "end")
    for model_option in PRO_MODEL_OPTIONS:
        pro_model_menu["menu"].add_command(
            label=model_option["label"],
            command=lambda value=model_option["id"]: pro_model_var.set(value),
        )
    pro_model_hint_label = tk.Label(
        license_frame,
        text="",
        bg=UI_PANEL_BG,
        fg=UI_MUTED,
        font=(UI_FONT, 9),
        justify="left",
        wraplength=520,
    )
    pro_model_hint_label.pack(anchor="w", pady=(6, 0))
    wrap_labels.append(pro_model_hint_label)

    api_label_widget, api_entry = make_labeled_entry(api_frame, "", api_var, show="*")
    api_entry.bind("<KeyRelease>", lambda _event: error_var.set(""), add="+")
    api_options = tk.Frame(api_frame, bg=UI_PANEL_BG, bd=0)
    api_options.pack(fill="x", pady=(8, 0))

    def toggle_show_api():
        show_api = not show_api_var.get()
        show_api_var.set(show_api)
        api_entry.configure(show="" if show_api else "*")
        refresh_copy()

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

    paste_api_btn = tk.Button(
        api_options,
        text="",
        command=lambda: api_var.set(str(pyperclip.paste() or "").strip()),
        relief="flat",
        bd=0,
        padx=12,
        pady=6,
        font=(UI_FONT, 9, "bold"),
        cursor="hand2",
    )
    style_button(paste_api_btn, primary=False)
    paste_api_btn.pack(side="left", padx=(8, 0))

    api_link_btn = tk.Button(
        api_options,
        text="",
        command=lambda: webbrowser.open("https://aistudio.google.com/api-keys", new=2),
        relief="flat",
        bd=0,
        padx=12,
        pady=6,
        font=(UI_FONT, 9, "bold"),
        cursor="hand2",
    )
    style_button(api_link_btn, primary=False)
    api_link_btn.pack(side="left", padx=(8, 0))

    api_note_label = tk.Label(
        api_frame,
        text="",
        bg=UI_PANEL_BG,
        fg=UI_MUTED,
        font=(UI_FONT, 9),
        justify="left",
        wraplength=520,
    )
    api_note_label.pack(anchor="w", pady=(10, 0))
    wrap_labels.append(api_note_label)

    info_row = tk.Frame(card, bg=UI_CARD_BG, bd=0)
    info_row.pack(fill="x", padx=30, pady=(0, 2))
    info_label = tk.Label(
        info_row,
        text="",
        bg=UI_CARD_BG,
        fg=UI_MUTED,
        font=(UI_FONT, 9),
    )
    info_label.pack(anchor="w")
    wrap_labels.append(info_label)

    error_label = tk.Label(card, textvariable=error_var, bg=UI_CARD_BG, fg=UI_DANGER, font=(UI_FONT, 10, "bold"))
    error_label.pack(
        fill="x", anchor="w", padx=30, pady=(2, 4)
    )
    wrap_labels.append(error_label)

    button_bar = tk.Frame(card, bg=UI_CARD_BG, bd=0)
    button_bar.pack(fill="x", padx=30, pady=(0, 24))

    def on_cancel():
        result["value"] = None
        root.destroy()

    def refresh_copy():
        lang = normalize_language(language_var.get())
        title_label.configure(text=tr("auth.title", language=lang))
        subtitle_label.configure(text=tr("auth.subtitle", language=lang))
        hotkey_label.configure(text=tr("auth.hotkeys.copy", language=lang))
        subscription_state_var.set(tr("auth.status.pro", language=lang) if mode_var.get() == "license" else tr("auth.status.free", language=lang))
        language_title.configure(text=tr("auth.language", language=lang))
        for key, btn in language_buttons.items():
            btn.configure(text=tr(f"lang.{key}", language=lang))
            style_button(btn, primary=(language_var.get() == key))
        mode_api_btn.configure(text=tr("auth.mode.free", language=lang))
        mode_license_btn.configure(text=tr("auth.mode.pro", language=lang))
        blob_title_label.configure(text=tr("auth.section.indicator_size", language=lang))
        position_title_label.configure(text=tr("auth.section.indicator_position", language=lang))
        position_value_label.configure(text=tr(f"position.{normalize_indicator_position(position_var.get())}", language=lang))
        startup_title_label.configure(text=tr("auth.startup_screen.label", language=lang))
        startup_helper_label.configure(text=tr("auth.startup_screen.copy", language=lang))
        update_startup_screen_ui()
        for size_key, button in blob_size_buttons.items():
            button.configure(text=tr(f"size.{size_key}", language=lang))
        license_label_widget.configure(text=tr("auth.pro.label", language=lang))
        license_hint_label.configure(text=tr("auth.pro.note", language=lang))
        pro_model_label.configure(text=tr("auth.pro.model", language=lang))
        pro_model_hint_label.configure(text=tr("auth.pro.model.note", language=lang))
        api_label_widget.configure(text=tr("auth.api.label", language=lang))
        show_api_btn.configure(text=tr("auth.api.hide", language=lang) if show_api_var.get() else tr("auth.api.show", language=lang))
        paste_api_btn.configure(text=tr("auth.api.paste", language=lang))
        api_link_btn.configure(text=tr("auth.api.link", language=lang))
        api_note_label.configure(text=tr("auth.api.helper", language=lang))
        info_label.configure(text=tr("auth.security", language=lang))
        cancel_btn.configure(text=tr("auth.cancel", language=lang))
        continue_btn.configure(text=tr("auth.continue", language=lang))

    def on_continue():
        error_var.set("")
        lang = normalize_language(language_var.get())
        selected_mode = mode_var.get().strip()
        if selected_mode == "license":
            entered_license = license_var.get().strip()
            error_key = soft_validate_license_code(entered_license)
            if error_key:
                error_var.set(tr(error_key, language=lang))
                license_entry.focus_set()
                return
            result["value"] = {
                "mode": "license",
                "license_code": entered_license,
                "blob_size": normalize_indicator_blob_size(blob_size_var.get()),
                "language": lang,
                "indicator_position": normalize_indicator_position(position_var.get()),
                "show_startup_screen": bool(startup_screen_var.get()),
                "pro_model": normalize_pro_model(pro_model_var.get()),
            }
        else:
            entered_api_key = api_var.get().strip()
            error_key = soft_validate_api_key(entered_api_key)
            if error_key:
                error_var.set(tr(error_key, language=lang))
                api_entry.focus_set()
                return
            result["value"] = {
                "mode": "api",
                "api_key": entered_api_key,
                "blob_size": normalize_indicator_blob_size(blob_size_var.get()),
                "language": lang,
                "indicator_position": normalize_indicator_position(position_var.get()),
                "show_startup_screen": bool(startup_screen_var.get()),
                "pro_model": normalize_pro_model(pro_model_var.get()),
            }
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
        refresh_copy()
        if is_license:
            api_frame.pack_forget()
            license_frame.pack(fill="x", pady=(0, 8))
            license_entry.focus_set()
        else:
            license_frame.pack_forget()
            api_frame.pack(fill="x", pady=(0, 8))
            api_entry.focus_set()

    def on_return_key(_event):
        on_continue()
        return "break"

    root.protocol("WM_DELETE_WINDOW", on_cancel)
    root.bind("<Escape>", lambda _event: on_cancel())
    root.bind("<Return>", on_return_key)

    resize_refresh = {"after_id": None}

    def refresh_min_bounds():
        try:
            root.update_idletasks()
            required_width = max(min_width, min(max_width_limit, int(card.winfo_reqwidth()) + 42))
            required_height = max(min_height, min(max_height_limit, int(card.winfo_reqheight()) + 38))
            root.minsize(required_width, required_height)
        except Exception:
            pass

    def apply_responsive_layout():
        resize_refresh["after_id"] = None
        wrap = max(340, root.winfo_width() - 120)
        for label in wrap_labels:
            try:
                label.configure(wraplength=wrap)
            except Exception:
                pass
        redraw_blob_preview()
        refresh_min_bounds()

    def queue_responsive_layout(_event=None):
        if resize_refresh["after_id"] is not None:
            try:
                root.after_cancel(resize_refresh["after_id"])
            except Exception:
                pass
        resize_refresh["after_id"] = root.after(40, apply_responsive_layout)

    root.bind("<Configure>", queue_responsive_layout, add="+")
    update_blob_size_ui()
    update_mode_ui()
    refresh_min_bounds()
    root.after(60, apply_responsive_layout)
    root.mainloop()
    return result["value"]


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


def get_window_title(hwnd):
    if os.name != "nt":
        return ""
    try:
        title_buffer = ctypes.create_unicode_buffer(512)
        if _user32.GetWindowTextW(wintypes.HWND(int(hwnd)), title_buffer, len(title_buffer)) <= 0:
            return ""
        return str(title_buffer.value or "").strip()
    except Exception:
        return ""


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
                if not normalized_hwnd or not _user32.IsWindowVisible(wintypes.HWND(normalized_hwnd)):
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


class AuthShellBridge:
    def __init__(self):
        self._window = None
        self._result = None
        self._done = Event()
        self._manual_maximized = False
        self._normal_bounds = None
        self._hwnd_cache = 0

    def bind_window(self, window):
        self._window = window
        try:
            if self._window is not None:
                self._window.events.closed += self._on_closed
        except Exception:
            pass

    @property
    def result(self):
        return self._result

    def wait(self, timeout=None):
        self._done.wait(timeout)
        return self._result

    def _on_closed(self, *args, **kwargs):
        self._done.set()

    def _get_hwnd(self):
        if is_valid_window_handle(self._hwnd_cache):
            return int(self._hwnd_cache)
        hwnd = extract_native_window_handle(self._window, max_depth=2)
        if not hwnd:
            hwnd = extract_native_window_handle(getattr(self._window, "native", None), max_depth=3)
        if not hwnd:
            hwnd = find_webview_window_hwnd(getattr(self._window, "title", ""), process_id=os.getpid())
        if hwnd:
            self._hwnd_cache = int(hwnd)
            return int(hwnd)
        logger.warning("Could not resolve auth window handle for resize operations.")
        return 0

    def submit(self, payload):
        if not isinstance(payload, dict):
            return {"ok": False, "error": "Invalid setup payload."}
        hotkeys, hotkey_mode, hotkeys_customized = resolve_command_hotkey_state(
            payload.get("hotkeys"),
            payload.get("hotkey_mode", command_key_mode),
        )
        normalized = {
            "mode": "license" if str(payload.get("mode", "")).strip().lower() == "license" else "api",
            "language": normalize_language(payload.get("language", ui_language)),
            "theme": normalize_theme_preference(payload.get("theme", ui_theme_preference)),
            "blob_size": normalize_indicator_blob_size(payload.get("blob_size", indicator_blob_size_key)),
            "indicator_position": normalize_indicator_position(payload.get("indicator_position", indicator_position_key)),
            "show_startup_screen": normalize_startup_loading_screen_enabled(payload.get("show_startup_screen", startup_loading_screen_enabled)),
            "pro_model": normalize_pro_model(payload.get("pro_model", selected_pro_model_key)),
            "hotkeys": hotkeys,
            "hotkey_mode": hotkey_mode,
            "hotkeys_customized": bool(hotkeys_customized),
        }
        if normalized["mode"] == "license":
            normalized["license_code"] = str(payload.get("license_code", "") or "").strip()
            try:
                trusted_now, trusted_time_source = fetch_trusted_utc_epoch()
            except Exception as exc:
                clear_startup_preflight_license_auth()
                return {"ok": False, "error": str(exc or tr("error.pro_time_unavailable"))}
            is_locked, remaining_seconds, hard_locked, _guard_state = inspect_pro_auth_guard(trusted_now)
            if is_locked:
                clear_startup_preflight_license_auth()
                return {
                    "ok": False,
                    "error": build_pro_auth_lockout_message(remaining_seconds, hard_locked=hard_locked),
                    "lockout_seconds": int(max(1, remaining_seconds)),
                    "lockout_hard": bool(hard_locked),
                }
            ok, message, auth_data, reason = perform_license_auth_request(normalized["license_code"], device_id)
            if not ok:
                clear_startup_preflight_license_auth()
                lockout_seconds = 0
                lockout_hard = False
                if reason == "lockout":
                    try:
                        message = sync_local_pro_auth_lockout(trusted_now, message, time_source=trusted_time_source)
                    except Exception:
                        logger.warning("Could not persist server-side Pro auth lockout state.", exc_info=True)
                    lockout_seconds, lockout_hard = extract_lockout_seconds_from_message(message)
                elif reason == "invalid_secret":
                    try:
                        local_lockout_message = record_local_pro_auth_failure(trusted_now, time_source=trusted_time_source)
                    except Exception:
                        logger.warning("Could not persist local Pro auth failure state.", exc_info=True)
                        local_lockout_message = ""
                    if local_lockout_message:
                        message = local_lockout_message
                        lockout_seconds, lockout_hard = extract_lockout_seconds_from_message(local_lockout_message)
                result = {"ok": False, "error": str(message or tr("error.auth_denied"))}
                if lockout_seconds > 0:
                    result["lockout_seconds"] = int(max(1, lockout_seconds))
                    result["lockout_hard"] = bool(lockout_hard)
                return result
            try:
                clear_pro_auth_guard_state()
            except Exception:
                logger.warning("Could not clear local Pro auth failure state after successful sign-in.", exc_info=True)
            cache_startup_preflight_license_auth(normalized["license_code"], device_id, auth_data)
        else:
            normalized["api_key"] = str(payload.get("api_key", "") or "").strip()
            clear_startup_preflight_license_auth()
        self._result = normalized
        self.close()
        return {"ok": True}

    def close(self):
        try:
            if self._window is not None:
                self._window.destroy()
        except Exception:
            pass
        self._done.set()
        return True

    def exit_app(self):
        self.close()
        exit_program(trigger_uninstall=False)
        return True

    def minimize(self):
        try:
            if self._window is not None:
                self._window.minimize()
        except Exception:
            return False
        return True

    def toggle_maximize(self):
        try:
            if self._window is None:
                return False
            if self._manual_maximized and self._normal_bounds:
                x, y, width, height = self._normal_bounds
                self._window.resize(int(width), int(height))
                self._window.move(int(x), int(y))
                self._manual_maximized = False
                return False

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
            left, top, right, bottom = get_work_area_bounds(screen_width, screen_height)
            self._window.move(int(left), int(top))
            self._window.resize(int(max(320, right - left)), int(max(240, bottom - top)))
            self._manual_maximized = True
            return True
        except Exception:
            logger.exception("Auth window maximize toggle failed.")
            return False

    def start_resize(self, edge):
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
        try:
            _user32.ReleaseCapture()
            _user32.SendMessageW(wintypes.HWND(int(hwnd)), WM_NCLBUTTONDOWN, hit_test, 0)
        except Exception:
            logger.exception("Auth window resize dispatch failed for edge '%s'.", direction)
            return False
        return True

    def read_clipboard(self):
        try:
            return str(pyperclip.paste() or "")
        except Exception:
            return ""

    def open_external(self, url):
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
        "allowedHotkeys": dict(ALLOWED_HOTKEY_BINDINGS),
        "defaultNumpadHotkeys": get_default_command_hotkeys("numpad"),
        "sizeIds": list(INDICATOR_BLOB_SIZES.keys()),
        "positionIds": list(INDICATOR_POSITIONS.keys()),
        "positionPoints": dict(INDICATOR_PREVIEW_POINTS),
        "proModels": list(PRO_MODEL_OPTIONS),
        "apiKeyUrl": "https://aistudio.google.com/api-keys",
        "websiteUrl": DEFAULT_WEBSITE_URL,
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
      --bg0: #081321;
      --bg1: #0e2444;
      --glass: rgba(255,255,255,0.09);
      --glass-strong: rgba(255,255,255,0.14);
      --border: rgba(255,255,255,0.12);
      --text: #f6fbff;
      --muted: #b5c7df;
      --primary: #3b8cff;
      --danger: #ff9898;
      --radius-xl: 28px;
      --radius-lg: 22px;
      --radius-md: 16px;
      --font: "Segoe UI Variable Text", "Segoe UI", sans-serif;
    }
    body.theme-light {
      --bg0: #e7eef8;
      --bg1: #d8e5f8;
      --glass: rgba(255,255,255,0.74);
      --glass-strong: rgba(255,255,255,0.86);
      --border: rgba(16,42,86,0.12);
      --text: #102a56;
      --muted: #4c6082;
      --primary: #1459d9;
      --danger: #ba1a1a;
    }
    * { box-sizing: border-box; }
    html, body {
      margin: 0;
      min-height: 100%;
      font-family: var(--font);
      color: var(--text);
      background:
        radial-gradient(circle at 12% 16%, rgba(107,174,255,0.34), transparent 26%),
        radial-gradient(circle at 86% 12%, rgba(109,239,197,0.18), transparent 24%),
        linear-gradient(160deg, var(--bg0), var(--bg1));
    }
    body {
      padding: 16px;
      overflow: auto;
    }
    .window-shell {
      height: calc(100vh - 32px);
      background: linear-gradient(180deg, rgba(255,255,255,0.08), rgba(255,255,255,0.03));
      border: 1px solid var(--border);
      box-shadow: 0 30px 90px rgba(0,0,0,0.35);
      backdrop-filter: blur(24px);
      border-radius: 32px;
      overflow: hidden;
      position: relative;
      display: flex;
      flex-direction: column;
    }
    .window-bar {
      display: flex;
      align-items: center;
      gap: 16px;
      min-height: 72px;
      padding: 14px 18px;
      border-bottom: 1px solid rgba(255,255,255,0.08);
      background: linear-gradient(180deg, rgba(255,255,255,0.08), rgba(255,255,255,0.03));
    }
    .window-drag-zone {
      min-width: 0;
      flex: 1 1 auto;
      display: flex;
      align-items: center;
      gap: 16px;
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
      gap: 12px;
      min-width: 0;
      border-radius: 14px;
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
    }
    .window-brand-mark {
      width: 18px;
      height: 18px;
      border-radius: 7px;
      border: 2px solid #22D05D;
      background: rgba(0,0,0,0.92);
      box-shadow: 0 0 22px rgba(34,208,93,0.22);
      flex: 0 0 auto;
    }
    .window-caption {
      font-size: 15px;
      font-weight: 700;
    }
    .window-status {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 220px;
      padding: 10px 16px;
      border-radius: 999px;
      background: rgba(255,255,255,0.08);
      border: 1px solid var(--border);
      color: var(--muted);
      font-size: 12px;
      text-align: center;
    }
    .window-controls {
      display: flex;
      align-items: center;
      gap: 10px;
      flex: 0 0 auto;
    }
    .chrome-control {
      width: 40px;
      height: 40px;
      border-radius: 14px;
      border: 1px solid var(--border);
      background: rgba(255,255,255,0.06);
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
      grid-template-columns: minmax(340px, 1.03fr) minmax(320px, 0.97fr);
      overflow: hidden;
      align-items: center;
    }
    .hero, .panel { min-height: 0; padding: 26px 30px; }
    .hero {
      border-right: 1px solid rgba(255,255,255,0.08);
      display: flex;
      flex-direction: column;
      gap: 18px;
      justify-content: center;
      overflow: auto;
    }
    .hero-copy {
      display: flex;
      flex-direction: column;
      gap: 14px;
    }
    h1 {
      margin: 0;
      font-size: clamp(32px, 5vw, 52px);
      line-height: 1;
      letter-spacing: -0.04em;
    }
    .hero-title-link {
      width: fit-content;
      max-width: 100%;
      font-size: clamp(32px, 5vw, 52px);
      line-height: 1;
      letter-spacing: -0.04em;
      font-weight: 700;
    }
    .hero-title-link #title {
      display: block;
    }
    .subtitle { color: var(--muted); max-width: 540px; line-height: 1.55; }
    .card {
      background: var(--glass);
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      padding: 18px;
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
    .mode.active {
      border-color: rgba(120,183,255,0.52);
      background: linear-gradient(180deg, rgba(59,140,255,0.22), var(--glass));
      transform: translateY(-1px);
      box-shadow: 0 16px 36px rgba(14,34,66,0.24);
    }
    .mode h3, .section { margin: 0 0 6px; font-size: 15px; }
    .mode p, .helper, .hint { margin: 0; color: var(--muted); font-size: 13px; line-height: 1.5; }
    .section { font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; color: #d5e2f7; }
    .panel { display: flex; flex-direction: column; gap: 16px; justify-content: center; overflow: auto; padding-bottom: 18px; }
    .main-card {
      display: flex;
      flex-direction: column;
      gap: 14px;
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
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 12px 14px;
      border-radius: var(--radius-md);
      background: rgba(255,255,255,0.08);
      border: 1px solid var(--border);
    }
    .field input, .field select {
      width: 100%;
      border: none;
      background: transparent;
      outline: none;
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
      border-radius: 999px;
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
      transition: all 220ms ease;
      z-index: 2;
    }
    .input-link-row {
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
      justify-content: flex-end;
      flex-wrap: wrap;
      gap: 10px;
      margin-left: auto;
      padding-top: 4px;
    }
    .actions .ghost,
    .actions .primary {
      min-width: 148px;
      padding: 13px 22px;
      border-radius: 18px;
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
      box-shadow: 0 28px 72px rgba(0,0,0,0.36);
      backdrop-filter: blur(22px);
      display: flex;
      flex-direction: column;
      gap: 14px;
      transform: translateX(calc(100% + 24px));
      opacity: 0;
      pointer-events: none;
      transition: transform 220ms ease, opacity 220ms ease;
      z-index: 20;
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
    @media (max-width: 980px) {
      body { padding: 14px; }
      .window-shell { height: calc(100vh - 28px); }
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
  </style>
</head>
<body class="theme-dark">
  <div class="window-shell">
    <header class="window-bar">
      <div class="window-drag-zone">
        <button class="window-brand-link" id="windowBrandLink" type="button">
          <div class="window-brand-mark"></div>
          <div class="window-caption" id="windowCaption"></div>
        </button>
        <div class="window-status" id="windowStatus"></div>
        <div class="window-drag-fill pywebview-drag-region"></div>
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
        <div class="hero-copy">
          <button class="hero-title-link" id="titleButton" type="button"><span id="title"></span></button>
          <p class="subtitle" id="subtitle"></p>
        </div>
        <div class="modes">
          <article class="card mode" id="modeApiCard"><h3 id="modeApiTitle"></h3><p id="modeApiHelp"></p></article>
          <article class="card mode" id="modeLicenseCard"><h3 id="modeLicenseTitle"></h3><p id="modeLicenseHelp"></p></article>
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
          <p class="helper" id="accountCopy"></p>
          <div class="auth-panel" id="apiPanel">
          <label class="label" id="apiLabel"></label>
          <div class="field icon-field">
            <input id="apiInput" type="password" autocomplete="off" spellcheck="false">
            <div class="field-actions">
              <button class="icon-button" id="pasteButton" type="button"></button>
              <button class="icon-button" id="showButton" type="button"></button>
            </div>
          </div>
          <div class="input-link-row"><button class="text-link" id="linkButton" type="button"></button></div>
          <p class="helper" id="apiHelper" style="margin-top: 12px;"></p>
          </div>
          <div class="auth-panel" id="licensePanel">
          <label class="label" id="licenseLabel"></label>
          <div class="field"><input id="licenseInput" type="text" autocomplete="off" spellcheck="false"></div>
          <p class="helper" id="licenseNote" style="margin-top: 12px;"></p>
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
      mode: 'api',
      language: 'en',
      theme: 'system',
      blob_size: 'medium',
      indicator_position: 'bottom_right',
      show_startup_screen: true,
      hotkeys: {},
      hotkey_mode: 'numpad',
      pro_model: '',
      api_key: '',
      license_code: '',
      error_message: '',
      lockout_until_ms: 0,
      lockout_hard: false
    }, bootstrap.initialState || {});
    const hotkeyActionIds = bootstrap.hotkeyActionIds || [];
    const allowedHotkeys = bootstrap.allowedHotkeys || {};
    const defaultNumpadHotkeys = bootstrap.defaultNumpadHotkeys || {};
    const sizeIds = bootstrap.sizeIds || [];
    const positionIds = bootstrap.positionIds || [];
    const positionPoints = bootstrap.positionPoints || {};
    const proModels = bootstrap.proModels || [];
    const apiKeyUrl = bootstrap.apiKeyUrl || '';
    const websiteUrl = bootstrap.websiteUrl || '';
    let themeDark = !!bootstrap.themeDark;
    let closePending = false;
    let settingsOpen = false;
    let awaitingHotkeyAction = '';
    let hotkeyFeedbackKey = 'auth.hotkeys.copy';
    let windowMaximized = false;
    let isSubmitting = false;
    let lockoutTickHandle = null;
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

    function renderSubmitButton() {
      const button = document.getElementById('continueButton');
      if (!button) return;
      button.classList.toggle('loading', isSubmitting);
      button.disabled = !!isSubmitting || currentLockoutSeconds() > 0;
      button.setAttribute('aria-busy', isSubmitting ? 'true' : 'false');
      setText('continueButtonLabel', isSubmitting ? t('auth.continue.loading') : t('auth.continue'));
    }

    function currentLockoutSeconds() {
      const remainingMs = Math.max(0, Number(state.lockout_until_ms || 0) - Date.now());
      if (remainingMs <= 0) return 0;
      return Math.max(1, Math.ceil(remainingMs / 1000));
    }

    function clearLockoutState() {
      state.lockout_until_ms = 0;
      state.lockout_hard = false;
    }

    function setLockoutState(seconds, hardLocked) {
      const normalizedSeconds = Math.max(0, Number(seconds || 0));
      if (normalizedSeconds <= 0) {
        clearLockoutState();
        return;
      }
      state.lockout_until_ms = Date.now() + (normalizedSeconds * 1000);
      state.lockout_hard = !!hardLocked;
    }

    function lockoutMessage() {
      const remaining = currentLockoutSeconds();
      if (remaining <= 0) return '';
      return t(state.lockout_hard ? 'error.pro_lockout_locked' : 'error.pro_lockout_wait', { seconds: remaining });
    }

    function renderLockoutState() {
      const remaining = currentLockoutSeconds();
      if (remaining > 0) {
        state.error_message = lockoutMessage();
        setText('errorText', state.error_message);
      } else if (state.lockout_until_ms) {
        clearLockoutState();
        state.error_message = '';
        setText('errorText', '');
      }
      renderSubmitButton();
    }

    function ensureLockoutTicker() {
      if (lockoutTickHandle !== null) return;
      lockoutTickHandle = window.setInterval(() => {
        renderLockoutState();
      }, 250);
    }

    if (Number(state.lockout_seconds || 0) > 0) {
      setLockoutState(state.lockout_seconds, !!state.lockout_hard);
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
      return state.mode === 'license' ? t('auth.status.pro') : t('auth.status.free');
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
        btn.onclick = () => { state.language = lang; render(); };
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
        btn.onclick = () => { state.blob_size = sizeId; renderPreview(); renderSizeButtons(); };
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
      const nextValue = state.pro_model || (proModels[0] ? proModels[0].id : '');
      state.pro_model = nextValue;
      hiddenInput.value = nextValue;
      proModels.forEach((item) => {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'model-option' + (item.id === state.pro_model ? ' active' : '');
        button.title = item.description || item.label || item.id;
        button.setAttribute('aria-pressed', item.id === state.pro_model ? 'true' : 'false');
        button.onclick = () => {
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
      settingsOpen = typeof forceOpen === 'boolean' ? forceOpen : !settingsOpen;
      if (!settingsOpen) awaitingHotkeyAction = '';
      syncSettingsState();
    }

    function render() {
      themeDark = resolveThemeDarkJs();
      document.body.classList.toggle('theme-dark', themeDark);
      document.body.classList.toggle('theme-light', !themeDark);
      document.documentElement.lang = state.language;
      setText('windowCaption', t('auth.window_caption'));
      setText('windowStatus', currentStatus());
      setText('title', t('auth.title'));
      setText('subtitle', t('auth.subtitle'));
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
      setText('modeApiTitle', t('auth.mode.free'));
      setText('modeApiHelp', t('auth.mode.free.help'));
      setText('modeLicenseTitle', t('auth.mode.pro'));
      setText('modeLicenseHelp', t('auth.mode.pro.help'));
      setText('previewTitle', t('auth.preview.title'));
      setText('previewCopy', t('auth.preview.copy'));
      setText('languageTitle', t('auth.language'));
      setText('appearanceTitle', t('auth.section.appearance'));
      setText('themeTitle', t('auth.section.theme'));
      setText('themeCopy', t('auth.theme.copy'));
      setText('sizeTitle', t('auth.section.indicator_size'));
      setText('proSectionTitle', t('auth.section.pro'));
      setText('accountTitle', state.mode === 'license' ? t('auth.mode.pro') : t('auth.mode.free'));
      setText('accountCopy', state.mode === 'license' ? t('auth.mode.pro.help') : t('auth.mode.free.help'));
      setText('apiLabel', t('auth.api.label'));
      setText('linkButton', t('auth.api.link'));
      setText('apiHelper', t('auth.api.helper'));
      setText('licenseLabel', t('auth.pro.label'));
      setText('licenseNote', t('auth.pro.note'));
      setText('modelLabel', t('auth.pro.model'));
      setText('modelNote', t('auth.pro.model.note'));
      setText('hotkeysTitle', t('auth.section.hotkeys'));
      setText('hotkeysCopy', t('auth.hotkeys.copy'));
      setText('hotkeysResetButton', t('auth.hotkeys.reset'));
      setText('hotkeysFeedback', t(awaitingHotkeyAction ? 'auth.hotkeys.waiting' : hotkeyFeedbackKey));
      setText('securityCopy', t('auth.security'));
      setText('cancelButton', t('auth.cancel'));
      document.getElementById('apiInput').placeholder = t('auth.api.placeholder');
      document.getElementById('licenseInput').placeholder = t('auth.pro.placeholder');
      document.getElementById('modeApiCard').classList.toggle('active', state.mode === 'api');
      document.getElementById('modeLicenseCard').classList.toggle('active', state.mode === 'license');
      document.getElementById('apiPanel').classList.toggle('hidden', state.mode !== 'api');
      document.getElementById('licensePanel').classList.toggle('hidden', state.mode !== 'license');
      document.getElementById('modelSettingsCard').classList.toggle('hidden', state.mode !== 'license');
      setIconButton('settingsToggleButton', 'settings', t('auth.settings'));
      setIconButton('minimizeButton', 'remove', t('auth.window.minimize'));
      setIconButton('maximizeButton', windowMaximized ? 'contract' : 'square', windowMaximized ? t('auth.window.restore') : t('auth.window.maximize'));
      setIconButton('closeChromeButton', 'close', t('auth.window.close'));
      setIconButton('pasteButton', 'paste', t('auth.api.paste'));
      setIconButton('showButton', document.getElementById('apiInput').type === 'password' ? 'eye' : 'eye-off', document.getElementById('apiInput').type === 'password' ? t('auth.api.show') : t('auth.api.hide'));
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
      renderLockoutState();
      renderSubmitButton();
      syncSettingsState();
    }

    function validate() {
      const apiValue = String(document.getElementById('apiInput').value || '').trim();
      const licenseValue = String(document.getElementById('licenseInput').value || '').trim();
      state.api_key = apiValue;
      state.license_code = licenseValue;
      if (state.mode === 'license') {
        return licenseValue ? '' : 'auth.validation.pro.empty';
      }
      if (!apiValue) return 'auth.validation.api.empty';
      if (/\s/.test(apiValue)) return 'auth.validation.api.whitespace';
      if (apiValue.length < 12) return 'auth.validation.api.short';
      if ((new Set(apiValue.split(''))).size < 4 || !/[A-Za-z]/.test(apiValue) || !/[A-Za-z0-9]/.test(apiValue)) {
        return 'auth.validation.api.shape';
      }
      return '';
    }

    async function submit() {
      if (isSubmitting) return;
      if (currentLockoutSeconds() > 0) {
        renderLockoutState();
        return;
      }
      const errorKey = validate();
      setText('errorText', errorKey ? t(errorKey) : '');
      if (errorKey) return;
      state.error_message = '';
      const payload = {
        mode: state.mode,
        language: state.language,
        theme: state.theme,
        blob_size: state.blob_size,
        indicator_position: state.indicator_position,
        show_startup_screen: !!state.show_startup_screen,
        hotkeys: state.hotkeys,
        hotkey_mode: state.hotkey_mode,
        pro_model: state.pro_model,
        api_key: state.api_key,
        license_code: state.license_code
      };
      if (window.pywebview && window.pywebview.api && window.pywebview.api.submit) {
        isSubmitting = true;
        renderSubmitButton();
        await nextPaint();
        try {
          const result = await window.pywebview.api.submit(payload);
          if (result && result.error) {
            state.error_message = String(result.error || '');
            if (Number(result.lockout_seconds || 0) > 0) setLockoutState(result.lockout_seconds, !!result.lockout_hard);
            else clearLockoutState();
            setText('errorText', state.error_message);
            renderLockoutState();
            return;
          }
          clearLockoutState();
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

    async function pasteKey() {
      let value = '';
      try {
        if (window.pywebview && window.pywebview.api && window.pywebview.api.read_clipboard) value = await window.pywebview.api.read_clipboard();
        else if (navigator.clipboard && navigator.clipboard.readText) value = await navigator.clipboard.readText();
      } catch (error) {}
      if (value) {
        document.getElementById('apiInput').value = String(value).trim();
        setText('errorText', '');
      }
    }

    async function closeWindow() {
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
      if (window.pywebview && window.pywebview.api && window.pywebview.api.exit_app) {
        await window.pywebview.api.exit_app();
        return;
      }
      await closeWindow();
    }

    async function minimizeWindow() {
      if (window.pywebview && window.pywebview.api && window.pywebview.api.minimize) {
        await window.pywebview.api.minimize();
      }
    }

    async function toggleMaximize() {
      if (window.pywebview && window.pywebview.api && window.pywebview.api.toggle_maximize) {
        const nextState = await window.pywebview.api.toggle_maximize();
        if (typeof nextState === 'boolean') {
          windowMaximized = nextState;
          render();
        }
      }
    }

    async function openApiLink() {
      if (window.pywebview && window.pywebview.api && window.pywebview.api.open_external) {
        await window.pywebview.api.open_external(apiKeyUrl);
        return;
      }
      window.open(apiKeyUrl, '_blank');
    }

    async function openWebsiteLink() {
      if (!websiteUrl) return;
      if (window.pywebview && window.pywebview.api && window.pywebview.api.open_external) {
        await window.pywebview.api.open_external(websiteUrl);
        return;
      }
      window.open(websiteUrl, '_blank');
    }

    window.addEventListener('DOMContentLoaded', () => {
      hotkeyActionIds.forEach((action) => {
        if (!allowedHotkeys[state.hotkeys[action]]) {
          state.hotkeys[action] = '';
        }
      });
      state.hotkey_mode = inferHotkeyModeJs();
      document.getElementById('apiInput').value = state.api_key || '';
      document.getElementById('licenseInput').value = state.license_code || '';
      document.getElementById('modeApiCard').onclick = () => { state.mode = 'api'; render(); };
      document.getElementById('modeLicenseCard').onclick = () => { state.mode = 'license'; render(); };
      document.getElementById('showButton').onclick = () => {
        const input = document.getElementById('apiInput');
        input.type = input.type === 'password' ? 'text' : 'password';
        render();
      };
      document.getElementById('settingsToggleButton').onclick = () => toggleSettings();
      document.getElementById('openSettingsButton').onclick = () => toggleSettings(true);
      document.getElementById('settingsDoneButton').onclick = () => toggleSettings(false);
      document.getElementById('settingsBackdrop').onclick = () => toggleSettings(false);
      document.getElementById('hotkeysResetButton').onclick = resetHotkeysToDefault;
      document.getElementById('startupScreenToggle').onclick = () => {
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
      document.getElementById('pasteButton').onclick = pasteKey;
      document.getElementById('linkButton').onclick = openApiLink;
      document.getElementById('windowBrandLink').onclick = openWebsiteLink;
      document.getElementById('titleButton').onclick = openWebsiteLink;
      document.getElementById('minimizeButton').onclick = minimizeWindow;
      document.getElementById('maximizeButton').onclick = toggleMaximize;
      document.getElementById('closeChromeButton').onclick = exitApp;
      document.getElementById('cancelButton').onclick = closeWindow;
      document.getElementById('continueButton').onclick = submit;
      document.getElementById('apiInput').addEventListener('input', () => { state.error_message = ''; setText('errorText', ''); });
      document.getElementById('licenseInput').addEventListener('input', () => {
        if (currentLockoutSeconds() <= 0) {
          state.error_message = '';
          setText('errorText', '');
        }
      });
      document.addEventListener('keydown', (event) => {
        if (captureHotkey(event)) return;
        if (event.key === 'Escape') {
          if (settingsOpen) toggleSettings(false);
          else closeWindow();
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
      ensureLockoutTicker();
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


def prompt_startup_auth(
    initial_server_url,
    initial_license,
    initial_api_key,
    initial_blob_size="medium",
    initial_mode="api",
    initial_error="",
    prefer_legacy=False,
):
    _ = initial_server_url
    startup_progress_hide()
    initial_lockout_seconds = 0
    initial_lockout_hard = False
    if str(initial_mode or "").strip().lower() == "license":
        initial_lockout_seconds, initial_lockout_hard = get_live_pro_auth_lockout_state()
    initial_state = {
        "mode": "license" if str(initial_mode or "").strip().lower() == "license" else "api",
        "language": normalize_language(ui_language),
        "theme": normalize_theme_preference(ui_theme_preference),
        "blob_size": normalize_indicator_blob_size(initial_blob_size),
        "indicator_position": normalize_indicator_position(indicator_position_key),
        "show_startup_screen": bool(startup_loading_screen_enabled),
        "pro_model": normalize_pro_model(selected_pro_model_key),
        "hotkeys": dict(command_hotkeys),
        "hotkey_mode": command_key_mode,
        "api_key": str(initial_api_key or ""),
        "license_code": str(initial_license or ""),
        "error_message": str(initial_error or ""),
        "lockout_seconds": int(max(0, initial_lockout_seconds)),
        "lockout_hard": bool(initial_lockout_hard),
    }
    result = None
    used_webview = False
    if webview is not None and not prefer_legacy:
        bridge = AuthShellBridge()
        try:
            running_on_main_thread = current_thread().name == "MainThread"
            can_attach_to_existing_gui = bool(getattr(webview, "guilib", None))
            if running_on_main_thread or can_attach_to_existing_gui:
                window = webview.create_window(
                    tr("auth.window_title", language=initial_state["language"]),
                    html=build_auth_shell_html(initial_state),
                    js_api=bridge,
                    width=1260,
                    height=760,
                    min_size=(920, 640),
                    resizable=True,
                    background_color="#081321",
                    frameless=True,
                    easy_drag=False,
                    shadow=True,
                    vibrancy=bool(os.name == "nt"),
                    text_select=False,
                )
                bridge.bind_window(window)
                used_webview = True
                if can_attach_to_existing_gui:
                    result = bridge.wait()
                elif running_on_main_thread:
                    webview.start(debug=False, private_mode=True)
                    result = bridge.result
                else:
                    result = bridge.wait()
        except Exception:
            logger.exception("Auth webview flow failed; falling back to Tk setup window.")
            result = None
    if used_webview:
        startup_progress_show()
        return result
    if result is None:
        result = prompt_startup_auth_legacy(
            initial_server_url,
            initial_license,
            initial_api_key,
            initial_blob_size,
            initial_mode=initial_mode,
            initial_error=initial_error,
        )
        if result:
            result.setdefault("language", normalize_language(ui_language))
            result.setdefault("theme", normalize_theme_preference(ui_theme_preference))
            result.setdefault("indicator_position", normalize_indicator_position(indicator_position_key))
            result.setdefault("show_startup_screen", bool(startup_loading_screen_enabled))
            result.setdefault("pro_model", normalize_pro_model(selected_pro_model_key))
            result.setdefault("hotkeys", dict(command_hotkeys))
            result.setdefault("hotkey_mode", command_key_mode)
    startup_progress_show()
    return result


def indicator_refresh_preferences():
    indicator_call(lambda obj: obj.refresh_preferences() if hasattr(obj, "refresh_preferences") else None)


def open_settings_menu(hide_indicator_temporarily=False):
    global settings_window_open, command_hotkeys, command_hotkeys_customized, command_key_mode
    global startup_loading_screen_enabled, auth_mode, api_key, license_code
    global local_model, local_chat_session, api_backend_name, ui_theme_preference
    with settings_window_lock:
        if settings_window_open:
            return
        settings_window_open = True
    restore_indicator_after_close = False
    try:
        if hide_indicator_temporarily and indicator and not indicator.hidden:
            restore_indicator_after_close = True
            indicator_hide()
        record = load_config_record()
        saved_license = load_saved_secret(record, "license_code", "license_code_dpapi")
        saved_api_key = load_saved_secret(record, "api_key", "api_key_dpapi")
        selected = prompt_startup_auth(
            initial_server_url=DEFAULT_SERVER_URL,
            initial_license=license_code or saved_license,
            initial_api_key=api_key or saved_api_key,
            initial_blob_size=indicator_blob_size_key,
            initial_mode=auth_mode,
        )
        if not selected:
            return

        auth_changed = False
        next_mode = "license" if str(selected.get("mode", "")).strip().lower() == "license" else "api"
        next_license = str(selected.get("license_code", "") or "").strip()
        next_api_key = str(selected.get("api_key", "") or "").strip()
        live_api_key_change = (
            auth_mode == "api"
            and next_mode == "api"
            and bool(next_api_key)
            and next_api_key != api_key
        )
        if next_mode != auth_mode:
            auth_changed = True
        elif next_mode == "license" and next_license and next_license != license_code:
            auth_changed = True
        elif next_mode == "api" and next_api_key and next_api_key != api_key and not live_api_key_change:
            auth_changed = True

        record["ui_language"] = normalize_language(selected.get("language", ui_language))
        record["ui_theme"] = normalize_theme_preference(selected.get("theme", ui_theme_preference))
        record["indicator_blob_size"] = normalize_indicator_blob_size(selected.get("blob_size", indicator_blob_size_key))
        record["indicator_position"] = normalize_indicator_position(selected.get("indicator_position", indicator_position_key))
        record["show_startup_screen"] = normalize_startup_loading_screen_enabled(selected.get("show_startup_screen", startup_loading_screen_enabled))
        record["pro_model"] = normalize_pro_model(selected.get("pro_model", selected_pro_model_key))
        saved_hotkeys, saved_hotkey_mode, saved_hotkeys_customized = resolve_command_hotkey_state(
            selected.get("hotkeys"),
            selected.get("hotkey_mode", command_key_mode),
        )
        record["command_hotkeys"] = dict(saved_hotkeys)
        record["command_key_mode"] = saved_hotkey_mode
        record["command_hotkeys_customized"] = bool(saved_hotkeys_customized)
        record["auth_mode"] = next_mode
        live_api_key_applied = False
        if live_api_key_change:
            previous_api_key = str(api_key or "")
            previous_runtime = (local_model, local_chat_session, api_backend_name)
            api_key = next_api_key
            license_code = ""
            if ensure_api_mode_ready():
                if not save_secret(record, "api_key", "api_key_dpapi", next_api_key):
                    show_styled_message(APP_NAME, tr("error.save_api"), is_error=True, parent=None)
                    api_key = previous_api_key
                    local_model, local_chat_session, api_backend_name = previous_runtime
                    ensure_api_mode_ready()
                    return
                live_api_key_applied = True
            else:
                api_key = previous_api_key
                license_code = ""
                local_model, local_chat_session, api_backend_name = previous_runtime
                if previous_api_key:
                    ensure_api_mode_ready()
                return

        if next_mode == "license" and next_license:
            if not save_secret(record, "license_code", "license_code_dpapi", next_license):
                show_styled_message(APP_NAME, tr("error.save_code"), is_error=True, parent=None)
                return
        elif next_mode == "api" and next_api_key and not live_api_key_applied:
            if not save_secret(record, "api_key", "api_key_dpapi", next_api_key):
                show_styled_message(APP_NAME, tr("error.save_api"), is_error=True, parent=None)
                return
        else:
            save_config_record(record)

        globals()["ui_language"] = normalize_language(record.get("ui_language", ui_language))
        globals()["ui_theme_preference"] = normalize_theme_preference(record.get("ui_theme", ui_theme_preference))
        globals()["indicator_blob_size_key"] = normalize_indicator_blob_size(record.get("indicator_blob_size", indicator_blob_size_key))
        globals()["indicator_position_key"] = normalize_indicator_position(record.get("indicator_position", indicator_position_key))
        globals()["startup_loading_screen_enabled"] = normalize_startup_loading_screen_enabled(record.get("show_startup_screen", startup_loading_screen_enabled))
        globals()["selected_pro_model_key"] = normalize_pro_model(record.get("pro_model", selected_pro_model_key))
        apply_ui_theme_preference(ui_theme_preference)
        command_hotkeys = dict(saved_hotkeys)
        command_hotkeys_customized = bool(saved_hotkeys_customized)
        command_key_mode = saved_hotkey_mode
        if live_api_key_applied:
            auth_mode = "api"
            api_key = next_api_key
            license_code = ""
        set_command_key_mode(command_key_mode)
        update_tray_menu()
        indicator_refresh_preferences()
        if not auth_changed and next_mode == "license":
            push_remote_preferences()

        if auth_changed:
            show_styled_message(
                APP_NAME,
                "Settings saved. Restart EyesAndEars to apply sign-in changes.",
                is_error=False,
                parent=indicator.root if indicator and indicator.root.winfo_exists() else None,
            )
    finally:
        if restore_indicator_after_close and not indicator_manual_hidden and not privacy_forced_hidden:
            indicator_show()
        with settings_window_lock:
            settings_window_open = False


def gui_ask_retry_license(message):
    parent = indicator.root if indicator and indicator.root.winfo_exists() else None
    splash = startup_progress_window
    splash_was_visible = False
    if parent is None and splash is not None:
        # During startup the loading screen is always-on-top, so the error
        # dialog would appear hidden behind it.  Hide the splash first and
        # use its root as the dialog parent (Toplevel instead of a second
        # tk.Tk) so the dialog is properly visible and the event loop works.
        try:
            if splash.root.winfo_exists() and not splash.hidden:
                splash_was_visible = True
                splash.hide()
                parent = splash.root
        except Exception:
            pass
    result = show_styled_message(APP_NAME, f"{message}\n\n{tr('error.license_retry')}", ask_retry=True, parent=parent)
    if splash_was_visible:
        startup_progress_show()
    return result


def gui_show_error(message):
    parent = indicator.root if indicator and indicator.root.winfo_exists() else None
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
    try:
        window = getattr(startup_progress_window, "root", None)
        if window is not None:
            apply_capture_privacy_to_window(window, enabled=active)
    except Exception:
        pass
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
    global auth_mode, server_url, license_code, api_key, device_id, indicator_blob_size_key
    global ui_language, indicator_position_key, selected_pro_model_key, session_status_text
    global command_hotkeys, command_hotkeys_customized, command_key_mode, startup_loading_screen_enabled
    global ui_theme_preference
    record = load_config_record()
    env_license = os.environ.get("EAE_LICENSE_CODE", "").strip()
    env_api_key = find_env_api_key()
    env_language_raw = os.environ.get("EAE_LANGUAGE", "").strip()
    env_theme_raw = os.environ.get("EAE_THEME", "").strip()
    env_blob_size_raw = os.environ.get("EAE_BLOB_SIZE", "").strip()
    env_position_raw = os.environ.get("EAE_INDICATOR_POSITION", "").strip()
    env_startup_screen_raw = os.environ.get("EAE_SHOW_STARTUP_SCREEN", "").strip()
    env_blob_size = normalize_indicator_blob_size(env_blob_size_raw) if env_blob_size_raw else ""
    saved_license = load_saved_secret(record, "license_code", "license_code_dpapi")
    saved_api_key = load_saved_secret(record, "api_key", "api_key_dpapi")
    saved_blob_size = normalize_indicator_blob_size(record.get("indicator_blob_size", ""))
    saved_language = normalize_language(record.get("ui_language", ui_language))
    saved_theme = normalize_theme_preference(record.get("ui_theme", ui_theme_preference))
    saved_position = normalize_indicator_position(record.get("indicator_position", indicator_position_key))
    saved_startup_screen = normalize_startup_loading_screen_enabled(record.get("show_startup_screen", startup_loading_screen_enabled))
    saved_pro_model = normalize_pro_model(record.get("pro_model", selected_pro_model_key))
    saved_auth_mode = "license" if str(record.get("auth_mode", "")).strip().lower() == "license" else "api"
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
    clear_startup_preflight_license_auth()

    ui_language = normalize_language(env_language_raw or saved_language or ui_language)
    ui_theme_preference = normalize_theme_preference(env_theme_raw or saved_theme or ui_theme_preference)
    apply_ui_theme_preference(ui_theme_preference)
    indicator_position_key = normalize_indicator_position(env_position_raw or saved_position or indicator_position_key)
    startup_loading_screen_enabled = normalize_startup_loading_screen_enabled(env_startup_screen_raw) if env_startup_screen_raw else saved_startup_screen
    selected_pro_model_key = normalize_pro_model(saved_pro_model)
    command_hotkeys = dict(saved_hotkeys)
    command_hotkeys_customized = bool(saved_hotkeys_customized)
    command_key_mode = saved_hotkey_mode
    session_status_text = tr("status.not_authenticated")

    initial_blob_size = env_blob_size or saved_blob_size or indicator_blob_size_key
    initial_mode = saved_auth_mode
    if env_license and not env_api_key:
        initial_mode = "license"
    elif env_api_key and not env_license:
        initial_mode = "api"
    startup_progress_update("startup.opening_setup")
    selected = prompt_startup_auth(
        initial_server_url=DEFAULT_SERVER_URL,
        initial_license=env_license or saved_license,
        initial_api_key=env_api_key or saved_api_key,
        initial_blob_size=initial_blob_size,
        initial_mode=initial_mode,
    )
    if not selected:
        return False

    selected_blob_size = normalize_indicator_blob_size(selected.get("blob_size", initial_blob_size))
    record["indicator_blob_size"] = selected_blob_size
    indicator_blob_size_key = selected_blob_size
    ui_language = normalize_language(selected.get("language", ui_language))
    ui_theme_preference = normalize_theme_preference(selected.get("theme", ui_theme_preference))
    indicator_position_key = normalize_indicator_position(selected.get("indicator_position", indicator_position_key))
    selected_pro_model_key = normalize_pro_model(selected.get("pro_model", selected_pro_model_key))
    selected_hotkeys, selected_hotkey_mode, selected_hotkeys_customized = resolve_command_hotkey_state(
        selected.get("hotkeys"),
        selected.get("hotkey_mode", command_key_mode),
    )
    record["ui_language"] = ui_language
    record["ui_theme"] = ui_theme_preference
    record["indicator_position"] = indicator_position_key
    record["show_startup_screen"] = normalize_startup_loading_screen_enabled(selected.get("show_startup_screen", startup_loading_screen_enabled))
    startup_loading_screen_enabled = bool(record["show_startup_screen"])
    record["pro_model"] = selected_pro_model_key
    record["command_hotkeys"] = dict(selected_hotkeys)
    record["command_key_mode"] = selected_hotkey_mode
    record["command_hotkeys_customized"] = bool(selected_hotkeys_customized)
    command_hotkeys = dict(selected_hotkeys)
    command_key_mode = selected_hotkey_mode
    command_hotkeys_customized = bool(selected_hotkeys_customized)
    apply_ui_theme_preference(ui_theme_preference)

    selected_mode = selected["mode"]
    if selected_mode == "license":
        selected_server = normalize_server_url(DEFAULT_SERVER_URL) or DEFAULT_SERVER_URL
        selected_license = selected["license_code"]
        record["auth_mode"] = "license"
        record["server_url"] = selected_server
        if not save_secret(record, "license_code", "license_code_dpapi", selected_license):
            gui_show_error(tr("error.save_code"))
            return False
        auth_mode = "license"
        server_url = selected_server
        license_code = selected_license
        api_key = ""
    else:
        selected_api_key = selected["api_key"]
        record["auth_mode"] = "api"
        if not save_secret(record, "api_key", "api_key_dpapi", selected_api_key):
            gui_show_error(tr("error.save_api"))
            return False
        auth_mode = "api"
        api_key = selected_api_key
        license_code = ""

    record["device_id"] = saved_device_id
    save_config_record(record)
    device_id = saved_device_id
    return True


def request_json(method, path, token="", json_payload=None, files=None, timeout=30):
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
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        return HTTP_SESSION.request(
            method=method,
            url=url,
            headers=headers,
            json=json_payload,
            files=files,
            timeout=timeout,
            allow_redirects=False,
        )
    except requests.RequestException:
        logger.warning("HTTP request failed for %s %s.", str(method or "").upper(), normalized_path, exc_info=True)
        raise
    except Exception:
        logger.exception("Unexpected error while sending %s %s.", str(method or "").upper(), normalized_path)
        raise


def build_remote_preferences_payload():
    return {
        "language": normalize_language(ui_language),
        "indicator_position": normalize_indicator_position(indicator_position_key),
        "indicator_blob_size": normalize_indicator_blob_size(indicator_blob_size_key),
        "show_startup_screen": bool(startup_loading_screen_enabled),
        "pro_model": normalize_pro_model(selected_pro_model_key),
        "hotkey_mode": command_key_mode,
        "hotkeys": dict(command_hotkeys),
    }


def persist_runtime_preferences():
    record = load_config_record()
    record["ui_language"] = normalize_language(ui_language)
    record["ui_theme"] = normalize_theme_preference(ui_theme_preference)
    record["indicator_blob_size"] = normalize_indicator_blob_size(indicator_blob_size_key)
    record["indicator_position"] = normalize_indicator_position(indicator_position_key)
    record["show_startup_screen"] = normalize_startup_loading_screen_enabled(startup_loading_screen_enabled)
    record["pro_model"] = normalize_pro_model(selected_pro_model_key)
    record["command_hotkeys"] = dict(command_hotkeys)
    record["command_key_mode"] = command_key_mode
    record["command_hotkeys_customized"] = bool(command_hotkeys_customized)
    save_config_record(record)


def apply_remote_preferences_payload(payload):
    global ui_language, indicator_position_key, indicator_blob_size_key
    global selected_pro_model_key, startup_loading_screen_enabled
    global command_hotkeys, command_hotkeys_customized, command_key_mode
    if not isinstance(payload, dict):
        return False

    ui_language = normalize_language(payload.get("language", ui_language))
    indicator_position_key = normalize_indicator_position(payload.get("indicator_position", indicator_position_key))
    indicator_blob_size_key = normalize_indicator_blob_size(payload.get("indicator_blob_size", indicator_blob_size_key))
    startup_loading_screen_enabled = normalize_startup_loading_screen_enabled(
        payload.get("show_startup_screen", startup_loading_screen_enabled)
    )
    selected_pro_model_key = normalize_pro_model(payload.get("pro_model", selected_pro_model_key))
    remote_hotkeys, remote_hotkey_mode, remote_hotkeys_customized = resolve_command_hotkey_state(
        payload.get("hotkeys"),
        payload.get("hotkey_mode", command_key_mode),
    )
    command_hotkeys = dict(remote_hotkeys)
    command_key_mode = remote_hotkey_mode
    command_hotkeys_customized = bool(remote_hotkeys_customized)
    persist_runtime_preferences()
    try:
        set_command_key_mode(command_key_mode)
    except Exception:
        pass
    return True


def push_remote_preferences():
    with session_lock:
        local_token = str(session_token or "")
        local_active = bool(session_active)
    if auth_mode != "license" or not local_token or not local_active:
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


def pull_remote_preferences():
    with session_lock:
        local_token = str(session_token or "")
    if auth_mode != "license" or not local_token:
        return None, ""

    try:
        response = request_json("GET", "/api/v1/client/preferences", token=local_token, timeout=15)
        if not response.ok:
            return None, ""
        data = decode_json_response(response, "Remote preferences")
    except Exception:
        logger.debug("Remote preference pull failed.", exc_info=True)
        return None, ""

    if not isinstance(data, dict):
        return None, ""
    return data.get("preferences"), str(data.get("preferences_updated_at", "") or "")


def sync_remote_preferences_after_auth(auth_data):
    remote_payload = auth_data.get("preferences") if isinstance(auth_data, dict) else None
    remote_updated_at = str(auth_data.get("preferences_updated_at", "") or "") if isinstance(auth_data, dict) else ""
    if remote_payload is None:
        remote_payload, remote_updated_at = pull_remote_preferences()
    if isinstance(remote_payload, dict) and (remote_updated_at or remote_payload):
        apply_remote_preferences_payload(remote_payload)
        return True
    return push_remote_preferences()


def authenticate_license_session():
    global session_id, session_token, user_email, license_hint
    global heartbeat_interval_seconds, heartbeat_timeout_seconds
    data = consume_startup_preflight_license_auth(license_code, device_id)
    if data is None:
        ok, message, data, _reason = perform_license_auth_request(license_code, device_id)
        if not ok:
            return False, message

    with session_lock:
        session_id = data.get("session_id", "")
        session_token = data.get("session_token", "")
        user_email = data.get("user_email", "")
        license_hint = data.get("license_hint", "")
        heartbeat_interval_seconds = int(data.get("heartbeat_interval_seconds", 20))
        heartbeat_timeout_seconds = int(data.get("heartbeat_timeout_seconds", 90))
    sync_remote_preferences_after_auth(data if isinstance(data, dict) else {})
    set_session_status(tr("status.code_active"), active=True)
    return True, tr("startup.ready")


def ensure_license_mode_ready():
    global server_url, license_code, indicator_blob_size_key
    global ui_language, indicator_position_key, selected_pro_model_key, startup_loading_screen_enabled
    global command_hotkeys, command_key_mode, command_hotkeys_customized
    while True:
        ok, message = run_startup_background_task(authenticate_license_session, stage_key="startup.connecting_pro")
        if ok:
            return True
        set_session_status(tr("status.code_disconnected", detail=message), active=False)
        selected = prompt_startup_auth(
            server_url,
            license_code,
            "",
            indicator_blob_size_key,
            initial_mode="license",
            initial_error=message,
        )
        if not selected or selected.get("mode") != "license":
            return False
        server_url = normalize_server_url(DEFAULT_SERVER_URL) or DEFAULT_SERVER_URL
        license_code = selected["license_code"]
        indicator_blob_size_key = normalize_indicator_blob_size(selected.get("blob_size", indicator_blob_size_key))
        ui_language = normalize_language(selected.get("language", ui_language))
        indicator_position_key = normalize_indicator_position(selected.get("indicator_position", indicator_position_key))
        selected_pro_model_key = normalize_pro_model(selected.get("pro_model", selected_pro_model_key))
        selected_hotkeys, selected_hotkey_mode, selected_hotkeys_customized = resolve_command_hotkey_state(
            selected.get("hotkeys"),
            selected.get("hotkey_mode", command_key_mode),
        )
        record = load_config_record()
        record["auth_mode"] = "license"
        record["server_url"] = server_url
        record["indicator_blob_size"] = indicator_blob_size_key
        record["ui_language"] = ui_language
        record["indicator_position"] = indicator_position_key
        record["show_startup_screen"] = normalize_startup_loading_screen_enabled(selected.get("show_startup_screen", startup_loading_screen_enabled))
        record["pro_model"] = selected_pro_model_key
        record["command_hotkeys"] = dict(selected_hotkeys)
        record["command_key_mode"] = selected_hotkey_mode
        record["command_hotkeys_customized"] = bool(selected_hotkeys_customized)
        command_hotkeys = dict(selected_hotkeys)
        command_key_mode = selected_hotkey_mode
        command_hotkeys_customized = bool(selected_hotkeys_customized)
        startup_loading_screen_enabled = bool(record["show_startup_screen"])
        if not save_secret(record, "license_code", "license_code_dpapi", license_code):
            gui_show_error(tr("error.save_code"))
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


def initialize_api_runtime():
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

    backend_module.configure(api_key=api_key)
    generation_config = {"temperature": 0.0, "top_p": 1.0, "top_k": 1}
    model = backend_module.GenerativeModel(model_name, generation_config=generation_config)
    return {
        "backend_name": backend_name,
        "model": model,
        "chat_session": model.start_chat(history=[]),
    }


def ensure_api_mode_ready():
    global local_model, local_chat_session, api_backend_name
    if not api_key:
        gui_show_error(tr("error.api_empty"))
        return False
    try:
        runtime = run_startup_background_task(initialize_api_runtime, stage_key="startup.initializing_model")
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
    global auth_mode, api_key, license_code, indicator_blob_size_key
    global ui_language, indicator_position_key, selected_pro_model_key, startup_loading_screen_enabled
    global local_model, local_chat_session, api_backend_name
    global command_hotkeys, command_key_mode, command_hotkeys_customized

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
    show_styled_message(APP_NAME, message, is_error=True, parent=None)

    initial_api_key = str(api_key or "")
    while True:
        selected = prompt_startup_auth(
            initial_server_url=DEFAULT_SERVER_URL,
            initial_license="",
            initial_api_key=initial_api_key,
            initial_blob_size=indicator_blob_size_key,
        )
        if not selected:
            local_model = None
            local_chat_session = None
            api_backend_name = "none"
            api_key = ""
            set_session_status(tr("status.api_required"), active=False)
            exit_program(trigger_uninstall=False)
            return False
        if selected.get("mode") != "api":
            show_styled_message(
                APP_NAME,
                tr("error.api_select_mode"),
                is_error=True,
                parent=None,
            )
            initial_api_key = str(selected.get("api_key", "") or initial_api_key)
            continue

        selected_api_key = str(selected.get("api_key", "")).strip()
        if not selected_api_key:
            show_styled_message(APP_NAME, tr("auth.validation.api.empty"), is_error=True, parent=None)
            continue

        selected_blob_size = normalize_indicator_blob_size(selected.get("blob_size", indicator_blob_size_key))
        ui_language = normalize_language(selected.get("language", ui_language))
        indicator_position_key = normalize_indicator_position(selected.get("indicator_position", indicator_position_key))
        selected_pro_model_key = normalize_pro_model(selected.get("pro_model", selected_pro_model_key))
        selected_hotkeys, selected_hotkey_mode, selected_hotkeys_customized = resolve_command_hotkey_state(
            selected.get("hotkeys"),
            selected.get("hotkey_mode", command_key_mode),
        )
        record = load_config_record()
        record["auth_mode"] = "api"
        record["indicator_blob_size"] = selected_blob_size
        record["ui_language"] = ui_language
        record["indicator_position"] = indicator_position_key
        record["show_startup_screen"] = normalize_startup_loading_screen_enabled(selected.get("show_startup_screen", startup_loading_screen_enabled))
        record["pro_model"] = selected_pro_model_key
        record["command_hotkeys"] = dict(selected_hotkeys)
        record["command_key_mode"] = selected_hotkey_mode
        record["command_hotkeys_customized"] = bool(selected_hotkeys_customized)
        if not save_secret(record, "api_key", "api_key_dpapi", selected_api_key):
            show_styled_message(APP_NAME, tr("error.save_api"), is_error=True, parent=None)
            return False

        auth_mode = "api"
        api_key = selected_api_key
        license_code = ""
        indicator_blob_size_key = selected_blob_size
        command_hotkeys = dict(selected_hotkeys)
        command_key_mode = selected_hotkey_mode
        command_hotkeys_customized = bool(selected_hotkeys_customized)
        startup_loading_screen_enabled = bool(record["show_startup_screen"])
        initial_api_key = selected_api_key

        if ensure_api_mode_ready():
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
        logger.debug("Remote session shutdown request failed.", exc_info=True)


def heartbeat_loop():
    while True:
        with session_lock:
            local_interval = int(heartbeat_interval_seconds)
            local_active = session_active
            local_session_id = session_id
            local_session_token = session_token
        if heartbeat_stop_event.wait(max(8, local_interval)):
            break
        if auth_mode != "license":
            continue
        if not local_active or not local_session_token:
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
                set_session_status(tr("status.code_session_lost"), active=False)
                disable_typing_mode()
                indicator_set_idle()
        except Exception:
            set_session_status(tr("status.code_network_error"), active=False)
            disable_typing_mode()
            indicator_set_idle()


def start_heartbeat():
    global heartbeat_thread
    if heartbeat_thread is not None and heartbeat_thread.is_alive():
        return
    heartbeat_stop_event.clear()
    heartbeat_thread = Thread(target=heartbeat_loop, daemon=True)
    heartbeat_thread.start()


def list_running_process_snapshot():
    global process_snapshot_cache_at, process_snapshot_cache_running, process_snapshot_cache_pid
    running_names = set()
    pid_to_name = {}
    if os.name != "nt":
        return running_names, pid_to_name
    now = time.monotonic()
    with process_snapshot_cache_lock:
        if process_snapshot_cache_running and (now - process_snapshot_cache_at) < PROCESS_SNAPSHOT_CACHE_SECONDS:
            return set(process_snapshot_cache_running), dict(process_snapshot_cache_pid)
    if psutil is not None:
        try:
            for proc in psutil.process_iter(attrs=("pid", "name")):
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
        if STRICT_PRIVACY_FALLBACK and is_capture_privacy_active():
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
    if privacy_guard_thread is not None and privacy_guard_thread.is_alive():
        return
    privacy_guard_stop_event.clear()
    privacy_guard_thread = Thread(target=privacy_guard_loop, daemon=True)
    privacy_guard_thread.start()


class StatusIndicator:
    def __init__(self):
        ensure_ui_crisp_mode()
        self.root = tk.Tk()
        apply_tk_scaling(self.root)
        self.root.overrideredirect(True)
        self.root.attributes("-topmost", True)
        try:
            self.root.attributes("-toolwindow", True)
        except Exception:
            pass
        self.transparent_color = "#00F7E7"
        self.window_bg = "#040912"
        self.panel_bg = "#06111D"
        self.panel_outline = "#163454"
        try:
            self.root.wm_attributes("-transparentcolor", self.transparent_color)
            self.root.configure(bg=self.transparent_color)
        except Exception:
            self.transparent_color = None
            self.root.configure(bg=self.window_bg)

        self.hidden = False
        self.command_mode = str(command_key_mode).strip().lower() or "numpad"
        self.state = "idle"
        self.current_char = ""
        self.answer_preview = ""
        self.answer_progress_index = 0
        self.answer_preview_expires_at = 0.0
        self.cooldown_until = 0.0
        self.hover_inside = False
        self.frame_after_id = None
        self.collapse_after_id = None
        self.animation_after_id = None
        self.click_after_id = None
        self.ready_pulse_started_at = 0.0
        self.base_size = int(INDICATOR_BLOB_SIZES.get(indicator_blob_size_key, INDICATOR_BLOB_SIZES["medium"]))
        self.collapsed_padding = max(2, int(round(self.base_size * 0.14)))
        self.expanded_chip_padding = max(4, int(round(self.base_size * 0.18)))
        self.collapsed_width = self.base_size + (self.collapsed_padding * 2)
        self.collapsed_height = self.collapsed_width
        self.square_corner_radius = compute_indicator_chip_corner_radius(self.collapsed_width)
        self.panel_corner_radius = max(14, int(self.base_size * 0.95))
        self.panel_padding = max(14, int(self.base_size * 0.7))
        self.gap = max(12, int(self.base_size * 0.65))
        self.chip_corner_radius = compute_indicator_chip_corner_radius(self.base_size)
        self.current_width = self.collapsed_width
        self.current_height = self.collapsed_height
        self.target_width = self.collapsed_width
        self.target_height = self.collapsed_height
        self._last_render_signature = None
        self.body_font = tkfont.Font(root=self.root, family=UI_FONT, size=max(9, int(round(self.base_size * 0.55))))
        self.char_font = tkfont.Font(root=self.root, family=UI_FONT, size=max(8, int(round(self.base_size * 0.42))), weight="bold")
        self.control_hint_text = self._build_control_hint_text()
        self.max_panel_width = max(340, min(560, int(self.root.winfo_screenwidth() * 0.34)))
        self.canvas = tk.Canvas(
            self.root,
            width=self.current_width,
            height=self.current_height,
            highlightthickness=0,
            bd=0,
            bg=self.transparent_color or self.window_bg,
        )
        self.canvas.pack(fill="both", expand=True)
        self.canvas.bind("<Enter>", self._on_hover_enter, add="+")
        self.canvas.bind("<Leave>", self._on_hover_leave, add="+")
        self.canvas.bind("<Button-1>", self._on_click_toggle)
        self.canvas.bind("<Double-Button-1>", self._on_double_click)
        self.root.bind("<Enter>", self._on_hover_enter, add="+")
        self.root.bind("<Leave>", self._on_hover_leave, add="+")
        self.root.bind("<Double-Button-1>", self._on_double_click, add="+")
        self.root.bind("<Destroy>", self._on_destroy, add="+")
        configure_private_window(self.root, dark=True, translucent=False, refresh_ms=1200)
        self._set_geometry(self.collapsed_width, self.collapsed_height)
        self._apply_window_rounding()
        self._apply_capture_privacy()
        self._schedule_frame_tick()
        self.set_idle()

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
            return max(0, int(bbox[2] - bbox[0])), max(0, int(bbox[3] - bbox[1]))
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
        height = int(max(self.collapsed_height + 44, text_height + (self.panel_padding * 2) + bottom_reserve))
        return width, height

    def _desired_size(self):
        if self._should_show_panel() and (self.answer_preview or self.state in {"idle", "cooldown"}):
            return self._desired_panel_size()
        return self.collapsed_width, self.collapsed_height

    def _should_show_panel(self):
        return bool(self.hover_inside or self._is_pointer_inside())

    def _is_expanded(self):
        return self.current_width > self.collapsed_width + 4 or self.current_height > self.collapsed_height + 4

    def _ready_burst_active(self):
        return self.state == "ready" and (time.monotonic() - self.ready_pulse_started_at) <= INDICATOR_READY_BURST_SECONDS

    def _render_signature(self, antialias):
        panel_text = str(self._panel_text() or "")
        text_signature = (len(panel_text), panel_text[:48], panel_text[-48:] if len(panel_text) > 48 else "")
        pulse_bucket = 0
        if self.state == "processing":
            pulse_bucket = int(round(self._pulse_value() * 24))
        elif self._ready_burst_active():
            pulse_bucket = int(max(0, (time.monotonic() - self.ready_pulse_started_at) * 1000.0) // 40)
        cooldown_bucket = self._cooldown_seconds_remaining()
        return (
            int(self.current_width),
            int(self.current_height),
            bool(self._is_expanded()),
            str(self.state),
            str(self.current_char),
            int(self.answer_progress_index),
            text_signature,
            int(antialias),
            int(pulse_bucket),
            int(cooldown_bucket),
        )

    def _chip_corner_radius_for_size(self, chip_size):
        return max(4, min(int(self.chip_corner_radius), compute_indicator_chip_corner_radius(chip_size)))

    def _active_ring_specs(self):
        if self.state == "processing":
            return [("processing", 0.35 + (0.65 * self._pulse_value()))]
        if self.state == "cooldown":
            return [("cooldown", 0.42 + (0.58 * self._pulse_value()))]
        if self.state == "ready":
            elapsed = max(0.0, time.monotonic() - self.ready_pulse_started_at)
            specs = []
            for offset in (0.0, 0.15):
                age = elapsed - offset
                if 0.0 <= age <= 0.22:
                    specs.append(("ready", max(0.0, 1.0 - (age / 0.22))))
            return specs
        return []

    def _draw_chip(self, x1, y1, x2, y2, fill, outline, antialias=1, width=1):
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
        if not accent_color:
            return
        available_pad = min(
            int(max(0, x1)),
            int(max(0, y1)),
            int(max(0, self.current_width - x2 - 1)),
            int(max(0, self.current_height - y2 - 1)),
        )
        if available_pad <= 0:
            return
        for ring_kind, strength in self._active_ring_specs():
            pad = max(1, min(available_pad, int(round(1 + (available_pad * strength)))))
            if ring_kind == "processing":
                alpha = 64
            elif ring_kind == "cooldown":
                alpha = int(72 * strength)
            else:
                alpha = int(58 * strength)
            draw_rounded_canvas_rect(
                self.canvas,
                x1 - pad,
                y1 - pad,
                x2 + pad,
                y2 + pad,
                self._chip_corner_radius_for_size((x2 - x1 + 1) + (pad * 2)),
                fill="",
                outline=hex_to_rgba(accent_color, alpha),
                width=1,
                antialias=max(2, antialias),
            )

    def _set_state(self, state_name):
        self.state = state_name
        if state_name == "ready":
            self.ready_pulse_started_at = time.monotonic()
        self._sync_target_size()
        self._redraw()

    def _sync_target_size(self):
        target_width, target_height = self._desired_size()
        self.target_width = target_width
        self.target_height = target_height
        self._ensure_animation()

    def _ensure_animation(self):
        if self.animation_after_id is None:
            self.animation_after_id = self.root.after(0, self._animate_step)

    def _animate_step(self):
        self.animation_after_id = None
        
        def _next(current, target):
            if current == target:
                return current
            delta = target - current
            step = max(1, int(abs(delta) * 0.34))
            if delta < 0:
                step = -step
            candidate = current + step
            if (delta > 0 and candidate > target) or (delta < 0 and candidate < target):
                return target
            return candidate

        next_width = _next(self.current_width, self.target_width)
        next_height = _next(self.current_height, self.target_height)
        self._set_geometry(next_width, next_height)
        animating = next_width != self.target_width or next_height != self.target_height
        self._apply_window_rounding()
        self._redraw(antialias=1 if animating else 2)
        if animating:
            self.animation_after_id = self.root.after(16, self._animate_step)
        else:
            self._apply_capture_privacy()

    def _schedule_frame_tick(self):
        if self.frame_after_id is None:
            self.frame_after_id = self.root.after(42, self._frame_tick)

    def _frame_tick(self):
        self.frame_after_id = None
        if not self.hidden and (self.state == "processing" or self._ready_burst_active()):
            self._redraw(antialias=1 if not self._is_expanded() else 2)
        if self.answer_preview_expires_at > 0 and time.monotonic() >= self.answer_preview_expires_at:
            self.clear_answer_preview()
        if self.state == "cooldown":
            if self.cooldown_until > 0 and time.monotonic() >= self.cooldown_until:
                self.clear_cooldown()
            else:
                self._redraw(antialias=1 if not self._is_expanded() else 2)
        self._schedule_frame_tick()

    def _set_geometry(self, width, height):
        self.current_width = int(max(1, width))
        self.current_height = int(max(1, height))
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        work_left, work_top, work_right, work_bottom = get_work_area_bounds(screen_width, screen_height)
        x, y = compute_indicator_origin(work_left, work_top, work_right, work_bottom, self.current_width, self.current_height, indicator_position_key)
        self.root.geometry(f"{self.current_width}x{self.current_height}+{x}+{y}")
        self.canvas.configure(width=self.current_width, height=self.current_height)

    def _apply_capture_privacy(self):
        global indicator_capture_protected
        if not is_capture_privacy_active():
            indicator_capture_protected = False
            apply_capture_privacy_to_window(self.root, enabled=False)
            return
        try:
            indicator_capture_protected = bool(apply_capture_privacy_to_window(self.root, enabled=True))
        except Exception:
            indicator_capture_protected = False

    def refresh_capture_privacy(self):
        self._apply_capture_privacy()
        self._redraw(force=True)

    def _apply_window_rounding(self):
        if os.name != "nt":
            return
        radius = self.square_corner_radius if not self._is_expanded() else self.panel_corner_radius
        apply_window_corner_region(self.root, radius)

    def _on_destroy(self, _event=None):
        for attr_name in ("frame_after_id", "collapse_after_id", "animation_after_id", "click_after_id"):
            after_id = getattr(self, attr_name, None)
            if after_id:
                try:
                    self.root.after_cancel(after_id)
                except Exception:
                    pass
            setattr(self, attr_name, None)

    def _pulse_value(self):
        now = time.monotonic()
        if self.state == "processing":
            return 0.48 + (0.32 * ((math.sin(now * 5.2) + 1.0) / 2.0))
        if self.state == "cooldown":
            return 0.56 + (0.24 * ((math.sin(now * 6.0) + 1.0) / 2.0))
        if self.state == "ready":
            elapsed = max(0.0, now - self.ready_pulse_started_at)
            if elapsed <= INDICATOR_READY_BURST_SECONDS:
                return 0.78 + (0.12 * ((math.sin(elapsed * 15.0) + 1.0) / 2.0))
            return 0.82
        if self.state == "paused":
            return 0.7
        return 0.3

    def _state_palette(self):
        if self.state == "processing":
            return "#7A4709", "#FFB34C", "#FF8C1A"
        if self.state == "cooldown":
            return "#825118", "#FFBF63", "#FF9624"
        if self.state == "ready":
            return "#0F5A31", "#57F09D", "#1FD16D"
        if self.state == "paused":
            return "#5F6878", "#9BAEC8", ""
        return "#636A74", "#98A0AB", ""

    def _chip_rect(self, expanded):
        chip_size = self.base_size + (self.expanded_chip_padding if expanded else 0)
        chip_side = self._anchor_side()
        if not expanded:
            return 0, 0, min(self.current_width, self.current_height)
        y = self.current_height - self.panel_padding - chip_size - 2
        if expanded and chip_side == "left":
            x = self.panel_padding + 2
        else:
            x = self.current_width - self.panel_padding - chip_size - 2
        return x, y, chip_size

    def _collapsed_chip_bounds(self, pulse):
        full_size = min(self.current_width, self.current_height)
        if self.state == "processing":
            core_scale = 0.78 + (0.1 * pulse)
        elif self.state == "ready":
            core_scale = 0.86 + (0.06 * max(0.0, pulse - 0.78))
        elif self.state == "paused":
            core_scale = 0.82
        else:
            core_scale = 0.86
        core_size = int(round(full_size * core_scale))
        min_size = max(8, self.base_size)
        max_size = max(min_size, full_size - 2)
        core_size = max(min_size, min(core_size, max_size))
        inset = max(1, int(round((full_size - core_size) / 2.0)))
        x1 = inset
        y1 = inset
        x2 = full_size - inset - 1
        y2 = full_size - inset - 1
        return x1, y1, x2, y2

    def _expanded_chip_bounds(self, chip_x, chip_y, chip_size, pulse):
        if self.state == "processing":
            core_scale = 0.8 + (0.08 * pulse)
        elif self.state == "ready":
            core_scale = 0.86 + (0.06 * max(0.0, pulse - 0.78))
        elif self.state == "paused":
            core_scale = 0.82
        else:
            core_scale = 0.86
        core_size = int(round(chip_size * core_scale))
        min_size = max(10, int(round(chip_size * 0.7)))
        max_size = max(min_size, chip_size - 2)
        core_size = max(min_size, min(core_size, max_size))
        inset = max(1, int(round((chip_size - core_size) / 2.0)))
        x1 = chip_x + inset
        y1 = chip_y + inset
        x2 = chip_x + chip_size - inset - 1
        y2 = chip_y + chip_size - inset - 1
        return x1, y1, x2, y2

    def _draw_progress_bar(self):
        if not self.answer_preview:
            return
        total = len(self.answer_preview)
        if total <= 0:
            return
        fraction = max(0.0, min(1.0, float(self.answer_progress_index) / float(total)))
        bar_width = max(80, self.current_width - (self.panel_padding * 2))
        x1 = self.panel_padding
        y1 = self.current_height - max(12, int(self.panel_padding * 0.85))
        x2 = x1 + bar_width
        self.canvas.create_line(x1, y1, x2, y1, fill="#243B63", width=3, capstyle=tk.ROUND)
        self.canvas.create_line(x1, y1, x1 + int(bar_width * fraction), y1, fill="#FF5F5F", width=3, capstyle=tk.ROUND)

    def _redraw(self, antialias=2, force=False):
        expanded = self._is_expanded()
        effective_antialias = 1 if not expanded else max(1, int(antialias))
        render_signature = self._render_signature(effective_antialias)
        if not force and render_signature == self._last_render_signature:
            return
        self._last_render_signature = render_signature

        self.canvas.delete("all")
        self.canvas._eae_image_refs = []
        if expanded:
            draw_rounded_canvas_rect(
                self.canvas,
                0,
                0,
                self.current_width - 1,
                self.current_height - 1,
                self.panel_corner_radius,
                fill=self.panel_bg,
                outline=self.panel_outline,
                antialias=max(1, effective_antialias),
            )

        pulse = self._pulse_value()
        chip_fill, chip_outline, chip_accent = self._state_palette()
        if not expanded:
            chip_x1, chip_y1, chip_x2, chip_y2 = self._collapsed_chip_bounds(pulse)
            self._draw_chip(chip_x1, chip_y1, chip_x2, chip_y2, chip_fill, chip_outline, antialias=1, width=1)
            if chip_accent:
                self._draw_active_rings(chip_x1, chip_y1, chip_x2, chip_y2, chip_accent, antialias=2)
            chip_x = chip_x1
            chip_y = chip_y1
            chip_size = max(1, chip_x2 - chip_x1 + 1)
        else:
            chip_x, chip_y, chip_size = self._chip_rect(expanded)
            core_x1, core_y1, core_x2, core_y2 = self._expanded_chip_bounds(chip_x, chip_y, chip_size, pulse)
            self._draw_chip(
                core_x1,
                core_y1,
                core_x2,
                core_y2,
                chip_fill,
                chip_outline,
                antialias=max(1, effective_antialias),
                width=1,
            )
            if chip_accent:
                self._draw_active_rings(core_x1, core_y1, core_x2, core_y2, chip_accent, antialias=max(2, effective_antialias))
        display_char = self._display_char()
        if display_char:
            self.canvas.create_text(
                chip_x + (chip_size / 2),
                chip_y + (chip_size / 2),
                text=display_char.upper(),
                fill="white",
                font=self.char_font,
            )
        elif self.state == "paused":
            bar_width = max(2, int(chip_size * 0.16))
            gap = max(2, int(chip_size * 0.12))
            x_mid = chip_x + (chip_size / 2)
            y1 = chip_y + int(chip_size * 0.26)
            y2 = chip_y + int(chip_size * 0.74)
            self.canvas.create_rectangle(x_mid - gap - bar_width, y1, x_mid - gap, y2, fill="white", outline="")
            self.canvas.create_rectangle(x_mid + gap, y1, x_mid + gap + bar_width, y2, fill="white", outline="")
        text = self._panel_text()
        if expanded and text:
            chip_side = self._anchor_side()
            text_width = max(220, self.current_width - (self.panel_padding * 2) - chip_size - self.gap - 20)
            if chip_side == "left":
                text_x = chip_x + chip_size + self.gap
            else:
                text_x = self.panel_padding
            text_y = self.panel_padding + 2
            self.canvas.create_text(
                text_x,
                text_y,
                text=text,
                fill="#EAF3FF",
                font=self.body_font,
                anchor="nw",
                justify="left",
                width=text_width,
            )
            if self.answer_preview and self.answer_progress_index > 0:
                self.canvas.create_text(
                    text_x,
                    text_y,
                    text=self.answer_preview[: self.answer_progress_index],
                    fill="#FF6E6E",
                    font=self.body_font,
                    anchor="nw",
                    justify="left",
                    width=text_width,
                )
            if self.answer_preview:
                self._draw_progress_bar()

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
        if self.hidden or self.hover_inside or self._is_pointer_inside():
            return
        self.target_width = self.collapsed_width
        self.target_height = self.collapsed_height
        self._ensure_animation()

    def _on_hover_enter(self, _event):
        if self.hidden:
            return
        self.hover_inside = True
        self._cancel_scheduled_collapse()
        if self.state in {"idle", "cooldown"} or self.answer_preview:
            self._sync_target_size()

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
        expanded = self.current_width > self.collapsed_width + 4
        if expanded:
            self.hover_inside = False
            self._collapse_if_possible()
        else:
            self.hover_inside = True
            self._sync_target_size()

    def _on_double_click(self, _event=None):
        if self.click_after_id is not None:
            try:
                self.root.after_cancel(self.click_after_id)
            except Exception:
                pass
            self.click_after_id = None
        Thread(target=lambda: open_settings_menu(hide_indicator_temporarily=True), daemon=True).start()

    def set_command_mode(self, mode):
        self.command_mode = "toprow" if str(mode or "").strip().lower() == "toprow" else "numpad"
        self.control_hint_text = self._build_control_hint_text()
        self._sync_target_size()
        self._redraw()

    def refresh_preferences(self):
        self.base_size = int(INDICATOR_BLOB_SIZES.get(indicator_blob_size_key, INDICATOR_BLOB_SIZES["medium"]))
        self.collapsed_padding = max(2, int(round(self.base_size * 0.14)))
        self.expanded_chip_padding = max(4, int(round(self.base_size * 0.18)))
        self.collapsed_width = self.base_size + (self.collapsed_padding * 2)
        self.collapsed_height = self.collapsed_width
        self.square_corner_radius = compute_indicator_chip_corner_radius(self.collapsed_width)
        self.panel_corner_radius = max(14, int(self.base_size * 0.95))
        self.panel_padding = max(14, int(self.base_size * 0.7))
        self.gap = max(12, int(self.base_size * 0.65))
        self.chip_corner_radius = compute_indicator_chip_corner_radius(self.base_size)
        self.body_font.configure(size=max(9, int(round(self.base_size * 0.55))))
        self.char_font.configure(size=max(8, int(round(self.base_size * 0.42))))
        self.max_panel_width = max(340, min(560, int(self.root.winfo_screenwidth() * 0.34)))
        self._last_render_signature = None
        self._sync_target_size()
        self._set_geometry(self.current_width, self.current_height)
        self._redraw(force=True)

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
        self.answer_preview = text
        self.answer_progress_index = typed_index
        self.answer_preview_expires_at = time.monotonic() + ANSWER_PREVIEW_RETENTION_SECONDS if text and typed_index >= len(text) else 0.0
        self._sync_target_size()
        self._redraw(force=True)

    def clear_answer_preview(self):
        if not self.answer_preview and self.answer_progress_index == 0:
            return
        self.answer_preview = ""
        self.answer_progress_index = 0
        self.answer_preview_expires_at = 0.0
        self._sync_target_size()
        self._redraw(force=True)

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

    def clear_cooldown(self):
        if self.cooldown_until <= 0 and self.state != "cooldown":
            return
        self.cooldown_until = 0.0
        self.current_char = ""
        if self.state == "cooldown":
            self._set_state("idle")
        else:
            self._redraw(force=True)

    def hide(self):
        if not self.hidden:
            self._cancel_scheduled_collapse()
            self.root.withdraw()
            self.hidden = True

    def show(self):
        if self.hidden:
            self.root.deiconify()
            self.root.attributes("-topmost", True)
            self._apply_window_rounding()
            self._apply_capture_privacy()
            self.hidden = False
            self._last_render_signature = None
            self._redraw(force=True)

    def run(self):
        self.root.mainloop()


def init_indicator():
    global indicator
    indicator = StatusIndicator()
    indicator.run()


def indicator_call(func):
    local_indicator = indicator
    if not local_indicator:
        return

    def _invoke():
        try:
            func(local_indicator)
        except Exception:
            logger.debug("Indicator callback failed.", exc_info=True)

    try:
        local_indicator.root.after(0, _invoke)
    except Exception:
        logger.debug("Indicator callback scheduling failed.", exc_info=True)


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
    indicator_call(lambda obj: obj.set_answer_progress(value, typed_count))


def indicator_clear_answer_preview():
    indicator_call(lambda obj: obj.clear_answer_preview())


def indicator_set_command_mode(mode):
    indicator_call(lambda obj: obj.set_command_mode(mode))


def indicator_hide():
    indicator_call(lambda obj: obj.hide())


def indicator_show():
    if privacy_forced_hidden:
        return
    indicator_call(lambda obj: obj.show())


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
    if not indicator:
        return
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
    if pystray is None:
        return
    tray_icon = pystray.Icon(
        "EyesAndEars",
        build_tray_image(),
        "EyesAndEars",
        pystray.Menu(
            pystray.MenuItem(tr("tray.open"), tray_open_ui),
            pystray.MenuItem(tray_status_label, None, enabled=False),
            pystray.MenuItem(tr("tray.toggle"), tray_toggle_indicator),
            pystray.MenuItem(tray_capture_privacy_label, tray_toggle_capture_privacy),
            pystray.MenuItem(tr("tray.check_updates"), tray_check_updates),
            pystray.MenuItem(tr("tray.quit"), tray_exit),
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


def get_command_action_from_scan(scan_code, mode=None):
    local_mode = str(mode or command_key_mode).strip().lower()
    if local_mode == "toprow":
        return TOPROW_SCAN_TO_ACTION.get(int(scan_code), "")
    return NUMPAD_SCAN_TO_ACTION.get(int(scan_code), "")


def get_numpad_action(event):
    return get_hotkey_action(event)


def stop_command_mode_probe():
    global command_mode_probe_hook
    if command_mode_probe_hook is None:
        return
    try:
        keyboard.unhook(command_mode_probe_hook)
    except Exception:
        pass
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
    if keyboard.is_pressed("ctrl") or keyboard.is_pressed("alt") or keyboard.is_pressed("win"):
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
        try:
            keyboard.unhook(hook)
        except Exception:
            pass
    command_key_hooks = []


def dispatch_hotkey_action(action, event=None):
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


def on_command_key_event(event):
    if event is None:
        return True
    if getattr(event, "event_type", "") != "down":
        return True
    action = get_hotkey_action(event)
    if not action:
        return True
    dispatch_hotkey_action(action, event=event)
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
        command_key_hooks = [keyboard.hook(on_command_key_event, suppress=True)]
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
    if event.event_type != "down":
        return
    action = get_numpad_action(event)
    if action:
        dispatch_hotkey_action(action, event=event)
        return
    key_name = str(getattr(event, "name", "") or "").strip().lower()
    if not is_character_like_key(key_name):
        deactivate_post_type_guard()


def post_type_guard_watch_loop():
    while not post_type_guard_stop.wait(0.07):
        with post_type_guard_lock:
            if not post_type_guard_active:
                return
            local_until = float(post_type_guard_until)
            origin = post_type_guard_mouse
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
        try:
            keyboard.unhook(hook_to_remove)
        except Exception:
            pass
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
        keyboard.unhook(typing_hook)
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
    if not indicator:
        return
    if indicator.hidden:
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
    if auth_mode == "api":
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
        keyboard.write(remaining)
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
    if is_ctrl_modifier_pressed():
        schedule_manual_winget_uninstall("EyesAndEars")
        exit_program(trigger_uninstall=False)
        return
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


def encode_capture_for_license_upload(screenshot):
    try:
        upload_image = screenshot if screenshot.mode == "RGB" else screenshot.convert("RGB")
        stream = io.BytesIO()
        upload_image.save(stream, format="JPEG", quality=FAST_UPLOAD_JPEG_QUALITY, optimize=False)
        return "capture.jpg", stream.getvalue(), "image/jpeg"
    except Exception:
        stream = io.BytesIO()
        screenshot.save(stream, format="PNG")
        return "capture.png", stream.getvalue(), "image/png"


def infer_via_license_server(upload_file, local_token):
    file_name, file_bytes, mime_type = upload_file
    files = {"file": (file_name, file_bytes, mime_type)}
    response = request_json("POST", "/api/v1/client/infer", token=local_token, files=files, timeout=80)
    if response.status_code == 401:
        set_session_status(tr("status.code_expired"), active=False)
        raise RuntimeError("Session expired or invalid.")
    response.raise_for_status()
    payload = decode_json_response(response, "License inference")
    if not isinstance(payload, dict):
        raise RuntimeError(f"Server returned an unexpected response ({response.status_code}).")
    return str(payload.get("text", ""))


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
    local_token = ""
    try:
        if auth_mode == "license":
            with session_lock:
                local_active = session_active
                local_token = session_token
            if not local_active or not local_token:
                set_session_status(tr("status.code_inactive"), active=False)
                disable_typing_mode()
                indicator_set_idle()
                gui_show_error(tr("error.session_inactive"))
                return

        is_paused = False
        disable_typing_mode()
        indicator_set_processing()
        screenshot = PIL.ImageGrab.grab()
        try:
            if auth_mode == "license":
                upload_file = encode_capture_for_license_upload(screenshot)
                raw_text = infer_via_license_server(upload_file, local_token)
            else:
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
        logger.exception("Screenshot processing failed.")
        if auth_mode == "api":
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
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": f"{APP_NAME}/{APP_VERSION}",
    }
    response = HTTP_SESSION.get(DEFAULT_RELEASES_API_URL, headers=headers, timeout=12, allow_redirects=False)
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
    return {
        "version": str(payload.get("tag_name", "") if isinstance(payload, dict) else "").strip().lstrip("vV"),
        "release_url": str(payload.get("html_url", "") if isinstance(payload, dict) else "").strip() or DEFAULT_RELEASES_PAGE_URL,
        "download_url": str((exe_asset or {}).get("browser_download_url", "")).strip(),
        "asset_name": str((exe_asset or {}).get("name", "")).strip(),
    }


def powershell_single_quote(value):
    return "'" + str(value or "").replace("'", "''") + "'"


def cleanup_data_dir_command():
    try:
        target = Path(APP_DATA_DIR).resolve()
    except Exception:
        return ""
    target_text = str(target).strip()
    if not target_text:
        return ""
    return f'if exist "{target_text}" rmdir /s /q "{target_text}"'


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
    package_id = resolve_winget_package_id() or "FediMust.EyesAndEars"
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
    package_id = resolve_winget_package_id() or "FediMust.EyesAndEars"
    cleanup_command = cleanup_data_dir_command()
    uninstall_script = Path(tempfile.gettempdir()) / f"eyesandears-manual-uninstall-{secrets.token_hex(8)}.cmd"
    script_lines = [
        "@echo off",
        f"timeout /t {SELF_UNINSTALL_DELAY_SECONDS} /nobreak >nul",
        f"winget uninstall --name \"{query}\" --exact --silent --disable-interactivity --accept-source-agreements",
        "if errorlevel 1 (",
        f"  winget uninstall --id \"{package_id}\" --exact --purge --silent --disable-interactivity --accept-source-agreements",
        ")",
    ]
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


def schedule_self_uninstall():
    package_id = resolve_winget_package_id()
    if not package_id:
        return False
    cleanup_command = cleanup_data_dir_command()
    uninstall_script = Path(tempfile.gettempdir()) / f"eyesandears-self-uninstall-{secrets.token_hex(8)}.cmd"
    script_lines = [
        "@echo off",
        f"timeout /t {SELF_UNINSTALL_DELAY_SECONDS} /nobreak >nul",
        f"winget uninstall --id \"{package_id}\" --exact --purge --silent --disable-interactivity --accept-source-agreements",
    ]
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
    heartbeat_stop_event.set()
    privacy_guard_stop_event.set()
    stop_command_mode_probe()
    if auth_mode == "license":
        end_remote_session()
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
    os._exit(0)


def on_smart_type(event):
    global current_index
    scan_code = get_event_scan_code(event)
    action = get_numpad_action(event)
    if action:
        if event.event_type == "down":
            dispatch_hotkey_action(action, event=event)
        elif event.event_type == "up" and scan_code > 0:
            with typing_pressed_lock:
                typing_pressed_scancodes.discard(scan_code)
        return
    if event.event_type == "up":
        if scan_code > 0:
            with typing_pressed_lock:
                typing_pressed_scancodes.discard(scan_code)
        return
    if event.event_type != "down":
        return
    key_name = str(getattr(event, "name", "") or "").strip().lower()
    if not is_character_like_key(key_name):
        return
    if keyboard.is_pressed("ctrl") or keyboard.is_pressed("alt") or keyboard.is_pressed("win"):
        return
    if write_lock.locked():
        return
    if scan_code > 0:
        with typing_pressed_lock:
            if scan_code in typing_pressed_scancodes:
                return
            typing_pressed_scancodes.add(scan_code)
    if current_answer and current_index < len(current_answer):
        progress_answer = ""
        progress_index = 0
        with write_lock:
            # Re-check inside the lock: another thread may have cleared the answer
            # between the outer check above and acquiring the lock here.
            if not current_answer or current_index >= len(current_answer):
                return
            char = current_answer[current_index]
            keyboard.write(char, delay=0)
            current_index += 1
            progress_index = current_index
            progress_answer = current_answer
        push_indicator_progress(progress_answer, progress_index, force=(progress_index >= len(progress_answer)))
        if current_index >= len(progress_answer):
            disable_typing_mode()
            clear_answer_state()
            activate_post_type_guard(POST_TYPE_GUARD_SECONDS)


def main():
    global indicator_manual_hidden
    apply_ui_theme_preference(os.environ.get("EAE_THEME", ui_theme_preference))
    ensure_ui_crisp_mode()
    hide_console_window()
    startup_progress_update("startup.launching")
    startup_progress_update("startup.restoring")
    if not resolve_auth_settings():
        startup_progress_close()
        return
    startup_progress_update("startup.checking_auth")
    if not initialize_auth_mode():
        startup_progress_close()
        return
    if auth_mode == "license":
        start_heartbeat()

    startup_progress_update("startup.starting_indicator")
    indicator_thread = Thread(target=init_indicator, daemon=True)
    indicator_thread.start()
    startup_progress_wait(0.35)
    start_privacy_guard()
    indicator_manual_hidden = not INDICATOR_VISIBLE_BY_DEFAULT
    set_indicator_manual_visibility(indicator_manual_hidden)
    if pystray is not None:
        tray_thread = Thread(target=run_tray_icon, daemon=True)
        tray_thread.start()
    if AUTO_UPDATE_ENABLED:
        Thread(target=maybe_auto_update_on_startup, daemon=True).start()

    set_command_key_mode(command_key_mode)
    start_command_mode_probe()
    startup_progress_update("startup.ready")
    startup_progress_wait(0.28)
    startup_progress_close()
    keyboard.wait()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        try:
            exit_program(trigger_uninstall=False)
        except Exception:
            raise SystemExit(0)
