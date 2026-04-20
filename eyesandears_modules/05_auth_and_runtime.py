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


