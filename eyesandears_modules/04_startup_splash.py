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


