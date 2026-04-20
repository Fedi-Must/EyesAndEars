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


