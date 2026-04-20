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


