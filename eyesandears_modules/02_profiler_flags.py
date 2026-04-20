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

