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


