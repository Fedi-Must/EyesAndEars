from pathlib import Path

_MODULE_DIR = Path(__file__).resolve().parent / "eyesandears_modules"
_SECTION_FILES = (
    "01_bootstrap.py",
    "02_profiler_flags.py",
    "03_win32_core.py",
    "04_startup_splash.py",
    "05_auth_and_runtime.py",
    "06_api_core.py",
    "07_indicator_core.py",
    "08_runtime_main.py",
)


def _load_sections(target_globals):
    for file_name in _SECTION_FILES:
        section_path = _MODULE_DIR / file_name
        source = section_path.read_text(encoding="utf-8")
        exec(compile(source, str(section_path), "exec"), target_globals, target_globals)


_load_sections(globals())
