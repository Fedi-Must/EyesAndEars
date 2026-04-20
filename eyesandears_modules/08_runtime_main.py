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
