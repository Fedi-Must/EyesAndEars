import sys

from eyesandears_runtime import *  # noqa: F401,F403


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
