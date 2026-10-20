"""Chaquopy entry point: launch the bundled Reconix server.

The Reconix tree is copied by MainActivity into app-private storage
before this is called, so every __file__-relative write in app.py
(scans.db, rules, inventory, screenshots) lands somewhere writable.
"""
import os
import sys
import traceback

_started = False


def start_server(workdir):
    global _started
    if _started:
        return "already running"
    _started = True
    try:
        os.chdir(workdir)
        if workdir not in sys.path:
            sys.path.insert(0, workdir)
        sys.argv = ["app.py", "--port", "8777"]
        import app as reconix_app
        reconix_app.main()
        return "server exited"
    except Exception:
        try:
            with open(os.path.join(workdir, "server-error.log"), "w") as fh:
                fh.write(traceback.format_exc())
        except Exception:
            pass
        traceback.print_exc()
        return "error"
    finally:
        # Always allow a later start_server() to actually restart the
        # engine (paired with the service-side worker reset in v1.4).
        _started = False
