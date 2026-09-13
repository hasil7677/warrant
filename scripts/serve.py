"""
serve.py
--------
Start the console, killing whatever already holds the port.

uvicorn does not replace a process that is already bound - it logs
"only one usage of each socket address" to stderr and exits, leaving the OLD
server running and answering. Every health check still returns 200, so a
restart can silently not happen and you spend an hour debugging behaviour the
code no longer has.

This frees the port first, so "restart" means restart.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000


def pids_on(port: int) -> list[str]:
    try:
        out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True).stdout
    except OSError:
        return []
    found = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[-1].isdigit() and f":{port}" in parts[1] \
                and "LISTENING" in line:
            found.append(parts[-1])
    return sorted(set(found))


def main() -> int:
    for pid in pids_on(PORT):
        print(f"  port {PORT} held by pid {pid}, terminating")
        subprocess.run(["taskkill", "/F", "/PID", pid],
                       capture_output=True, text=True)
        time.sleep(1)

    if pids_on(PORT):
        print(f"  could not free port {PORT}. Close it by hand and retry.")
        return 1

    print(f"  starting console on http://127.0.0.1:{PORT}\n")
    return subprocess.call(
        [sys.executable, "-m", "uvicorn", "server.app:app",
         "--host", "127.0.0.1", "--port", str(PORT)],
        cwd=ROOT,
    )


if __name__ == "__main__":
    raise SystemExit(main())
