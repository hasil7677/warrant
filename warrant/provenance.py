"""
provenance.py
─────────────
Every result-producing run writes a stamped artifact. Non-optional.

Why this exists: a governance claim is only worth what its evidence is worth,
and evidence transcribed by hand out of a terminal is worth nothing. The
precedent is concrete - on a sibling project the headline evaluation figures
could not be reproduced months later. The code had not changed; eighteen
parameter combinations were tried and none matched. The numbers were not wrong
because something broke, they were unreconstructable because nothing linked them
to the run that produced them. Someone read a number off a screen and typed it
into a markdown file.

So an artifact stamps the code (git SHA + dirty flag + which files are dirty),
the environment (interpreter and library versions), and the full config,
alongside the result. A config dump alone is not enough: a dirty tree means the
SHA does not identify the code that ran, which is exactly the hole that produced
the unreproducible headline.

The point is to make this structural rather than remembered. `write_artifact` is
called unconditionally by the eval runner - there is no --no-artifact flag,
because the 2am-before-a-deadline version of anyone will use it.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

ARTIFACT_DIR = Path(os.getenv("WARRANT_ARTIFACT_DIR", "artifacts"))


def git_sha() -> dict[str, Any]:
    """Current commit and whether the tree is dirty. A dirty tree means the
    SHA alone does not identify the code that ran - which is exactly the hole
    that produced the unreproducible headline."""
    repo = Path(__file__).resolve().parents[1]

    def _git(*args: str) -> Optional[str]:
        try:
            out = subprocess.run(
                ["git", *args], cwd=repo, capture_output=True, text=True, timeout=10
            )
            return out.stdout.strip() if out.returncode == 0 else None
        except (OSError, subprocess.SubprocessError):
            return None

    sha = _git("rev-parse", "HEAD")
    status = _git("status", "--porcelain")
    return {
        "sha": sha,
        "dirty": bool(status) if status is not None else None,
        "dirty_files": status.splitlines()[:20] if status else [],
    }


def file_digest(path: Path, chunk: int = 1 << 20) -> Optional[str]:
    """SHA-256 of a file, or None if it isn't there.

    Used to pin inputs that live outside the repo - policy.yaml above all. A
    policy file is the consent in this system, and an artifact that names the
    policy without digesting it cannot tell you whether the policy was edited
    between the run and the reading.
    """
    if not path.exists():
        return None
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while block := fh.read(chunk):
            h.update(block)
    return h.hexdigest()


def redact_path(p: Any) -> str:
    """Replace the user's home directory with ~ so artifacts are publishable.

    Artifacts are meant to be committed and cited, so they must not carry the
    machine's username around in absolute paths.
    """
    s = str(p)
    try:
        home = str(Path.home())
        for variant in (home, home.replace("\\", "/")):
            if variant and variant in s:
                s = s.replace(variant, "~")
    except (OSError, RuntimeError):
        pass
    return s.replace("\\", "/")


def environment() -> dict[str, Any]:
    """Interpreter and the libraries that can change behaviour between runs.

    Each import is wrapped: a missing module yields None rather than raising,
    because provenance must never be the reason a run fails. An artifact that
    records "googleapiclient: null" is still telling you something true about
    the machine that produced the result.
    """
    versions: dict[str, Optional[str]] = {}
    for mod in ("anthropic", "googleapiclient", "yaml"):
        try:
            versions[mod] = getattr(__import__(mod), "__version__", None)
        except Exception:
            versions[mod] = None
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "packages": versions,
    }


def write_artifact(
    kind: str,
    config: dict[str, Any],
    result: dict[str, Any],
    out_dir: Optional[Path] = None,
    extra: Optional[dict[str, Any]] = None,
) -> Path:
    """Write a stamped run artifact and return its path.

    Cite this file in docs instead of transcribing numbers out of it.
    """
    out_dir = Path(out_dir or ARTIFACT_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    artifact = {
        "kind": kind,
        "created_utc": now.isoformat(timespec="seconds"),
        "git": git_sha(),
        "environment": environment(),
        "config": config,
        "result": result,
        **(extra or {}),
    }
    dest = out_dir / f"{kind}_{now.strftime('%Y%m%dT%H%M%SZ')}.json"
    payload = json.dumps(artifact, indent=2, default=str)
    # Belt and braces: redact any home-directory path that reached the config or
    # result dicts by another route (e.g. a caller passing an absolute path).
    try:
        home = str(Path.home())
        for variant in (home, home.replace("\\", "\\\\"), home.replace("\\", "/")):
            if variant:
                payload = payload.replace(variant, "~")
    except (OSError, RuntimeError):
        pass
    dest.write_text(payload, encoding="utf-8")
    return dest
