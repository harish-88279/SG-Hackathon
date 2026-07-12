#!/usr/bin/env python3
"""
SBOMGuard — one-command launcher.

    python run.py

Opens http://localhost:8000
"""
from __future__ import annotations

import os
import sys
import webbrowser
from pathlib import Path
from threading import Timer

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

PORT = 8000


def _open():
    webbrowser.open(f"http://localhost:{PORT}")


def main() -> None:
    try:
        import uvicorn  # noqa: F401
    except ImportError:
        print("Dependencies are missing. Install them with:\n")
        print("    pip install -r requirements.txt\n")
        sys.exit(1)

    # Make sure the dataset exists before the server tries to read it.
    from sbomguard import config
    if not config.DEPENDENCIES_FILE.exists():
        print("Sample dataset not found — generating it now...")
        import subprocess
        subprocess.run([sys.executable, str(ROOT / "data" / "generator" / "generate_data.py")],
                       check=True)
        print()

    dataset = os.getenv("SBOMGUARD_DATASET", "official")

    print("=" * 70)
    print("  SBOMGuard — Software Supply Chain Risk Scorer")
    print("  Societe Generale hackathon, PB-10")
    print("=" * 70)
    print(f"\n  Dataset: {dataset.upper()}"
          + ("   (the real sample data shipped with the challenge)"
             if dataset == "official" else "   (our own reconstruction)"))
    if dataset == "official":
        print("  Set SBOMGUARD_DATASET=synthetic to run on our reconstruction instead.")
    print(f"\n  Dashboard:  http://localhost:{PORT}")
    print(f"  API docs:   http://localhost:{PORT}/docs")
    print("\n  Try the demo: type CVE-2021-44228 into the War Room search box.")
    print("  Ctrl-C to stop.\n")

    Timer(1.5, _open).start()

    import uvicorn
    uvicorn.run("sbomguard.api:app", host="127.0.0.1", port=PORT, log_level="warning")


if __name__ == "__main__":
    main()
