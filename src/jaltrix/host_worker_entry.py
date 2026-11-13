"""Absolute-path entry point for the independent optional host collector."""

import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from jaltrix.host_collector import main  # noqa: E402

if __name__ == "__main__":
    main()
