"""Absolute entry point usable by systemd from source and installed packages."""

import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from jaltrix.collector import main

main()
