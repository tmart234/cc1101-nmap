#!/usr/bin/env python3
"""Compatibility entry point; the scanner lives in the cc1101nmap package.

    ./evilcrow_scanner.py --help
    python3 -m cc1101nmap --backend sim      # demo without hardware
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cc1101nmap.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
