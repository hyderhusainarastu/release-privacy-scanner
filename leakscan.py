#!/usr/bin/env python3
"""Run without installing: python3 -I leakscan.py [PATH ...]"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from release_privacy_scanner.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
