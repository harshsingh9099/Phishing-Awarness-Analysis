#!/usr/bin/env python3
"""
PhishGuard Triage - entry point.

    python main.py analyze data/samples/phishing_sample_1.eml
    python main.py analyze data/samples/safe_sample_1.eml --format all
"""

import sys

from src.cli import main

if __name__ == "__main__":
    sys.exit(main())
