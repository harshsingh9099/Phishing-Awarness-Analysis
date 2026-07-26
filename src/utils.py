"""
Shared utilities: config loading, string-distance metrics, and logging setup.

Kept dependency-free (no external Levenshtein package) so the toolkit installs
cleanly in locked-down / air-gapped analyst environments.
"""

from __future__ import annotations

import logging
import os
from functools import lru_cache
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "rules.yaml"
DEFAULT_LOG_DIR = PROJECT_ROOT / "logs"


@lru_cache(maxsize=1)
def load_config(config_path: str | Path = DEFAULT_CONFIG_PATH) -> Dict[str, Any]:
    """
    Load and cache the YAML rules configuration.

    Raises a clear, non-leaking error if the file is missing or malformed
    rather than letting a raw traceback (with local file paths) surface.
    """
    path = Path(config_path)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except FileNotFoundError as exc:
        raise RuntimeError(
            "Configuration file not found. Ensure config/rules.yaml exists."
        ) from exc
    except yaml.YAMLError as exc:
        raise RuntimeError(
            "Configuration file is not valid YAML. Please check formatting."
        ) from exc

    if not isinstance(data, dict):
        raise RuntimeError("Configuration file is empty or malformed.")
    return data


def levenshtein_distance(a: str, b: str) -> int:
    """
    Classic iterative Levenshtein (edit) distance, O(len(a)*len(b)) time,
    O(min(len(a), len(b))) space. Used for typosquat detection
    (e.g. 'amaz0n' vs 'amazon').
    """
    a, b = a.lower(), b.lower()
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    if len(b) == 0:
        return len(a)

    previous_row = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current_row = [i]
        for j, char_b in enumerate(b, start=1):
            insertions = previous_row[j] + 1
            deletions = current_row[j - 1] + 1
            substitutions = previous_row[j - 1] + (char_a != char_b)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def get_logger(name: str = "phishguard") -> logging.Logger:
    """
    Configure a rotating-file + console logger. Never logs full email bodies
    or attachment contents -- only metadata (filenames, domains, verdicts) --
    to avoid persisting sensitive payload data on disk.
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger  # already configured (avoid duplicate handlers)

    logger.setLevel(logging.INFO)

    os.makedirs(DEFAULT_LOG_DIR, exist_ok=True)
    log_file = DEFAULT_LOG_DIR / "phishguard.log"

    file_handler = RotatingFileHandler(
        log_file, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
    )
    file_formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    file_handler.setFormatter(file_formatter)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)  # keep console clean; details go to file
    console_handler.setFormatter(file_formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger


def safe_str(value: Any, max_len: int = 500) -> str:
    """
    Defensive string coercion used before displaying/logging any user-supplied
    email content. Truncates to bound memory/log size and strips control
    characters that could be used for terminal-injection / log-forging.
    """
    text = "" if value is None else str(value)
    cleaned = "".join(ch for ch in text if ch.isprintable() or ch in "\n\t")
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len] + "...[truncated]"
    return cleaned
