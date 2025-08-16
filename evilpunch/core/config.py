"""
Simple configuration loader for the project.

Usage:
    from config import get_config
    cfg = get_config()
    host = cfg["proxy_host"]

Environment overrides:
    - Set env var `REVERSE_PROXY_CONFIG_PATH` (or `CONFIG_PATH`) to point to a
      different JSON config file if needed.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional, Union


# Default config path lives at project_root/config/config.json
# This file is in project_root/core/config.py, so go one level up
DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "config.json"

_cached_config: Optional[Dict[str, Any]] = None


def _resolve_config_path(path: Optional[Union[str, Path]] = None) -> Path:
    """Resolve the config path using explicit arg, env vars, or default."""
    # Highest precedence: explicit function argument
    if path is not None:
        return Path(path).expanduser().resolve()

    # Next: environment variables
    env_path = (
        os.getenv("REVERSE_PROXY_CONFIG_PATH")
        or os.getenv("CONFIG_PATH")
    )
    if env_path:
        return Path(env_path).expanduser().resolve()

    # Fallback: default path relative to this file
    return DEFAULT_CONFIG_PATH.resolve()


def load_config(
    path: Optional[Union[str, Path]] = None,
    *,
    clear_cache: bool = False,
) -> Dict[str, Any]:
    """
    Load configuration from disk.

    - path: Optional explicit path to a JSON file.
    - clear_cache: If True, ignore any previously cached configuration.
    """
    global _cached_config
    if clear_cache:
        _cached_config = None

    if _cached_config is not None and path is None:
        # If cached and no explicit path provided, return the cached value
        return _cached_config

    config_path = _resolve_config_path(path)
    if not config_path.exists():
        raise FileNotFoundError(
            f"Config file not found at {config_path}. "
            f"Set REVERSE_PROXY_CONFIG_PATH or CONFIG_PATH to override."
        )

    try:
        with config_path.open("r", encoding="utf-8") as f:
            config_data = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in config file {config_path}: {e}") from e

    # Cache and return
    _cached_config = config_data
    return config_data


def get_config() -> Dict[str, Any]:
    """Get cached configuration, loading from default path if needed."""
    if _cached_config is not None:
        return _cached_config
    return load_config()


__all__ = [
    "load_config",
    "get_config",
    "DEFAULT_CONFIG_PATH",
]
