"""
Phishlet loader utilities.

This module discovers and loads phishlet JSON files from the `phishlets/`
directory by default, with optional overrides via environment variables or
explicit parameters. It caches results for efficient reuse and provides helper
APIs to query by name or by host.

Example:
    from phishlet_loder import get_phishlets, get_phishlet_by_name

    phishlets = get_phishlets()
    fluxx = get_phishlet_by_name("fluxxset.com")
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union


# Default directory where phishlet JSON files reside
# Align with project-level `evilpunch/phishlets/` directory (one level above this file's directory)
DEFAULT_PHISHLETS_DIR: Path = Path(__file__).resolve().parent.parent / "phishlets"

# Environment variable to override the directory
ENV_PHISHLETS_DIR: str = "PHISHLETS_DIR"

# Module-level cache: { phishlet_name: phishlet_data }
_phishlets_cache: Optional[Dict[str, Dict[str, Any]]] = None


def _resolve_phishlets_dir(directory: Optional[Union[Path, str]] = None) -> Path:
    """
    Resolve the phishlets directory in the following precedence order:
      1) Explicit function argument
      2) Environment variable PHISHLETS_DIR
      3) Default directory adjacent to this file: ./phishlets
    """
    if directory is not None:
        return Path(directory).expanduser().resolve()

    env_dir = os.getenv(ENV_PHISHLETS_DIR)
    if env_dir:
        return Path(env_dir).expanduser().resolve()

    return DEFAULT_PHISHLETS_DIR.resolve()


def _discover_phishlet_files(directory: Path) -> List[Path]:
    """
    Return a list of JSON file paths in the provided directory.
    Ignores non-files and non-JSON entries.
    """
    if not directory.exists() or not directory.is_dir():
        raise FileNotFoundError(
            f"Phishlets directory not found or not a directory: {directory}"
        )

    return sorted([p for p in directory.iterdir() if p.is_file() and p.suffix.lower() == ".json"])


def _load_phishlet_file(file_path: Path) -> Dict[str, Any]:
    """
    Load and minimally validate a single phishlet JSON file.
    Ensures the following keys are present if available in the spec:
      - name (string)
      - target_url (string)
      - hosts_to_proxy (list)
    Additional keys are accepted and preserved.
    """
    try:
        with file_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in phishlet file {file_path}: {e}") from e

    if not isinstance(data, dict):
        raise ValueError(f"Phishlet file must contain a JSON object: {file_path}")

    # Name: use explicit 'name' or infer from filename stem
    if "name" not in data or not isinstance(data.get("name"), str) or not data["name"].strip():
        data["name"] = file_path.stem

    # Normalize optional structures to sane defaults
    if "hosts_to_proxy" in data and not isinstance(data["hosts_to_proxy"], list):
        raise ValueError(
            f"Expected 'hosts_to_proxy' to be a list in {file_path}, got {type(data['hosts_to_proxy'])}"
        )

    return data


def load_phishlets(directory: Optional[Union[Path, str]] = None, *, clear_cache: bool = False) -> Dict[str, Dict[str, Any]]:
    """
    Discover and load all phishlet JSON files, returning a dict keyed by phishlet name.

    - directory: Optional path to override the phishlets directory
    - clear_cache: If True, clear in-memory cache before loading
    """
    global _phishlets_cache
    if clear_cache:
        _phishlets_cache = None

    if _phishlets_cache is not None and directory is None:
        return _phishlets_cache

    phishlets_dir = _resolve_phishlets_dir(directory)
    files = _discover_phishlet_files(phishlets_dir)

    loaded: Dict[str, Dict[str, Any]] = {}
    for file_path in files:
        phishlet = _load_phishlet_file(file_path)
        name = phishlet.get("name")
        if name in loaded:
            raise ValueError(
                f"Duplicate phishlet name '{name}' detected between files. Ensure unique 'name' fields."
            )
        loaded[name] = phishlet

    _phishlets_cache = loaded
    return loaded


def get_phishlets() -> Dict[str, Dict[str, Any]]:
    """Return cached phishlets, loading from default directory if needed."""
    global _phishlets_cache
    if _phishlets_cache is not None:
        return _phishlets_cache
    return load_phishlets()


def list_phishlet_names() -> List[str]:
    """Return a sorted list of available phishlet names."""
    return sorted(get_phishlets().keys())


def get_phishlet_by_name(name: str) -> Dict[str, Any]:
    """
    Return a phishlet by its name. Raises KeyError if not found.
    """
    phishlets = get_phishlets()
    if name not in phishlets:
        raise KeyError(f"Phishlet not found: {name}")
    return phishlets[name]


def get_phishlet_for_host(host: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    """
    Find and return the first phishlet that references the provided host in its
    'hosts_to_proxy' list. Returns a tuple of (phishlet_name, phishlet_data) or None.
    Matching is exact against the 'host' field of each entry.
    """
    normalized_host = host.strip().lower()
    for name, phishlet in get_phishlets().items():
        hosts_list = phishlet.get("hosts_to_proxy", []) or []
        if not isinstance(hosts_list, list):
            continue
        for entry in hosts_list:
            if not isinstance(entry, dict):
                continue
            entry_host = str(entry.get("host", "")).strip().lower()
            if entry_host and entry_host == normalized_host:
                return name, phishlet
    return None


__all__ = [
    "load_phishlets",
    "get_phishlets",
    "list_phishlet_names",
    "get_phishlet_by_name",
    "get_phishlet_for_host",
    "DEFAULT_PHISHLETS_DIR",
]

