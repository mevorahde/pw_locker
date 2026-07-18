"""Shared filesystem locations for Password Locker interfaces."""

from pathlib import Path


def default_vault_path() -> Path:
    """Return the user-local default vault path."""
    return Path.home() / ".password_locker" / "vault.db"
