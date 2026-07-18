"""Widget-free session controller for the Password Locker GUI."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable

from .vault import (
    AccountNotFoundError,
    Vault,
    VaultAuthenticationError,
    VaultError,
    VaultFormatError,
    VaultValidationError,
)


DEFAULT_CLIPBOARD_CLEAR_SECONDS = 30


class GUIState(str, Enum):
    CREATE = "create"
    UNLOCK = "unlock"
    UNLOCKED = "unlocked"
    CLOSED = "closed"


@dataclass(frozen=True)
class ControllerResult:
    ok: bool
    message: str
    accounts: tuple[str, ...] = ()
    clear_secret_fields: bool = False


@dataclass(frozen=True)
class ControllerDependencies:
    clipboard_copy: Callable[[str], None]
    clipboard_paste: Callable[[], str]
    schedule: Callable[[int, Callable[[], None]], object]
    cancel_scheduled: Callable[[object], None]
    create_vault: Callable[[Path, str], Vault] = Vault.create
    open_vault: Callable[[Path, str], Vault] = Vault.open


class VaultGUIController:
    """Own one vault session and expose secret-safe GUI operations."""

    def __init__(
        self,
        vault_path: Path,
        dependencies: ControllerDependencies,
        *,
        clipboard_clear_seconds: int = DEFAULT_CLIPBOARD_CLEAR_SECONDS,
    ) -> None:
        self.vault_path = Path(vault_path)
        self._dependencies = dependencies
        self._clipboard_clear_ms = clipboard_clear_seconds * 1000
        self._vault: Vault | None = None
        self._scheduled_cleanup: object | None = None
        self._clipboard_secret: str | None = None
        self._cleanup_generation = 0
        self.state = (
            GUIState.UNLOCK if self.vault_path.is_file() else GUIState.CREATE
        )

    def create_vault(
        self, master_password: str, confirmation: str
    ) -> ControllerResult:
        if not _nonblank(master_password):
            return ControllerResult(False, "Master password is required.", clear_secret_fields=True)
        if master_password != confirmation:
            return ControllerResult(False, "Confirmation did not match.", clear_secret_fields=True)
        try:
            self.vault_path.parent.mkdir(parents=True, exist_ok=True)
            vault = self._dependencies.create_vault(self.vault_path, master_password)
        except Exception as error:
            return self._mapped_error(error, clear_secret_fields=True)
        self._replace_session(vault)
        self.state = GUIState.UNLOCKED
        return ControllerResult(True, "Vault created.", clear_secret_fields=True)

    def unlock(self, master_password: str) -> ControllerResult:
        if not _nonblank(master_password):
            return ControllerResult(False, "Master password is required.", clear_secret_fields=True)
        try:
            vault = self._dependencies.open_vault(self.vault_path, master_password)
        except Exception:
            return ControllerResult(
                False, "Unable to unlock vault.", clear_secret_fields=True
            )
        self._replace_session(vault)
        self.state = GUIState.UNLOCKED
        return ControllerResult(True, "Vault unlocked.", clear_secret_fields=True)

    def refresh_accounts(self) -> ControllerResult:
        if self._vault is None:
            return ControllerResult(False, "Vault is locked.")
        try:
            accounts = tuple(self._vault.list_accounts())
        except Exception as error:
            return self._mapped_error(error)
        return ControllerResult(True, "Accounts refreshed.", accounts=accounts)

    def set_credential(
        self, account: str, password: str, confirmation: str
    ) -> ControllerResult:
        if self._vault is None:
            return ControllerResult(False, "Vault is locked.", clear_secret_fields=True)
        if not _nonblank(account) or not _nonblank(password):
            return ControllerResult(False, "Account and password are required.", clear_secret_fields=True)
        if password != confirmation:
            return ControllerResult(False, "Confirmation did not match.", clear_secret_fields=True)
        try:
            self._vault.set_credential(account, password)
        except Exception as error:
            return self._mapped_error(error, clear_secret_fields=True)
        return ControllerResult(True, "Credential saved.", clear_secret_fields=True)

    def copy_credential(self, account: str) -> ControllerResult:
        if self._vault is None:
            return ControllerResult(False, "Vault is locked.")
        if not _nonblank(account):
            return ControllerResult(False, "Select an account.")
        self._cancel_cleanup(forget_secret=False)
        try:
            credential_password = self._vault.get_credential(account)
            self._dependencies.clipboard_copy(credential_password)
            self._clipboard_secret = credential_password
            self._cleanup_generation += 1
            generation = self._cleanup_generation
            self._scheduled_cleanup = self._dependencies.schedule(
                self._clipboard_clear_ms,
                lambda: self._run_scheduled_cleanup(generation),
            )
        except Exception as error:
            self._attempt_clipboard_cleanup()
            return self._mapped_error(error)
        return ControllerResult(True, "Credential copied to clipboard.")

    def delete_credential(self, account: str, *, confirmed: bool) -> ControllerResult:
        if self._vault is None:
            return ControllerResult(False, "Vault is locked.")
        if not confirmed:
            return ControllerResult(False, "Deletion cancelled.")
        try:
            self._vault.delete_credential(account)
        except Exception as error:
            return self._mapped_error(error)
        return ControllerResult(True, "Credential deleted.")

    def lock(self) -> ControllerResult:
        if self.state is GUIState.CLOSED:
            return ControllerResult(True, "Vault closed.")
        self._attempt_clipboard_cleanup()
        self._cancel_cleanup(forget_secret=True)
        self._close_session()
        self.state = (
            GUIState.UNLOCK if self.vault_path.is_file() else GUIState.CREATE
        )
        return ControllerResult(True, "Vault locked.")

    def close(self) -> None:
        if self.state is GUIState.CLOSED:
            return
        self._attempt_clipboard_cleanup()
        self._cancel_cleanup(forget_secret=True)
        self._close_session()
        self.state = GUIState.CLOSED

    def _replace_session(self, vault: Vault) -> None:
        self._attempt_clipboard_cleanup()
        self._cancel_cleanup(forget_secret=True)
        self._close_session()
        self._vault = vault

    def _close_session(self) -> None:
        vault, self._vault = self._vault, None
        if vault is not None:
            try:
                vault.close()
            except Exception:
                pass

    def _run_scheduled_cleanup(self, generation: int) -> None:
        if generation != self._cleanup_generation:
            return
        self._scheduled_cleanup = None
        self._attempt_clipboard_cleanup()

    def _attempt_clipboard_cleanup(self) -> None:
        credential_password, self._clipboard_secret = self._clipboard_secret, None
        if credential_password is None:
            return
        try:
            if self._dependencies.clipboard_paste() == credential_password:
                self._dependencies.clipboard_copy("")
        except Exception:
            pass

    def _cancel_cleanup(self, *, forget_secret: bool) -> None:
        self._cleanup_generation += 1
        scheduled, self._scheduled_cleanup = self._scheduled_cleanup, None
        if scheduled is not None:
            try:
                self._dependencies.cancel_scheduled(scheduled)
            except Exception:
                pass
        if forget_secret:
            self._clipboard_secret = None

    @staticmethod
    def _mapped_error(
        error: Exception, *, clear_secret_fields: bool = False
    ) -> ControllerResult:
        if isinstance(error, AccountNotFoundError):
            message = "Account was not found."
        elif isinstance(error, (VaultAuthenticationError, VaultFormatError)):
            message = "Vault is unavailable or invalid."
        elif isinstance(error, VaultValidationError):
            message = "Input was invalid."
        elif isinstance(error, VaultError):
            message = "Vault operation failed."
        else:
            message = "Operation failed."
        return ControllerResult(False, message, clear_secret_fields=clear_secret_fields)


def _nonblank(value: str) -> bool:
    return isinstance(value, str) and bool(value.strip())
