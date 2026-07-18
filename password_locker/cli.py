"""Argparse command-line interface for the authenticated password vault."""

from __future__ import annotations

import argparse
import contextlib
import getpass
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence, TextIO

import pyperclip

from .vault import (
    AccountNotFoundError,
    Vault,
    VaultAuthenticationError,
    VaultError,
    VaultFormatError,
    VaultValidationError,
)


EXIT_SUCCESS = 0
EXIT_USAGE = 2
EXIT_DOMAIN_ERROR = 3
EXIT_CONFIRMATION = 4
EXIT_CLIPBOARD = 5
EXIT_UNEXPECTED = 70
EXIT_INTERRUPTED = 130

DEFAULT_CLEAR_AFTER = 30
MIN_CLEAR_AFTER = 1
MAX_CLEAR_AFTER = 3600


@dataclass(frozen=True)
class CLIDependencies:
    """Replaceable process boundaries used by the CLI."""

    prompt_secret: Callable[[str], str] = getpass.getpass
    prompt_input: Callable[[str], str] = input
    clipboard_copy: Callable[[str], None] = pyperclip.copy
    clipboard_paste: Callable[[], str] = pyperclip.paste
    wait: Callable[[float], None] = time.sleep
    create_vault: Callable[[Path, str], Vault] = Vault.create
    open_vault: Callable[[Path, str], Vault] = Vault.open


class _ConfirmationMismatch(Exception):
    pass


def default_vault_path() -> Path:
    """Return the user-local default vault path."""
    return Path.home() / ".password_locker" / "vault.db"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="password-locker",
        description="Manage an authenticated local password vault.",
    )
    parser.add_argument(
        "--vault",
        type=Path,
        default=default_vault_path(),
        metavar="PATH",
        help="vault database path (default: user-local vault)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init", help="create a new vault")

    set_parser = subparsers.add_parser("set", help="add or update a credential")
    set_parser.add_argument("account", metavar="ACCOUNT")

    get_parser = subparsers.add_parser("get", help="copy a credential to the clipboard")
    get_parser.add_argument("account", metavar="ACCOUNT")
    get_parser.add_argument(
        "--clear-after",
        type=_bounded_clear_after,
        default=DEFAULT_CLEAR_AFTER,
        metavar="SECONDS",
        help=f"conditionally clear the clipboard after {MIN_CLEAR_AFTER}-{MAX_CLEAR_AFTER} seconds",
    )

    subparsers.add_parser("list", help="list account names")

    delete_parser = subparsers.add_parser("delete", help="delete a credential")
    delete_parser.add_argument("account", metavar="ACCOUNT")
    delete_parser.add_argument(
        "--yes", action="store_true", help="delete without interactive confirmation"
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    dependencies: CLIDependencies | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run the CLI and return a stable process exit code."""
    deps = dependencies or CLIDependencies()
    output = stdout if stdout is not None else sys.stdout
    errors = stderr if stderr is not None else sys.stderr
    parser = build_parser()
    try:
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)

    vault_path = args.vault.expanduser()
    try:
        if args.command == "init":
            return _run_init(vault_path, deps, output)
        if args.command == "set":
            return _run_set(vault_path, args.account, deps, output)
        if args.command == "get":
            return _run_get(
                vault_path, args.account, args.clear_after, deps, output, errors
            )
        if args.command == "list":
            return _run_list(vault_path, deps, output)
        if args.command == "delete":
            return _run_delete(vault_path, args.account, args.yes, deps, output)
    except _ConfirmationMismatch:
        _write(errors, "Confirmation did not match.")
        return EXIT_CONFIRMATION
    except VaultAuthenticationError:
        _write(errors, "Unable to unlock vault.")
        return EXIT_DOMAIN_ERROR
    except AccountNotFoundError:
        _write(errors, "Account was not found.")
        return EXIT_DOMAIN_ERROR
    except VaultFormatError:
        _write(errors, "Vault is unavailable or invalid.")
        return EXIT_DOMAIN_ERROR
    except VaultValidationError:
        _write(errors, "Input was invalid.")
        return EXIT_DOMAIN_ERROR
    except VaultError:
        _write(errors, "Vault operation failed.")
        return EXIT_DOMAIN_ERROR
    except pyperclip.PyperclipException:
        _write(errors, "Clipboard operation failed.")
        return EXIT_CLIPBOARD
    except KeyboardInterrupt:
        _write(errors, "Operation interrupted.")
        return EXIT_INTERRUPTED
    except Exception:
        _write(errors, "Operation failed.")
        return EXIT_UNEXPECTED
    return EXIT_UNEXPECTED


def _run_init(path: Path, deps: CLIDependencies, output: TextIO) -> int:
    master_password = deps.prompt_secret("Master password: ")
    confirmation = deps.prompt_secret("Confirm master password: ")
    if master_password != confirmation:
        raise _ConfirmationMismatch
    path.parent.mkdir(parents=True, exist_ok=True)
    with deps.create_vault(path, master_password):
        pass
    _write(output, "Vault initialized.")
    return EXIT_SUCCESS


def _run_set(
    path: Path, account: str, deps: CLIDependencies, output: TextIO
) -> int:
    master_password = deps.prompt_secret("Master password: ")
    credential_password = deps.prompt_secret("Credential password: ")
    confirmation = deps.prompt_secret("Confirm credential password: ")
    if credential_password != confirmation:
        raise _ConfirmationMismatch
    with deps.open_vault(path, master_password) as vault:
        vault.set_credential(account, credential_password)
    _write(output, "Credential saved.")
    return EXIT_SUCCESS


def _run_get(
    path: Path,
    account: str,
    clear_after: int,
    deps: CLIDependencies,
    output: TextIO,
    errors: TextIO,
) -> int:
    master_password = deps.prompt_secret("Master password: ")
    with deps.open_vault(path, master_password) as vault:
        credential_password = vault.get_credential(account)
    deps.clipboard_copy(credential_password)
    _write(output, "Credential copied to clipboard.")
    try:
        deps.wait(clear_after)
    except KeyboardInterrupt:
        try:
            _conditionally_clear_clipboard(credential_password, deps)
        except pyperclip.PyperclipException:
            _write(errors, "Clipboard cleanup could not be completed.")
        _write(errors, "Operation interrupted.")
        return EXIT_INTERRUPTED
    _conditionally_clear_clipboard(credential_password, deps)
    return EXIT_SUCCESS


def _run_list(path: Path, deps: CLIDependencies, output: TextIO) -> int:
    master_password = deps.prompt_secret("Master password: ")
    with deps.open_vault(path, master_password) as vault:
        accounts = vault.list_accounts()
    if not accounts:
        _write(output, "Vault contains no accounts.")
    else:
        for account in accounts:
            _write(output, account)
    return EXIT_SUCCESS


def _run_delete(
    path: Path,
    account: str,
    assume_yes: bool,
    deps: CLIDependencies,
    output: TextIO,
) -> int:
    master_password = deps.prompt_secret("Master password: ")
    with deps.open_vault(path, master_password) as vault:
        if not assume_yes:
            answer = deps.prompt_input(f"Delete account '{account}'? [y/N]: ")
            if answer.strip().casefold() not in {"y", "yes"}:
                _write(output, "Delete cancelled.")
                return EXIT_CONFIRMATION
        vault.delete_credential(account)
    _write(output, "Credential deleted.")
    return EXIT_SUCCESS


def _conditionally_clear_clipboard(
    credential_password: str, deps: CLIDependencies
) -> None:
    if deps.clipboard_paste() == credential_password:
        deps.clipboard_copy("")


def _bounded_clear_after(value: str) -> int:
    try:
        seconds = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("clear delay must be an integer") from None
    if not MIN_CLEAR_AFTER <= seconds <= MAX_CLEAR_AFTER:
        raise argparse.ArgumentTypeError(
            f"clear delay must be between {MIN_CLEAR_AFTER} and {MAX_CLEAR_AFTER} seconds"
        )
    return seconds


def _write(stream: TextIO, message: str) -> None:
    print(message, file=stream)
