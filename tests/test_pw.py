import importlib
import io
import sys

import pytest

from password_locker import cli
from password_locker.cli import (
    CLIDependencies,
    EXIT_CLIPBOARD,
    EXIT_DOMAIN_ERROR,
    EXIT_INTERRUPTED,
    EXIT_SUCCESS,
    EXIT_USAGE,
)
from password_locker.vault import AccountNotFoundError, VaultAuthenticationError
import password_locker.pw as pw


FAKE_MASTER = "pw-test-only master"
FAKE_PASSWORD = "Pw-Test-Only-Credential!"


class FakeVault:
    def __init__(self, account="Apple ID", password=FAKE_PASSWORD, error=None):
        self.account = account
        self.password = password
        self.error = error
        self.requested_accounts = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def get_credential(self, account):
        self.requested_accounts.append(account)
        if self.error is not None:
            raise self.error
        return self.password


def make_dependencies(
    vault,
    *,
    copies=None,
    pasted=FAKE_PASSWORD,
    waits=None,
    open_error=None,
    wait=None,
    copy=None,
):
    clipboard_copies = copies if copies is not None else []
    recorded_waits = waits if waits is not None else []

    def open_vault(path, master_password):
        if open_error is not None:
            raise open_error
        assert master_password == FAKE_MASTER
        return vault

    return CLIDependencies(
        prompt_secret=lambda prompt: FAKE_MASTER,
        prompt_input=lambda prompt: pytest.fail("input prompt must not be used"),
        clipboard_copy=copy or clipboard_copies.append,
        clipboard_paste=lambda: pasted,
        wait=wait or recorded_waits.append,
        create_vault=lambda path, password: pytest.fail("vault must not be created"),
        open_vault=open_vault,
    )


def run_pw(arguments, dependencies):
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = pw.main(
        arguments,
        dependencies=dependencies,
        stdout=stdout,
        stderr=stderr,
    )
    return code, stdout.getvalue(), stderr.getvalue()


@pytest.mark.parametrize(
    ("arguments", "delegated"),
    [
        (["iTunes"], ["get", "iTunes"]),
        (["Apple ID"], ["get", "Apple ID"]),
        (
            ["Apple ID", "--clear-after", "30"],
            ["get", "Apple ID", "--clear-after", "30"],
        ),
    ],
)
def test_pw_delegates_arguments_to_secure_get(monkeypatch, arguments, delegated):
    calls = []

    def fake_main(received, **kwargs):
        calls.append((received, kwargs))
        return EXIT_SUCCESS

    monkeypatch.setattr(cli, "main", fake_main)

    assert pw.main(arguments) == EXIT_SUCCESS
    assert calls == [
        (
            delegated,
            {"dependencies": None, "stdout": None, "stderr": None},
        )
    ]


def test_pw_multiword_account_copies_without_displaying_secret_and_clears():
    vault = FakeVault()
    copies = []
    waits = []
    dependencies = make_dependencies(vault, copies=copies, waits=waits)

    code, output, errors = run_pw(
        ["Apple ID", "--clear-after", "30"], dependencies
    )

    assert code == EXIT_SUCCESS
    assert vault.requested_accounts == ["Apple ID"]
    assert waits == [30]
    assert copies == [FAKE_PASSWORD, ""]
    assert output == "Credential copied to clipboard.\n"
    assert errors == ""
    assert FAKE_PASSWORD not in output + errors


def test_pw_help_and_no_account_do_not_prompt_or_access_vault():
    def fail(*args, **kwargs):
        pytest.fail("help and usage errors must not cross process boundaries")

    dependencies = CLIDependencies(
        prompt_secret=fail,
        prompt_input=fail,
        clipboard_copy=fail,
        clipboard_paste=fail,
        wait=fail,
        create_vault=fail,
        open_vault=fail,
    )

    help_code, help_output, help_errors = run_pw(["--help"], dependencies)
    usage_code, usage_output, usage_errors = run_pw([], dependencies)

    assert help_code == EXIT_SUCCESS
    assert "usage:" in help_output
    assert help_errors == ""
    assert usage_code == EXIT_USAGE
    assert usage_output == ""
    assert "usage:" in usage_errors
    assert "Traceback" not in help_output + usage_errors


def test_pw_propagates_cli_exit_code(monkeypatch):
    monkeypatch.setattr(cli, "main", lambda arguments, **kwargs: EXIT_CLIPBOARD)

    assert pw.main(["iTunes"]) == EXIT_CLIPBOARD


def test_pw_interruption_preserves_conditional_cleanup_and_safe_output():
    vault = FakeVault(account="iTunes")
    copies = []

    def interrupt(seconds):
        raise KeyboardInterrupt

    dependencies = make_dependencies(vault, copies=copies, wait=interrupt)

    code, output, errors = run_pw(["iTunes"], dependencies)

    assert code == EXIT_INTERRUPTED
    assert copies == [FAKE_PASSWORD, ""]
    assert output == "Credential copied to clipboard.\n"
    assert errors == "Operation interrupted.\n"
    assert FAKE_PASSWORD not in output + errors
    assert "Traceback" not in output + errors


@pytest.mark.parametrize(
    ("vault", "open_error", "copy", "expected_code", "expected_error"),
    [
        (
            FakeVault(),
            VaultAuthenticationError(),
            None,
            EXIT_DOMAIN_ERROR,
            "Unable to unlock vault.\n",
        ),
        (
            FakeVault(error=AccountNotFoundError()),
            None,
            None,
            EXIT_DOMAIN_ERROR,
            "Account was not found.\n",
        ),
        (
            FakeVault(),
            None,
            lambda value: (_ for _ in ()).throw(cli.pyperclip.PyperclipException()),
            EXIT_CLIPBOARD,
            "Clipboard operation failed.\n",
        ),
    ],
)
def test_pw_failures_are_concise_and_do_not_expose_secrets(
    vault, open_error, copy, expected_code, expected_error
):
    dependencies = make_dependencies(vault, open_error=open_error, copy=copy)

    code, output, errors = run_pw(["Apple ID"], dependencies)

    assert code == expected_code
    assert output == ""
    assert errors == expected_error
    assert FAKE_MASTER not in output + errors
    assert FAKE_PASSWORD not in output + errors
    assert "Traceback" not in output + errors


def test_importing_pw_has_no_process_boundary_side_effects(monkeypatch):
    def fail(*args, **kwargs):
        pytest.fail("import must not access a vault, clipboard, or prompt")

    monkeypatch.setattr(cli.Vault, "open", fail)
    monkeypatch.setattr(cli.Vault, "create", fail)
    monkeypatch.setattr(cli.pyperclip, "copy", fail)
    monkeypatch.setattr(cli.pyperclip, "paste", fail)
    monkeypatch.setattr(cli.getpass, "getpass", fail)
    sys.modules.pop("password_locker.pw", None)

    module = importlib.import_module("password_locker.pw")

    assert callable(module.main)
