import io
import subprocess
import sys
from pathlib import Path

import pytest

from password_locker import AccountNotFoundError, KDFParameters, Vault
from password_locker.cli import (
    DEFAULT_CLEAR_AFTER,
    EXIT_CONFIRMATION,
    EXIT_DOMAIN_ERROR,
    EXIT_INTERRUPTED,
    EXIT_SUCCESS,
    EXIT_UNEXPECTED,
    EXIT_USAGE,
    CLIDependencies,
    default_vault_path,
    main,
)


TEST_KDF = KDFParameters(n=2**10, r=8, p=1)
FAKE_MASTER = "cli-only example master"
FAKE_PASSWORD = "Cli-Example-Only-42!"


class FakeClipboard:
    def __init__(self):
        self.value = ""
        self.copies = []

    def copy(self, value):
        self.value = value
        self.copies.append(value)

    def paste(self):
        return self.value


def make_dependencies(
    secrets=(), *, answers=(), clipboard=None, wait=None, create_vault=None, open_vault=None
):
    secret_values = iter(secrets)
    answer_values = iter(answers)
    fake_clipboard = clipboard or FakeClipboard()
    return CLIDependencies(
        prompt_secret=lambda prompt: next(secret_values),
        prompt_input=lambda prompt: next(answer_values),
        clipboard_copy=fake_clipboard.copy,
        clipboard_paste=fake_clipboard.paste,
        wait=wait or (lambda seconds: None),
        create_vault=create_vault
        or (
            lambda path, password: Vault.create(
                path, password, kdf_parameters=TEST_KDF
            )
        ),
        open_vault=open_vault or Vault.open,
    )


def run_cli(arguments, dependencies):
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = main(arguments, dependencies=dependencies, stdout=stdout, stderr=stderr)
    return code, stdout.getvalue(), stderr.getvalue()


def create_test_vault(path):
    vault = Vault.create(path, FAKE_MASTER, kdf_parameters=TEST_KDF)
    vault.close()


def store_test_credential(path, account="fake account", password=FAKE_PASSWORD):
    with Vault.open(path, FAKE_MASTER) as vault:
        vault.set_credential(account, password)


def test_init_success_creates_parent_and_vault(tmp_path):
    path = tmp_path / "nested" / "vault.db"
    deps = make_dependencies([FAKE_MASTER, FAKE_MASTER])

    code, output, errors = run_cli(["--vault", str(path), "init"], deps)

    assert code == EXIT_SUCCESS
    assert output == "Vault initialized.\n"
    assert errors == ""
    with Vault.open(path, FAKE_MASTER) as vault:
        assert vault.list_accounts() == []


def test_init_confirmation_mismatch_creates_nothing(tmp_path):
    path = tmp_path / "nested" / "vault.db"
    deps = make_dependencies([FAKE_MASTER, "different example confirmation"])

    code, output, errors = run_cli(["--vault", str(path), "init"], deps)

    assert code == EXIT_CONFIRMATION
    assert output == ""
    assert errors == "Confirmation did not match.\n"
    assert not path.exists()


def test_init_refuses_to_overwrite_existing_vault(tmp_path):
    path = tmp_path / "vault.db"
    create_test_vault(path)
    deps = make_dependencies([FAKE_MASTER, FAKE_MASTER])

    code, output, errors = run_cli(["--vault", str(path), "init"], deps)

    assert code == EXIT_DOMAIN_ERROR
    assert output == ""
    assert errors == "Vault operation failed.\n"


def test_set_success(tmp_path):
    path = tmp_path / "vault.db"
    create_test_vault(path)
    deps = make_dependencies([FAKE_MASTER, FAKE_PASSWORD, FAKE_PASSWORD])

    code, output, errors = run_cli(
        ["--vault", str(path), "set", "Fake Account"], deps
    )

    assert code == EXIT_SUCCESS
    assert output == "Credential saved.\n"
    assert errors == ""
    with Vault.open(path, FAKE_MASTER) as vault:
        assert vault.get_credential("fake account") == FAKE_PASSWORD


def test_set_confirmation_mismatch_does_not_store(tmp_path):
    path = tmp_path / "vault.db"
    create_test_vault(path)
    deps = make_dependencies([FAKE_MASTER, FAKE_PASSWORD, "different example"])

    code, output, errors = run_cli(
        ["--vault", str(path), "set", "fake account"], deps
    )

    assert code == EXIT_CONFIRMATION
    assert output == ""
    assert errors == "Confirmation did not match.\n"
    with Vault.open(path, FAKE_MASTER) as vault:
        with pytest.raises(AccountNotFoundError):
            vault.get_credential("fake account")


def test_get_copies_without_printing_and_clears_after_delay(tmp_path):
    path = tmp_path / "vault.db"
    create_test_vault(path)
    store_test_credential(path)
    clipboard = FakeClipboard()
    waits = []
    deps = make_dependencies(
        [FAKE_MASTER], clipboard=clipboard, wait=lambda seconds: waits.append(seconds)
    )

    code, output, errors = run_cli(["--vault", str(path), "get", "fake account"], deps)

    assert code == EXIT_SUCCESS
    assert output == "Credential copied to clipboard.\n"
    assert errors == ""
    assert waits == [DEFAULT_CLEAR_AFTER]
    assert clipboard.copies == [FAKE_PASSWORD, ""]
    assert clipboard.value == ""
    assert FAKE_PASSWORD not in output + errors


def test_get_preserves_newer_clipboard_content(tmp_path):
    path = tmp_path / "vault.db"
    create_test_vault(path)
    store_test_credential(path)
    clipboard = FakeClipboard()

    def replace_clipboard(seconds):
        clipboard.value = "newer non-secret clipboard content"

    deps = make_dependencies(
        [FAKE_MASTER], clipboard=clipboard, wait=replace_clipboard
    )
    code, output, errors = run_cli(
        ["--vault", str(path), "get", "fake account", "--clear-after", "5"],
        deps,
    )

    assert code == EXIT_SUCCESS
    assert clipboard.value == "newer non-secret clipboard content"
    assert clipboard.copies == [FAKE_PASSWORD]
    assert FAKE_PASSWORD not in output + errors


def test_get_keyboard_interrupt_attempts_conditional_cleanup(tmp_path):
    path = tmp_path / "vault.db"
    create_test_vault(path)
    store_test_credential(path)
    clipboard = FakeClipboard()

    def interrupt(seconds):
        raise KeyboardInterrupt

    deps = make_dependencies([FAKE_MASTER], clipboard=clipboard, wait=interrupt)
    code, output, errors = run_cli(["--vault", str(path), "get", "fake account"], deps)

    assert code == EXIT_INTERRUPTED
    assert clipboard.copies == [FAKE_PASSWORD, ""]
    assert clipboard.value == ""
    assert "Operation interrupted." in errors
    assert FAKE_PASSWORD not in output + errors


def test_list_prints_normalized_accounts_in_order(tmp_path):
    path = tmp_path / "vault.db"
    create_test_vault(path)
    store_test_credential(path, " Zulu Example ")
    store_test_credential(path, "ALPHA Example")
    deps = make_dependencies([FAKE_MASTER])

    code, output, errors = run_cli(["--vault", str(path), "list"], deps)

    assert code == EXIT_SUCCESS
    assert output.splitlines() == ["alpha example", "zulu example"]
    assert errors == ""


def test_list_empty_vault_message(tmp_path):
    path = tmp_path / "vault.db"
    create_test_vault(path)
    deps = make_dependencies([FAKE_MASTER])

    code, output, errors = run_cli(["--vault", str(path), "list"], deps)

    assert code == EXIT_SUCCESS
    assert output == "Vault contains no accounts.\n"
    assert errors == ""


def test_delete_requires_interactive_confirmation(tmp_path):
    path = tmp_path / "vault.db"
    create_test_vault(path)
    store_test_credential(path)
    deps = make_dependencies([FAKE_MASTER], answers=["no"])

    code, output, errors = run_cli(
        ["--vault", str(path), "delete", "fake account"], deps
    )

    assert code == EXIT_CONFIRMATION
    assert output == "Delete cancelled.\n"
    assert errors == ""
    with Vault.open(path, FAKE_MASTER) as vault:
        assert vault.get_credential("fake account") == FAKE_PASSWORD


def test_delete_interactive_confirmation_succeeds(tmp_path):
    path = tmp_path / "vault.db"
    create_test_vault(path)
    store_test_credential(path)
    deps = make_dependencies([FAKE_MASTER], answers=["yes"])

    code, output, errors = run_cli(
        ["--vault", str(path), "delete", "FAKE ACCOUNT"], deps
    )

    assert code == EXIT_SUCCESS
    assert output == "Credential deleted.\n"
    assert errors == ""


def test_delete_yes_skips_confirmation(tmp_path):
    path = tmp_path / "vault.db"
    create_test_vault(path)
    store_test_credential(path)

    def unexpected_prompt(prompt):
        raise AssertionError("confirmation prompt must be skipped")

    deps = make_dependencies([FAKE_MASTER])
    deps = CLIDependencies(**{**deps.__dict__, "prompt_input": unexpected_prompt})
    code, output, errors = run_cli(
        ["--vault", str(path), "delete", "fake account", "--yes"], deps
    )

    assert code == EXIT_SUCCESS
    assert errors == ""


def test_delete_missing_account_is_domain_error(tmp_path):
    path = tmp_path / "vault.db"
    create_test_vault(path)
    deps = make_dependencies([FAKE_MASTER])

    code, output, errors = run_cli(
        ["--vault", str(path), "delete", "missing example", "--yes"], deps
    )

    assert code == EXIT_DOMAIN_ERROR
    assert output == ""
    assert errors == "Account was not found.\n"


def test_wrong_master_is_generic_and_has_no_traceback(tmp_path):
    path = tmp_path / "vault.db"
    create_test_vault(path)
    wrong = "deliberately wrong cli example"
    deps = make_dependencies([wrong])

    code, output, errors = run_cli(["--vault", str(path), "list"], deps)

    assert code == EXIT_DOMAIN_ERROR
    assert errors == "Unable to unlock vault.\n"
    assert "Traceback" not in output + errors
    assert wrong not in output + errors


@pytest.mark.parametrize("kind", ["missing", "corrupt"])
def test_missing_or_corrupt_vault_is_domain_error(tmp_path, kind):
    path = tmp_path / "vault.db"
    if kind == "corrupt":
        path.write_bytes(b"invalid temporary cli test database")
    deps = make_dependencies([FAKE_MASTER])

    code, output, errors = run_cli(["--vault", str(path), "list"], deps)

    assert code == EXIT_DOMAIN_ERROR
    assert "Traceback" not in output + errors
    assert FAKE_MASTER not in output + errors


@pytest.mark.parametrize("value", ["0", "3601", "not-a-number"])
def test_invalid_clear_after_is_usage_error(tmp_path, value):
    path = tmp_path / "vault.db"
    deps = make_dependencies([])

    code, output, errors = run_cli(
        ["--vault", str(path), "get", "fake", "--clear-after", value], deps
    )

    assert code == EXIT_USAGE
    assert "Traceback" not in output + errors


def test_cli_account_normalization_round_trip(tmp_path):
    path = tmp_path / "vault.db"
    create_test_vault(path)
    set_deps = make_dependencies([FAKE_MASTER, FAKE_PASSWORD, FAKE_PASSWORD])
    code, _, _ = run_cli(
        ["--vault", str(path), "set", "  MIXED Case Example  "], set_deps
    )
    assert code == EXIT_SUCCESS

    list_deps = make_dependencies([FAKE_MASTER])
    code, output, errors = run_cli(["--vault", str(path), "list"], list_deps)
    assert code == EXIT_SUCCESS
    assert output == "mixed case example\n"
    assert errors == ""


def test_unexpected_failure_is_generic(tmp_path):
    detail = "internal-only exception detail"

    def fail_open(path, password):
        raise RuntimeError(detail)

    deps = make_dependencies([FAKE_MASTER], open_vault=fail_open)
    code, output, errors = run_cli(
        ["--vault", str(tmp_path / "vault.db"), "list"], deps
    )

    assert code == EXIT_UNEXPECTED
    assert errors == "Operation failed.\n"
    assert detail not in output + errors
    assert "Traceback" not in output + errors


def test_password_options_are_not_accepted(tmp_path):
    deps = make_dependencies([])
    code, output, errors = run_cli(
        ["--vault", str(tmp_path / "vault.db"), "init", "--master-password", "x"],
        deps,
    )
    assert code == EXIT_USAGE
    assert "Traceback" not in output + errors


def test_module_help_succeeds_without_accessing_a_vault():
    result = subprocess.run(
        [sys.executable, "-m", "password_locker", "--help"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == EXIT_SUCCESS
    assert "usage:" in result.stdout
    assert result.stderr == ""


def test_default_vault_path_is_user_local():
    assert default_vault_path() == Path.home() / ".password_locker" / "vault.db"
