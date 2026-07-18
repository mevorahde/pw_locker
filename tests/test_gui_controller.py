from password_locker import AccountNotFoundError, KDFParameters, Vault
from password_locker.gui_controller import (
    DEFAULT_CLIPBOARD_CLEAR_SECONDS,
    ControllerDependencies,
    GUIState,
    VaultGUIController,
)


TEST_KDF = KDFParameters(n=2**10, r=8, p=1)
FAKE_MASTER = "gui-only example master"
FAKE_PASSWORD = "Gui-Example-Only-42!"


class FakeProcessBoundaries:
    def __init__(self):
        self.clipboard = ""
        self.copies = []
        self.callbacks = {}
        self.cancelled = []
        self._next_token = 1

    def copy(self, value):
        self.clipboard = value
        self.copies.append(value)

    def paste(self):
        return self.clipboard

    def schedule(self, milliseconds, callback):
        token = self._next_token
        self._next_token += 1
        self.callbacks[token] = (milliseconds, callback)
        return token

    def cancel(self, token):
        self.cancelled.append(token)

    def run(self, token):
        self.callbacks[token][1]()


def make_controller(path, boundaries=None, *, create_vault=None, open_vault=None):
    fake = boundaries or FakeProcessBoundaries()
    dependencies = ControllerDependencies(
        clipboard_copy=fake.copy,
        clipboard_paste=fake.paste,
        schedule=fake.schedule,
        cancel_scheduled=fake.cancel,
        create_vault=create_vault
        or (
            lambda vault_path, password: Vault.create(
                vault_path, password, kdf_parameters=TEST_KDF
            )
        ),
        open_vault=open_vault or Vault.open,
    )
    return VaultGUIController(path, dependencies), fake


def create_test_vault(path):
    Vault.create(path, FAKE_MASTER, kdf_parameters=TEST_KDF).close()


def unlock_with_credential(controller, account="fake account", password=FAKE_PASSWORD):
    assert controller.unlock(FAKE_MASTER).ok
    assert controller.set_credential(account, password, password).ok


def test_startup_state_uses_path_existence(tmp_path):
    missing_controller, _ = make_controller(tmp_path / "missing.db")
    assert missing_controller.state is GUIState.CREATE

    existing = tmp_path / "existing.db"
    create_test_vault(existing)
    existing_controller, _ = make_controller(existing)
    assert existing_controller.state is GUIState.UNLOCK


def test_create_success_creates_parent_after_validation(tmp_path):
    path = tmp_path / "nested" / "vault.db"
    controller, _ = make_controller(path)

    result = controller.create_vault(FAKE_MASTER, FAKE_MASTER)

    assert result.ok
    assert controller.state is GUIState.UNLOCKED
    assert path.is_file()
    controller.close()


def test_create_rejects_blank_without_creating_parent(tmp_path):
    path = tmp_path / "nested" / "vault.db"
    controller, _ = make_controller(path)

    result = controller.create_vault("   ", "   ")

    assert not result.ok
    assert result.clear_secret_fields
    assert not path.parent.exists()


def test_create_rejects_confirmation_mismatch(tmp_path):
    path = tmp_path / "nested" / "vault.db"
    controller, _ = make_controller(path)

    result = controller.create_vault(FAKE_MASTER, "different example")

    assert not result.ok
    assert result.message == "Confirmation did not match."
    assert not path.parent.exists()


def test_unlock_success_and_wrong_password_mapping(tmp_path):
    path = tmp_path / "vault.db"
    create_test_vault(path)
    controller, _ = make_controller(path)

    wrong = "deliberately wrong gui example"
    failure = controller.unlock(wrong)
    assert not failure.ok
    assert failure.message == "Unable to unlock vault."
    assert failure.clear_secret_fields
    assert wrong not in failure.message

    success = controller.unlock(FAKE_MASTER)
    assert success.ok
    assert controller.state is GUIState.UNLOCKED
    controller.close()


def test_refresh_accounts_is_normalized_and_deterministic(tmp_path):
    path = tmp_path / "vault.db"
    create_test_vault(path)
    controller, _ = make_controller(path)
    assert controller.unlock(FAKE_MASTER).ok
    assert controller.set_credential(" Zulu Example ", FAKE_PASSWORD, FAKE_PASSWORD).ok
    assert controller.set_credential("ALPHA EXAMPLE", FAKE_PASSWORD, FAKE_PASSWORD).ok

    result = controller.refresh_accounts()

    assert result.ok
    assert result.accounts == ("alpha example", "zulu example")
    controller.close()


def test_add_update_and_confirmation_mismatch(tmp_path):
    path = tmp_path / "vault.db"
    create_test_vault(path)
    controller, _ = make_controller(path)
    assert controller.unlock(FAKE_MASTER).ok

    mismatch = controller.set_credential("fake", FAKE_PASSWORD, "different")
    assert not mismatch.ok
    assert mismatch.clear_secret_fields

    assert controller.set_credential(" Fake ", FAKE_PASSWORD, FAKE_PASSWORD).ok
    updated = "Updated-Gui-Example-43!"
    assert controller.set_credential("FAKE", updated, updated).ok
    with Vault.open(path, FAKE_MASTER) as vault:
        assert vault.get_credential("fake") == updated
    controller.close()


def test_copy_performs_clipboard_work_without_returning_password(tmp_path):
    path = tmp_path / "vault.db"
    create_test_vault(path)
    controller, fake = make_controller(path)
    unlock_with_credential(controller)

    result = controller.copy_credential("fake account")

    assert result.ok
    assert result.accounts == ()
    assert result.message == "Credential copied to clipboard."
    assert FAKE_PASSWORD not in result.message
    assert fake.clipboard == FAKE_PASSWORD
    controller.close()


def test_scheduled_cleanup_clears_only_unchanged_clipboard(tmp_path):
    path = tmp_path / "vault.db"
    create_test_vault(path)
    controller, fake = make_controller(path)
    unlock_with_credential(controller)
    assert controller.copy_credential("fake account").ok
    token = next(iter(fake.callbacks))
    assert fake.callbacks[token][0] == DEFAULT_CLIPBOARD_CLEAR_SECONDS * 1000

    fake.run(token)

    assert fake.clipboard == ""
    assert fake.copies == [FAKE_PASSWORD, ""]
    assert controller._clipboard_secret is None
    controller.close()


def test_scheduled_cleanup_preserves_newer_clipboard_content(tmp_path):
    path = tmp_path / "vault.db"
    create_test_vault(path)
    controller, fake = make_controller(path)
    unlock_with_credential(controller)
    assert controller.copy_credential("fake account").ok
    token = next(iter(fake.callbacks))
    fake.clipboard = "newer non-secret clipboard content"

    fake.run(token)

    assert fake.clipboard == "newer non-secret clipboard content"
    assert controller._clipboard_secret is None
    controller.close()


def test_new_copy_cancels_and_replaces_prior_cleanup(tmp_path):
    path = tmp_path / "vault.db"
    create_test_vault(path)
    controller, fake = make_controller(path)
    assert controller.unlock(FAKE_MASTER).ok
    first = "First-Gui-Example-1!"
    second = "Second-Gui-Example-2!"
    assert controller.set_credential("first", first, first).ok
    assert controller.set_credential("second", second, second).ok

    assert controller.copy_credential("first").ok
    first_token = max(fake.callbacks)
    assert controller.copy_credential("second").ok
    second_token = max(fake.callbacks)

    assert first_token in fake.cancelled
    assert second_token != first_token
    fake.run(first_token)
    assert fake.clipboard == second
    fake.run(second_token)
    assert fake.clipboard == ""
    controller.close()


def test_failed_replacement_copy_cleans_prior_clipboard(tmp_path):
    path = tmp_path / "vault.db"
    create_test_vault(path)
    controller, fake = make_controller(path)
    unlock_with_credential(controller)
    assert controller.copy_credential("fake account").ok

    result = controller.copy_credential("missing account")

    assert not result.ok
    assert result.message == "Account was not found."
    assert fake.clipboard == ""
    controller.close()


def test_lock_attempts_cleanup_and_is_repeatable(tmp_path):
    path = tmp_path / "vault.db"
    create_test_vault(path)
    controller, fake = make_controller(path)
    unlock_with_credential(controller)
    assert controller.copy_credential("fake account").ok
    token = max(fake.callbacks)

    first = controller.lock()
    second = controller.lock()

    assert first.ok and second.ok
    assert controller.state is GUIState.UNLOCK
    assert fake.clipboard == ""
    assert token in fake.cancelled
    assert controller._clipboard_secret is None


def test_close_preserves_newer_clipboard_and_is_repeatable(tmp_path):
    path = tmp_path / "vault.db"
    create_test_vault(path)
    controller, fake = make_controller(path)
    unlock_with_credential(controller)
    assert controller.copy_credential("fake account").ok
    fake.clipboard = "newer non-secret clipboard content"

    controller.close()
    controller.close()

    assert controller.state is GUIState.CLOSED
    assert fake.clipboard == "newer non-secret clipboard content"
    assert controller._clipboard_secret is None


def test_delete_requires_confirmation_and_handles_missing_account(tmp_path):
    path = tmp_path / "vault.db"
    create_test_vault(path)
    controller, _ = make_controller(path)
    unlock_with_credential(controller)

    cancelled = controller.delete_credential("fake account", confirmed=False)
    assert not cancelled.ok
    assert controller.refresh_accounts().accounts == ("fake account",)

    deleted = controller.delete_credential("fake account", confirmed=True)
    assert deleted.ok
    missing = controller.delete_credential("fake account", confirmed=True)
    assert not missing.ok
    assert missing.message == "Account was not found."
    controller.close()


def test_unexpected_errors_are_generic_and_secret_free(tmp_path):
    detail = "internal-only gui exception detail"

    def fail_create(path, password):
        raise RuntimeError(detail)

    controller, _ = make_controller(tmp_path / "vault.db", create_vault=fail_create)
    result = controller.create_vault(FAKE_MASTER, FAKE_MASTER)

    assert not result.ok
    assert result.message == "Operation failed."
    assert detail not in result.message
    assert FAKE_MASTER not in result.message


def test_locked_operations_fail_safely(tmp_path):
    controller, _ = make_controller(tmp_path / "vault.db")
    assert not controller.refresh_accounts().ok
    assert not controller.copy_credential("fake").ok
    assert not controller.delete_credential("fake", confirmed=True).ok
