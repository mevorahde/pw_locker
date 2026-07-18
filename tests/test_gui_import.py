import importlib
import subprocess
import sys
from importlib import resources
from pathlib import Path

from password_locker.gui_controller import ControllerResult


def test_gui_module_import_does_not_create_tk_root(monkeypatch):
    import tkinter

    def fail_if_called(*args, **kwargs):
        raise AssertionError("Tk root must not be created during import")

    monkeypatch.setattr(tkinter, "Tk", fail_if_called)
    sys.modules.pop("password_locker.gui", None)
    module = importlib.import_module("password_locker.gui")
    assert module.APPLICATION_TITLE == "Password Locker"


def test_packaged_icon_resource_exists_and_is_applied_from_expected_path():
    from password_locker import gui

    icon_resource = resources.files("password_locker").joinpath(
        "assets", "password-locker.ico"
    )

    class IconRoot:
        def __init__(self):
            self.applied_path = None

        def iconbitmap(self, *, default):
            self.applied_path = Path(default)

    root = IconRoot()
    assert icon_resource.is_file()
    assert gui.apply_application_icon(root)
    assert root.applied_path.name == "password-locker.ico"
    assert root.applied_path.parent.name == "assets"


def test_unsupported_icon_operation_does_not_crash_startup():
    from password_locker import gui

    class UnsupportedIconRoot:
        def iconbitmap(self, *, default):
            raise gui.tk.TclError("icon operation unsupported")

    assert gui.apply_application_icon(UnsupportedIconRoot()) is False


def test_app_initialization_attempts_to_apply_icon_before_showing_screen(monkeypatch):
    from password_locker import gui

    events = []

    class InitializationRoot:
        def title(self, value):
            events.append("title")

        def minsize(self, width, height):
            events.append("minsize")

        def columnconfigure(self, column, *, weight):
            pass

        def rowconfigure(self, row, *, weight):
            pass

        def protocol(self, name, callback):
            pass

    def fake_variable(*, master, value=""):
        return FakeVariable(value)

    monkeypatch.setattr(gui.tk, "StringVar", fake_variable)
    monkeypatch.setattr(gui.tk, "BooleanVar", fake_variable)
    monkeypatch.setattr(
        gui,
        "apply_application_icon",
        lambda root: events.append("icon") or True,
    )
    monkeypatch.setattr(
        gui.PasswordLockerApp,
        "_show_current_state",
        lambda self: events.append("screen"),
    )

    gui.PasswordLockerApp(InitializationRoot(), controller=object())

    assert events.index("icon") < events.index("screen")


def test_cli_module_help_still_succeeds_without_gui_or_vault():
    result = subprocess.run(
        [sys.executable, "-m", "password_locker", "--help"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0
    assert "usage:" in result.stdout
    assert result.stderr == ""


class FakeVariable:
    def __init__(self, value=""):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class FakeRoot:
    def __init__(self):
        self.idle_callbacks = []

    def after_idle(self, callback):
        self.idle_callbacks.append(callback)

    def run_idle(self):
        callbacks, self.idle_callbacks = self.idle_callbacks, []
        for callback in callbacks:
            callback()


class FakeAccountList:
    def __init__(self):
        self.values = []

    def delete(self, first, last):
        self.values = []

    def insert(self, index, value):
        self.values.append(value)

    def curselection(self):
        return ()


class FakeController:
    def __init__(self):
        self.save_calls = 0
        self.delete_calls = 0

    def set_credential(self, account, password, confirmation):
        self.save_calls += 1
        return ControllerResult(True, "Credential saved.", clear_secret_fields=True)

    def refresh_accounts(self):
        return ControllerResult(
            True, "Accounts refreshed.", accounts=("fake account",)
        )

    def delete_credential(self, account, *, confirmed):
        self.delete_calls += 1
        return ControllerResult(True, "Credential deleted.")


def make_headless_app():
    from password_locker.gui import PasswordLockerApp

    app = PasswordLockerApp.__new__(PasswordLockerApp)
    app.root = FakeRoot()
    app.controller = FakeController()
    app._status = FakeVariable()
    app._account = FakeVariable("fake account")
    app._password = FakeVariable("fake test password")
    app._confirmation = FakeVariable("fake test password")
    app._show_password = FakeVariable(False)
    app._password_entries = []
    app._account_list = FakeAccountList()
    app._save_submission_pending = False
    return app


def test_duplicate_save_callbacks_in_same_idle_cycle_submit_once():
    app = make_headless_app()

    app._save_credential()
    app._save_credential()

    assert app.controller.save_calls == 1
    assert len(app.root.idle_callbacks) == 1


def test_save_guard_resets_for_later_intentional_submission():
    app = make_headless_app()
    app._save_credential()
    app.root.run_idle()
    app._password.set("later fake test password")
    app._confirmation.set("later fake test password")

    app._save_credential()

    assert app.controller.save_calls == 2


def test_successful_save_status_survives_account_refresh():
    app = make_headless_app()

    app._save_credential()

    assert app._status.get() == "Credential saved."
    assert app._account_list.values == ["fake account"]


def test_successful_delete_status_survives_account_refresh(monkeypatch):
    from password_locker import gui

    app = make_headless_app()
    monkeypatch.setattr(gui.messagebox, "askyesno", lambda *args, **kwargs: True)

    app._delete_selected()

    assert app.controller.delete_calls == 1
    assert app._status.get() == "Credential deleted."
    assert app._account_list.values == ["fake account"]


def test_confirmation_return_handler_stops_event_propagation():
    app = make_headless_app()

    result = app._on_save_return(object())

    assert result == "break"
    assert app.controller.save_calls == 1


class FakePasswordEntry:
    def __init__(self, value):
        self.value = value
        self.show = None

    def configure(self, *, show):
        self.show = show


def test_password_fields_are_masked_by_default():
    app = make_headless_app()
    first = FakePasswordEntry("first fake value")
    second = FakePasswordEntry("second fake value")

    app._set_password_entries(first, second)

    assert not app._show_password.get()
    assert first.show == "*"
    assert second.show == "*"


def test_show_password_reveals_and_remasks_all_applicable_fields():
    app = make_headless_app()
    first = FakePasswordEntry("first fake value")
    second = FakePasswordEntry("second fake value")
    app._set_password_entries(first, second)

    app._show_password.set(True)
    app._toggle_password_visibility()
    assert first.show == ""
    assert second.show == ""

    app._show_password.set(False)
    app._toggle_password_visibility()
    assert first.show == "*"
    assert second.show == "*"


def test_visibility_toggle_does_not_change_field_contents():
    app = make_headless_app()
    first = FakePasswordEntry("first fake value")
    second = FakePasswordEntry("second fake value")
    app._set_password_entries(first, second)

    app._show_password.set(True)
    app._toggle_password_visibility()
    app._reset_password_visibility()

    assert first.value == "first fake value"
    assert second.value == "second fake value"


def test_visibility_resets_when_password_fields_are_cleared_after_save():
    app = make_headless_app()
    first = FakePasswordEntry("first fake value")
    second = FakePasswordEntry("second fake value")
    app._set_password_entries(first, second)
    app._show_password.set(True)
    app._toggle_password_visibility()

    app._save_credential()

    assert not app._show_password.get()
    assert first.show == "*"
    assert second.show == "*"
    assert app._password.get() == ""
    assert app._confirmation.get() == ""


def test_screen_reset_restores_masking_and_clears_toggle():
    app = make_headless_app()
    entry = FakePasswordEntry("fake value")
    app._set_password_entries(entry)
    app._show_password.set(True)
    app._toggle_password_visibility()

    app._reset_password_visibility()

    assert not app._show_password.get()
    assert entry.show == "*"
