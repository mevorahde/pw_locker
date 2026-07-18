"""Tkinter presentation layer for the authenticated Password Locker vault."""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

from .gui_controller import (
    ControllerDependencies,
    ControllerResult,
    GUIState,
    VaultGUIController,
)
from .paths import default_vault_path


APPLICATION_TITLE = "Password Locker"


class PasswordLockerApp:
    """Render controller state with Tk widgets and no cryptographic logic."""

    def __init__(
        self,
        root: tk.Tk,
        *,
        controller: VaultGUIController | None = None,
        vault_path: Path | None = None,
    ) -> None:
        self.root = root
        if controller is None:
            dependencies = ControllerDependencies(
                clipboard_copy=self._clipboard_copy,
                clipboard_paste=self._clipboard_paste,
                schedule=self.root.after,
                cancel_scheduled=self.root.after_cancel,
            )
            controller = VaultGUIController(
                vault_path or default_vault_path(), dependencies
            )
        self.controller = controller
        self._frame: ttk.Frame | None = None
        self._status = tk.StringVar(master=self.root, value="")
        self._account_list: tk.Listbox | None = None
        self._account = tk.StringVar(master=self.root, value="")
        self._password = tk.StringVar(master=self.root, value="")
        self._confirmation = tk.StringVar(master=self.root, value="")
        self._show_password = tk.BooleanVar(master=self.root, value=False)
        self._password_entries: list[ttk.Entry] = []
        self._save_submission_pending = False

        self.root.title(APPLICATION_TITLE)
        self.root.minsize(620, 440)
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._show_current_state()

    def _show_current_state(self) -> None:
        self._reset_password_visibility()
        if self._frame is not None:
            self._frame.destroy()
        self._status.set("")
        if self.controller.state is GUIState.CREATE:
            self._show_create_screen()
        elif self.controller.state is GUIState.UNLOCK:
            self._show_unlock_screen()
        elif self.controller.state is GUIState.UNLOCKED:
            self._show_vault_screen()

    def _new_frame(self) -> ttk.Frame:
        frame = ttk.Frame(self.root, padding=24)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.columnconfigure(0, weight=1)
        self._frame = frame
        return frame

    def _show_create_screen(self) -> None:
        frame = self._new_frame()
        ttk.Label(frame, text="Create Vault", font=("TkDefaultFont", 18, "bold")).grid(
            row=0, column=0, sticky="w", pady=(0, 18)
        )
        master_password = tk.StringVar(master=self.root)
        confirmation = tk.StringVar(master=self.root)
        form = ttk.Frame(frame)
        form.grid(row=1, column=0, sticky="ew")
        form.columnconfigure(1, weight=1)
        ttk.Label(form, text="Master password:").grid(row=0, column=0, sticky="w", padx=(0, 12), pady=6)
        master_entry = ttk.Entry(form, textvariable=master_password, show="*", width=36)
        master_entry.grid(row=0, column=1, sticky="ew", pady=6)
        ttk.Label(form, text="Confirm password:").grid(row=1, column=0, sticky="w", padx=(0, 12), pady=6)
        confirmation_entry = ttk.Entry(form, textvariable=confirmation, show="*", width=36)
        confirmation_entry.grid(row=1, column=1, sticky="ew", pady=6)
        self._set_password_entries(master_entry, confirmation_entry)
        ttk.Checkbutton(
            form,
            text="Show password",
            variable=self._show_password,
            command=self._toggle_password_visibility,
        ).grid(row=2, column=1, sticky="w", pady=(4, 0))

        def submit(event: object | None = None) -> None:
            result = self.controller.create_vault(
                master_password.get(), confirmation.get()
            )
            master_password.set("")
            confirmation.set("")
            self._reset_password_visibility()
            self._handle_transition_result(result, master_entry)

        ttk.Button(frame, text="Create Vault", command=submit).grid(
            row=2, column=0, sticky="e", pady=(18, 0)
        )
        ttk.Label(frame, textvariable=self._status, wraplength=540).grid(
            row=3, column=0, sticky="w", pady=(18, 0)
        )
        master_entry.bind("<Return>", submit)
        confirmation_entry.bind("<Return>", submit)
        master_entry.focus_set()

    def _show_unlock_screen(self) -> None:
        frame = self._new_frame()
        ttk.Label(frame, text="Unlock Vault", font=("TkDefaultFont", 18, "bold")).grid(
            row=0, column=0, sticky="w", pady=(0, 18)
        )
        master_password = tk.StringVar(master=self.root)
        form = ttk.Frame(frame)
        form.grid(row=1, column=0, sticky="ew")
        form.columnconfigure(1, weight=1)
        ttk.Label(form, text="Master password:").grid(row=0, column=0, sticky="w", padx=(0, 12))
        master_entry = ttk.Entry(form, textvariable=master_password, show="*", width=36)
        master_entry.grid(row=0, column=1, sticky="ew")
        self._set_password_entries(master_entry)
        ttk.Checkbutton(
            form,
            text="Show password",
            variable=self._show_password,
            command=self._toggle_password_visibility,
        ).grid(row=1, column=1, sticky="w", pady=(8, 0))

        def submit(event: object | None = None) -> None:
            result = self.controller.unlock(master_password.get())
            if result.clear_secret_fields:
                master_password.set("")
                self._reset_password_visibility()
            self._handle_transition_result(result, master_entry)

        ttk.Button(frame, text="Unlock", command=submit).grid(
            row=2, column=0, sticky="e", pady=(18, 0)
        )
        ttk.Label(frame, textvariable=self._status, wraplength=540).grid(
            row=3, column=0, sticky="w", pady=(18, 0)
        )
        master_entry.bind("<Return>", submit)
        master_entry.focus_set()

    def _show_vault_screen(self) -> None:
        frame = self._new_frame()
        frame.rowconfigure(1, weight=1)
        heading = ttk.Frame(frame)
        heading.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        heading.columnconfigure(0, weight=1)
        ttk.Label(heading, text="Vault", font=("TkDefaultFont", 18, "bold")).grid(row=0, column=0, sticky="w")
        ttk.Button(heading, text="Refresh", command=self._refresh_accounts).grid(row=0, column=1, padx=6)
        ttk.Button(heading, text="Lock", command=self._lock).grid(row=0, column=2)

        content = ttk.Panedwindow(frame, orient=tk.HORIZONTAL)
        content.grid(row=1, column=0, sticky="nsew")
        accounts_frame = ttk.LabelFrame(content, text="Accounts", padding=10)
        editor_frame = ttk.LabelFrame(content, text="Add or update", padding=10)
        content.add(accounts_frame, weight=2)
        content.add(editor_frame, weight=3)

        accounts_frame.rowconfigure(0, weight=1)
        accounts_frame.columnconfigure(0, weight=1)
        self._account_list = tk.Listbox(accounts_frame, exportselection=False, activestyle="dotbox")
        self._account_list.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(accounts_frame, orient=tk.VERTICAL, command=self._account_list.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self._account_list.configure(yscrollcommand=scrollbar.set)
        self._account_list.bind("<<ListboxSelect>>", self._select_account)
        self._account_list.bind("<Return>", lambda event: self._copy_selected())

        account_buttons = ttk.Frame(accounts_frame)
        account_buttons.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        account_buttons.columnconfigure((0, 1), weight=1)
        ttk.Button(account_buttons, text="Copy", command=self._copy_selected).grid(row=0, column=0, sticky="ew", padx=(0, 4))
        ttk.Button(account_buttons, text="Delete", command=self._delete_selected).grid(row=0, column=1, sticky="ew", padx=(4, 0))

        editor_frame.columnconfigure(1, weight=1)
        ttk.Label(editor_frame, text="Account:").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=5)
        account_entry = ttk.Entry(editor_frame, textvariable=self._account)
        account_entry.grid(row=0, column=1, sticky="ew", pady=5)
        ttk.Label(editor_frame, text="Password:").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=5)
        password_entry = ttk.Entry(editor_frame, textvariable=self._password, show="*")
        password_entry.grid(row=1, column=1, sticky="ew", pady=5)
        ttk.Label(editor_frame, text="Confirm:").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=5)
        confirmation_entry = ttk.Entry(editor_frame, textvariable=self._confirmation, show="*")
        confirmation_entry.grid(row=2, column=1, sticky="ew", pady=5)
        self._set_password_entries(password_entry, confirmation_entry)
        ttk.Checkbutton(
            editor_frame,
            text="Show password",
            variable=self._show_password,
            command=self._toggle_password_visibility,
        ).grid(row=3, column=1, sticky="w", pady=(4, 0))
        ttk.Button(editor_frame, text="Save Credential", command=self._save_credential).grid(row=4, column=0, columnspan=2, sticky="e", pady=(12, 0))
        confirmation_entry.bind("<Return>", self._on_save_return)

        ttk.Label(frame, textvariable=self._status, wraplength=560).grid(
            row=2, column=0, sticky="w", pady=(12, 0)
        )
        self._refresh_accounts()
        account_entry.focus_set()

    def _handle_transition_result(self, result: ControllerResult, focus: ttk.Entry) -> None:
        self._status.set(result.message)
        if result.ok:
            self._show_current_state()
        else:
            focus.focus_set()

    def _refresh_accounts(self, *, preserve_status: bool = False) -> None:
        result = self.controller.refresh_accounts()
        if not preserve_status:
            self._status.set(result.message)
        if not result.ok or self._account_list is None:
            return
        self._account_list.delete(0, tk.END)
        for account in result.accounts:
            self._account_list.insert(tk.END, account)

    def _select_account(self, event: object | None = None) -> None:
        account = self._selected_account()
        if account is not None:
            self._account.set(account)

    def _save_credential(self) -> None:
        if self._save_submission_pending:
            return
        self._save_submission_pending = True
        self.root.after_idle(self._reset_save_submission_guard)
        result = self.controller.set_credential(
            self._account.get(), self._password.get(), self._confirmation.get()
        )
        self._status.set(result.message)
        if result.clear_secret_fields:
            self._password.set("")
            self._confirmation.set("")
            self._reset_password_visibility()
        if result.ok:
            self._refresh_accounts(preserve_status=True)

    def _on_save_return(self, event: object | None = None) -> str:
        self._save_credential()
        return "break"

    def _reset_save_submission_guard(self) -> None:
        self._save_submission_pending = False

    def _set_password_entries(self, *entries: ttk.Entry) -> None:
        self._password_entries = list(entries)
        self._reset_password_visibility()

    def _toggle_password_visibility(self) -> None:
        display = "" if self._show_password.get() else "*"
        for entry in self._password_entries:
            entry.configure(show=display)

    def _reset_password_visibility(self) -> None:
        self._show_password.set(False)
        for entry in self._password_entries:
            entry.configure(show="*")

    def _copy_selected(self) -> None:
        account = self._selected_account() or self._account.get()
        result = self.controller.copy_credential(account)
        self._status.set(result.message)

    def _delete_selected(self) -> None:
        account = self._selected_account() or self._account.get()
        if not account.strip():
            self._status.set("Select an account.")
            return
        confirmed = messagebox.askyesno(
            APPLICATION_TITLE,
            f"Delete account '{account}'?",
            parent=self.root,
        )
        result = self.controller.delete_credential(account, confirmed=confirmed)
        self._status.set(result.message)
        if result.ok:
            self._account.set("")
            self._refresh_accounts(preserve_status=True)

    def _selected_account(self) -> str | None:
        if self._account_list is None:
            return None
        selection = self._account_list.curselection()
        if not selection:
            return None
        return str(self._account_list.get(selection[0]))

    def _lock(self) -> None:
        self.controller.lock()
        self._account.set("")
        self._password.set("")
        self._confirmation.set("")
        self._show_current_state()

    def _clipboard_copy(self, value: str) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(value)
        self.root.update_idletasks()

    def _clipboard_paste(self) -> str:
        return str(self.root.clipboard_get())

    def _on_close(self) -> None:
        self._reset_password_visibility()
        self.controller.close()
        self.root.destroy()


def main() -> None:
    """Create the Tk root and start the GUI event loop."""
    root = tk.Tk()
    PasswordLockerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
