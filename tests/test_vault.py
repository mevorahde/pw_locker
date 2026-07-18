import sqlite3

import pytest
import password_locker.vault as vault_module

from password_locker import (
    DEFAULT_KDF_PARAMETERS,
    AccountNotFoundError,
    KDFParameters,
    Vault,
    VaultAuthenticationError,
    VaultError,
    VaultFormatError,
    VaultIntegrityError,
    VaultValidationError,
)


TEST_KDF = KDFParameters(n=2**10, r=8, p=1)
FAKE_MASTER = "example-only master phrase"
FAKE_PASSWORD = "Example-Only-Credential-7!"


def create_vault(path):
    return Vault.create(path, FAKE_MASTER, kdf_parameters=TEST_KDF)


def mutate_blob(value):
    changed = bytearray(value)
    changed[0] ^= 1
    return bytes(changed)


def read_encrypted_record(path, account_name):
    with sqlite3.connect(path) as connection:
        return connection.execute(
            "SELECT nonce, ciphertext, tag FROM credentials WHERE account_name = ?",
            (account_name,),
        ).fetchone()


def test_create_and_reopen_empty_vault(tmp_path):
    path = tmp_path / "vault.db"
    with create_vault(path):
        pass

    with Vault.open(path, FAKE_MASTER) as reopened:
        with pytest.raises(AccountNotFoundError):
            reopened.get_credential("missing-example")


def test_incorrect_master_password_is_rejected(tmp_path):
    path = tmp_path / "vault.db"
    create_vault(path).close()

    with pytest.raises(VaultAuthenticationError, match="Unable to unlock vault"):
        Vault.open(path, "deliberately incorrect example")


def test_add_and_retrieve_credential(tmp_path):
    path = tmp_path / "vault.db"
    with create_vault(path) as vault:
        vault.set_credential("Example Account", FAKE_PASSWORD)
        assert vault.get_credential("Example Account") == FAKE_PASSWORD


def test_update_existing_normalized_account(tmp_path):
    path = tmp_path / "vault.db"
    updated = "Updated-Example-Only-8!"
    with create_vault(path) as vault:
        vault.set_credential("  Example Account  ", FAKE_PASSWORD)
        vault.set_credential("EXAMPLE ACCOUNT", updated)
        assert vault.get_credential("example account") == updated

    with sqlite3.connect(path) as connection:
        count = connection.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
    assert count == 1


def test_unicode_normalized_case_insensitive_lookup(tmp_path):
    path = tmp_path / "vault.db"
    with create_vault(path) as vault:
        vault.set_credential("ＦＡＫＥ Café", FAKE_PASSWORD)
        assert vault.get_credential("fake cafe\u0301") == FAKE_PASSWORD


@pytest.mark.parametrize("value", ["", " ", "\t\n"])
def test_blank_master_password_is_rejected(tmp_path, value):
    with pytest.raises(VaultValidationError):
        Vault.create(tmp_path / "vault.db", value, kdf_parameters=TEST_KDF)


@pytest.mark.parametrize("value", ["", " ", "\t\n"])
def test_blank_account_name_is_rejected(tmp_path, value):
    with create_vault(tmp_path / "vault.db") as vault:
        with pytest.raises(VaultValidationError):
            vault.set_credential(value, FAKE_PASSWORD)


@pytest.mark.parametrize("value", ["", " ", "\t\n"])
def test_blank_credential_password_is_rejected(tmp_path, value):
    with create_vault(tmp_path / "vault.db") as vault:
        with pytest.raises(VaultValidationError):
            vault.set_credential("fake-account", value)


def test_missing_account_does_not_decrypt_another_record(tmp_path):
    path = tmp_path / "vault.db"
    with create_vault(path) as vault:
        vault.set_credential("tampered-example", FAKE_PASSWORD)
    with sqlite3.connect(path) as connection:
        row = connection.execute(
            "SELECT ciphertext FROM credentials WHERE account_name = ?",
            ("tampered-example",),
        ).fetchone()
        connection.execute(
            "UPDATE credentials SET ciphertext = ? WHERE account_name = ?",
            (mutate_blob(row[0]), "tampered-example"),
        )

    with Vault.open(path, FAKE_MASTER) as vault:
        with pytest.raises(AccountNotFoundError):
            vault.get_credential("absent-example")


@pytest.mark.parametrize("column", ["ciphertext", "nonce", "tag"])
def test_modified_encrypted_component_is_detected(tmp_path, column):
    path = tmp_path / "vault.db"
    with create_vault(path) as vault:
        vault.set_credential("fake-account", FAKE_PASSWORD)
    with sqlite3.connect(path) as connection:
        value = connection.execute(
            f"SELECT {column} FROM credentials WHERE account_name = ?",
            ("fake-account",),
        ).fetchone()[0]
        connection.execute(
            f"UPDATE credentials SET {column} = ? WHERE account_name = ?",
            (mutate_blob(value), "fake-account"),
        )

    with Vault.open(path, FAKE_MASTER) as vault:
        with pytest.raises(VaultIntegrityError, match="could not be authenticated"):
            vault.get_credential("fake-account")


def test_modified_associated_account_context_is_detected(tmp_path):
    path = tmp_path / "vault.db"
    with create_vault(path) as vault:
        vault.set_credential("original-example", FAKE_PASSWORD)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE credentials SET account_name = ? WHERE account_name = ?",
            ("changed-example", "original-example"),
        )

    with Vault.open(path, FAKE_MASTER) as vault:
        with pytest.raises(VaultIntegrityError):
            vault.get_credential("changed-example")


def test_records_cannot_be_swapped_between_accounts(tmp_path):
    path = tmp_path / "vault.db"
    with create_vault(path) as vault:
        vault.set_credential("first-example", "First-Example-Only-1!")
        vault.set_credential("second-example", "Second-Example-Only-2!")
    first = read_encrypted_record(path, "first-example")
    second = read_encrypted_record(path, "second-example")
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE credentials SET nonce = ?, ciphertext = ?, tag = ? "
            "WHERE account_name = ?",
            (*second, "first-example"),
        )
        connection.execute(
            "UPDATE credentials SET nonce = ?, ciphertext = ?, tag = ? "
            "WHERE account_name = ?",
            (*first, "second-example"),
        )

    with Vault.open(path, FAKE_MASTER) as vault:
        with pytest.raises(VaultIntegrityError):
            vault.get_credential("first-example")


def test_identical_plaintext_uses_fresh_encryption_values(tmp_path):
    path = tmp_path / "vault.db"
    with create_vault(path) as vault:
        vault.set_credential("fake-account", FAKE_PASSWORD)
        first = read_encrypted_record(path, "fake-account")
        vault.set_credential("FAKE-ACCOUNT", FAKE_PASSWORD)
        second = read_encrypted_record(path, "fake-account")
    assert first != second
    assert first[0] != second[0]


def test_database_file_does_not_contain_plaintext_password(tmp_path):
    path = tmp_path / "vault.db"
    with create_vault(path) as vault:
        vault.set_credential("fake-account", FAKE_PASSWORD)
    assert FAKE_PASSWORD.encode("utf-8") not in path.read_bytes()
    assert FAKE_MASTER.encode("utf-8") not in path.read_bytes()


def test_schema_has_no_master_password_or_raw_key_column(tmp_path):
    path = tmp_path / "vault.db"
    create_vault(path).close()
    with sqlite3.connect(path) as connection:
        tables = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = ? ORDER BY name", ("table",)
        ).fetchall()
        columns = {
            table: [row[1] for row in connection.execute(f"PRAGMA table_info({table})")]
            for (table,) in tables
        }
        metadata_names = {
            row[0] for row in connection.execute("SELECT name FROM metadata").fetchall()
        }

    assert columns == {
        "credentials": ["account_name", "nonce", "ciphertext", "tag"],
        "metadata": ["name", "value"],
    }
    assert "schema_version" in metadata_names
    assert not {
        "master_password",
        "password",
        "derived_key",
        "encryption_key",
        "raw_key",
    } & metadata_names


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("kdf_n", b"not-a-number"),
        ("kdf_n", b"1073741824"),
        ("kdf_n", b"12345"),
        ("kdf_r", b"0"),
        ("kdf_p", b"999"),
    ],
)
def test_malformed_or_unreasonable_kdf_metadata_is_rejected(tmp_path, name, value):
    path = tmp_path / "vault.db"
    create_vault(path).close()
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE metadata SET value = ? WHERE name = ?", (value, name))

    with pytest.raises(VaultFormatError, match="KDF"):
        Vault.open(path, FAKE_MASTER)


def test_production_kdf_defaults_are_stronger_than_test_settings():
    assert DEFAULT_KDF_PARAMETERS.n > TEST_KDF.n
    assert DEFAULT_KDF_PARAMETERS.r >= TEST_KDF.r
    assert DEFAULT_KDF_PARAMETERS.p >= TEST_KDF.p


def test_context_manager_closes_vault(tmp_path):
    path = tmp_path / "vault.db"
    with create_vault(path) as vault:
        pass
    with pytest.raises(VaultError, match="closed"):
        vault.get_credential("fake-account")


@pytest.mark.parametrize("kind", ["non-sqlite", "incomplete"])
def test_invalid_database_returns_domain_format_error(tmp_path, kind):
    path = tmp_path / "vault.db"
    if kind == "non-sqlite":
        path.write_bytes(b"deliberately invalid temporary test file")
    else:
        with sqlite3.connect(path) as connection:
            connection.execute("CREATE TABLE incomplete (value BLOB)")

    with pytest.raises(VaultFormatError) as error:
        Vault.open(path, FAKE_MASTER)
    assert type(error.value) is VaultFormatError
    assert error.value.__cause__ is None


def test_missing_credentials_table_returns_domain_format_error(tmp_path):
    path = tmp_path / "vault.db"
    create_vault(path).close()
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE credentials")

    with pytest.raises(VaultFormatError, match="schema") as error:
        Vault.open(path, FAKE_MASTER)
    assert error.value.__cause__ is None


def test_failed_creation_removes_partial_vault(tmp_path, monkeypatch):
    path = tmp_path / "vault.db"

    def fail_encryption(*args, **kwargs):
        raise ValueError("deliberate internal test failure")

    monkeypatch.setattr(vault_module, "_encrypt", fail_encryption)
    with pytest.raises(VaultError, match="could not be created") as error:
        Vault.create(path, FAKE_MASTER, kdf_parameters=TEST_KDF)
    assert error.value.__cause__ is None
    assert not path.exists()


def test_close_is_idempotent(tmp_path):
    vault = create_vault(tmp_path / "vault.db")
    vault.close()
    vault.close()


@pytest.mark.parametrize(
    "name", ["verifier_nonce", "verifier_ciphertext", "verifier_tag"]
)
def test_modified_verifier_component_rejects_open(tmp_path, name):
    path = tmp_path / "vault.db"
    create_vault(path).close()
    with sqlite3.connect(path) as connection:
        value = connection.execute(
            "SELECT value FROM metadata WHERE name = ?", (name,)
        ).fetchone()[0]
        connection.execute(
            "UPDATE metadata SET value = ? WHERE name = ?",
            (mutate_blob(value), name),
        )

    with pytest.raises(VaultAuthenticationError, match="Unable to unlock vault") as error:
        Vault.open(path, FAKE_MASTER)
    assert error.value.__cause__ is None


@pytest.mark.parametrize("change", ["missing", "unexpected"])
def test_missing_or_unexpected_metadata_is_rejected(tmp_path, change):
    path = tmp_path / "vault.db"
    create_vault(path).close()
    with sqlite3.connect(path) as connection:
        if change == "missing":
            connection.execute("DELETE FROM metadata WHERE name = ?", ("kdf_p",))
        else:
            connection.execute(
                "INSERT INTO metadata (name, value) VALUES (?, ?)",
                ("unexpected", b"example"),
            )

    with pytest.raises(VaultFormatError, match="metadata"):
        Vault.open(path, FAKE_MASTER)


def test_production_kdf_defaults_pass_bounded_validation():
    DEFAULT_KDF_PARAMETERS.validate()
