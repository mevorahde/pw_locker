"""Versioned SQLite vault using scrypt and AES-256-GCM."""

from __future__ import annotations

import sqlite3
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes


SCHEMA_VERSION: Final = 1
KEY_LENGTH: Final = 32
SALT_LENGTH: Final = 16
NONCE_LENGTH: Final = 12
TAG_LENGTH: Final = 16
MAX_ACCOUNT_BYTES: Final = 1024
VERIFIER_PLAINTEXT: Final = b"password-locker-vault-verifier-v1"
VERIFIER_CONTEXT: Final = b"password-locker:vault-verifier:v1"
ACCOUNT_CONTEXT_PREFIX: Final = b"password-locker:account:v1:"

MIN_SCRYPT_N: Final = 2**10
MAX_SCRYPT_N: Final = 2**20
MAX_SCRYPT_R: Final = 16
MAX_SCRYPT_P: Final = 8
MAX_SCRYPT_MEMORY_BYTES: Final = 512 * 1024 * 1024
MAX_SCRYPT_WORK_FACTOR: Final = 2**24


class VaultError(Exception):
    """Base class for expected vault errors."""


class VaultValidationError(VaultError):
    """Raised when caller input is invalid."""


class VaultAuthenticationError(VaultError):
    """Raised when a vault cannot be authenticated."""


class VaultIntegrityError(VaultError):
    """Raised when an encrypted credential cannot be authenticated."""


class VaultFormatError(VaultError):
    """Raised when the vault schema or metadata is invalid."""


class AccountNotFoundError(VaultError):
    """Raised when a requested account is absent."""


@dataclass(frozen=True)
class KDFParameters:
    """Bounded scrypt work factors stored with each vault."""

    n: int
    r: int
    p: int

    def validate(self) -> None:
        if (
            isinstance(self.n, bool)
            or not isinstance(self.n, int)
            or self.n < MIN_SCRYPT_N
            or self.n > MAX_SCRYPT_N
            or self.n & (self.n - 1)
        ):
            raise VaultFormatError("Vault KDF parameters are invalid.")
        if (
            isinstance(self.r, bool)
            or not isinstance(self.r, int)
            or self.r < 1
            or self.r > MAX_SCRYPT_R
        ):
            raise VaultFormatError("Vault KDF parameters are invalid.")
        if (
            isinstance(self.p, bool)
            or not isinstance(self.p, int)
            or self.p < 1
            or self.p > MAX_SCRYPT_P
        ):
            raise VaultFormatError("Vault KDF parameters are invalid.")
        if 128 * self.n * self.r > MAX_SCRYPT_MEMORY_BYTES:
            raise VaultFormatError("Vault KDF parameters are invalid.")
        if self.n * self.r * self.p > MAX_SCRYPT_WORK_FACTOR:
            raise VaultFormatError("Vault KDF parameters are invalid.")


DEFAULT_KDF_PARAMETERS: Final = KDFParameters(n=2**17, r=8, p=1)


class Vault:
    """An open secure vault backed by one SQLite database."""

    def __init__(self, connection: sqlite3.Connection, key: bytes) -> None:
        self._connection: sqlite3.Connection | None = connection
        self._key = bytearray(key)

    @classmethod
    def create(
        cls,
        path: str | Path,
        master_password: str,
        *,
        kdf_parameters: KDFParameters = DEFAULT_KDF_PARAMETERS,
    ) -> Vault:
        """Create and open a new vault."""
        password = _require_nonblank(master_password, "Master password")
        kdf_parameters.validate()
        vault_path = Path(path)
        if vault_path.exists():
            raise VaultError("Vault already exists.")

        connection: sqlite3.Connection | None = None
        key_buffer: bytearray | None = None
        reserved_path = False
        complete = False
        try:
            with vault_path.open("xb"):
                pass
            reserved_path = True
            connection = sqlite3.connect(vault_path)
            connection.execute("PRAGMA foreign_keys = ON")
            salt = get_random_bytes(SALT_LENGTH)
            key = _derive_key(password, salt, kdf_parameters)
            key_buffer = bytearray(key)
            verifier_nonce, verifier_ciphertext, verifier_tag = _encrypt(
                key_buffer, VERIFIER_PLAINTEXT, VERIFIER_CONTEXT
            )
            metadata = (
                ("schema_version", _encode_int(SCHEMA_VERSION)),
                ("kdf_name", b"scrypt"),
                ("kdf_salt", salt),
                ("kdf_n", _encode_int(kdf_parameters.n)),
                ("kdf_r", _encode_int(kdf_parameters.r)),
                ("kdf_p", _encode_int(kdf_parameters.p)),
                ("verifier_nonce", verifier_nonce),
                ("verifier_ciphertext", verifier_ciphertext),
                ("verifier_tag", verifier_tag),
            )
            with connection:
                connection.execute(
                    "CREATE TABLE metadata ("
                    "name TEXT PRIMARY KEY, "
                    "value BLOB NOT NULL"
                    ")"
                )
                connection.execute(
                    "CREATE TABLE credentials ("
                    "account_name TEXT PRIMARY KEY, "
                    "nonce BLOB NOT NULL, "
                    "ciphertext BLOB NOT NULL, "
                    "tag BLOB NOT NULL"
                    ")"
                )
                connection.executemany(
                    "INSERT INTO metadata (name, value) VALUES (?, ?)", metadata
                )
            vault = cls(connection, key_buffer)
            connection = None
            complete = True
            return vault
        except (OSError, sqlite3.Error, ValueError, MemoryError):
            raise VaultError("Vault could not be created.") from None
        finally:
            if key_buffer is not None:
                _clear(key_buffer)
            if connection is not None:
                try:
                    connection.close()
                except sqlite3.Error:
                    pass
            if reserved_path and not complete:
                _remove_partial_vault(vault_path)

    @classmethod
    def open(cls, path: str | Path, master_password: str) -> Vault:
        """Open an existing vault after authenticating its master password."""
        password = _require_nonblank(master_password, "Master password")
        vault_path = Path(path)
        if not vault_path.is_file():
            raise VaultError("Vault does not exist.")

        try:
            connection = sqlite3.connect(vault_path)
        except sqlite3.Error:
            raise VaultFormatError("Vault database is invalid.") from None
        key_buffer: bytearray | None = None
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            _validate_schema(connection)
            metadata = _load_metadata(connection)
            salt, parameters = _validated_kdf_metadata(metadata)
            try:
                key = _derive_key(password, salt, parameters)
            except (ValueError, MemoryError):
                raise VaultFormatError("Vault KDF metadata is invalid.") from None
            key_buffer = bytearray(key)
            try:
                verifier = _decrypt(
                    key_buffer,
                    _required_blob(metadata, "verifier_nonce", NONCE_LENGTH),
                    _required_blob(metadata, "verifier_ciphertext", len(VERIFIER_PLAINTEXT)),
                    _required_blob(metadata, "verifier_tag", TAG_LENGTH),
                    VERIFIER_CONTEXT,
                )
            except ValueError:
                raise VaultAuthenticationError("Unable to unlock vault.") from None
            if verifier != VERIFIER_PLAINTEXT:
                raise VaultAuthenticationError("Unable to unlock vault.")
            vault = cls(connection, key_buffer)
            connection = None
            return vault
        except sqlite3.Error:
            raise VaultFormatError("Vault database is invalid.") from None
        finally:
            if key_buffer is not None:
                _clear(key_buffer)
            if connection is not None:
                try:
                    connection.close()
                except sqlite3.Error:
                    pass

    def set_credential(self, account_name: str, password: str) -> None:
        """Add or replace one credential by normalized account name."""
        normalized = _normalize_account_name(account_name)
        plaintext = _require_nonblank(password, "Password").encode("utf-8")
        try:
            nonce, ciphertext, tag = _encrypt(
                self._active_key(), plaintext, _account_context(normalized)
            )
        except (ValueError, MemoryError):
            raise VaultError("Credential could not be stored.") from None
        connection = self._active_connection()
        try:
            with connection:
                connection.execute(
                    "INSERT INTO credentials (account_name, nonce, ciphertext, tag) "
                    "VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(account_name) DO UPDATE SET "
                    "nonce = excluded.nonce, "
                    "ciphertext = excluded.ciphertext, "
                    "tag = excluded.tag",
                    (normalized, nonce, ciphertext, tag),
                )
        except sqlite3.Error:
            raise VaultError("Credential could not be stored.") from None

    def get_credential(self, account_name: str) -> str:
        """Retrieve and authenticate only the specifically requested credential."""
        normalized = _normalize_account_name(account_name)
        try:
            row = self._active_connection().execute(
                "SELECT nonce, ciphertext, tag FROM credentials WHERE account_name = ?",
                (normalized,),
            ).fetchone()
        except sqlite3.Error:
            raise VaultFormatError("Vault database is invalid.") from None
        if row is None:
            raise AccountNotFoundError("Account was not found.")
        nonce, ciphertext, tag = row
        if not (
            isinstance(nonce, bytes)
            and len(nonce) == NONCE_LENGTH
            and isinstance(ciphertext, bytes)
            and isinstance(tag, bytes)
            and len(tag) == TAG_LENGTH
        ):
            raise VaultIntegrityError("Credential could not be authenticated.")
        try:
            plaintext = _decrypt(
                self._active_key(), nonce, ciphertext, tag, _account_context(normalized)
            )
            return plaintext.decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            raise VaultIntegrityError("Credential could not be authenticated.") from None

    def close(self) -> None:
        """Close SQLite resources and clear the in-memory key buffer."""
        connection, self._connection = self._connection, None
        try:
            if connection is not None:
                connection.close()
        except sqlite3.Error:
            raise VaultError("Vault could not be closed cleanly.") from None
        finally:
            _clear(self._key)

    def __enter__(self) -> Vault:
        self._active_connection()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def _active_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise VaultError("Vault is closed.")
        return self._connection

    def _active_key(self) -> bytearray:
        self._active_connection()
        return self._key


def _require_nonblank(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise VaultValidationError(f"{label} must not be blank.")
    return value


def _normalize_account_name(account_name: str) -> str:
    value = _require_nonblank(account_name, "Account name")
    normalized = unicodedata.normalize("NFKC", value).strip().casefold()
    encoded = normalized.encode("utf-8")
    if not encoded or len(encoded) > MAX_ACCOUNT_BYTES:
        raise VaultValidationError("Account name is invalid.")
    return normalized


def _account_context(normalized_account_name: str) -> bytes:
    return ACCOUNT_CONTEXT_PREFIX + normalized_account_name.encode("utf-8")


def _derive_key(password: str, salt: bytes, parameters: KDFParameters) -> bytes:
    return scrypt(
        password.encode("utf-8"),
        salt,
        key_len=KEY_LENGTH,
        N=parameters.n,
        r=parameters.r,
        p=parameters.p,
    )


def _encrypt(key: bytes | bytearray, plaintext: bytes, context: bytes) -> tuple[bytes, bytes, bytes]:
    cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=get_random_bytes(NONCE_LENGTH), mac_len=TAG_LENGTH)
    cipher.update(context)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce, ciphertext, tag


def _decrypt(
    key: bytes | bytearray,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    context: bytes,
) -> bytes:
    cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=nonce, mac_len=TAG_LENGTH)
    cipher.update(context)
    return cipher.decrypt_and_verify(ciphertext, tag)


def _load_metadata(connection: sqlite3.Connection) -> dict[str, bytes]:
    try:
        rows = connection.execute("SELECT name, value FROM metadata").fetchall()
    except sqlite3.Error:
        raise VaultFormatError("Vault metadata is invalid.") from None
    if len(rows) != 9:
        raise VaultFormatError("Vault metadata is invalid.")
    metadata: dict[str, bytes] = {}
    for name, value in rows:
        if not isinstance(name, str) or not isinstance(value, bytes) or name in metadata:
            raise VaultFormatError("Vault metadata is invalid.")
        metadata[name] = value
    return metadata


def _validate_schema(connection: sqlite3.Connection) -> None:
    expected_metadata = [
        ("name", "TEXT", 0, 1),
        ("value", "BLOB", 1, 0),
    ]
    expected_credentials = [
        ("account_name", "TEXT", 0, 1),
        ("nonce", "BLOB", 1, 0),
        ("ciphertext", "BLOB", 1, 0),
        ("tag", "BLOB", 1, 0),
    ]
    try:
        metadata_rows = connection.execute("PRAGMA table_info(metadata)").fetchall()
        credential_rows = connection.execute("PRAGMA table_info(credentials)").fetchall()
    except sqlite3.Error:
        raise VaultFormatError("Vault schema is invalid.") from None
    metadata_schema = [(row[1], row[2], row[3], row[5]) for row in metadata_rows]
    credential_schema = [(row[1], row[2], row[3], row[5]) for row in credential_rows]
    if metadata_schema != expected_metadata or credential_schema != expected_credentials:
        raise VaultFormatError("Vault schema is invalid.")


def _validated_kdf_metadata(metadata: dict[str, bytes]) -> tuple[bytes, KDFParameters]:
    if _parse_int(metadata, "schema_version", 1, SCHEMA_VERSION) != SCHEMA_VERSION:
        raise VaultFormatError("Vault schema version is unsupported.")
    if metadata.get("kdf_name") != b"scrypt":
        raise VaultFormatError("Vault KDF metadata is invalid.")
    salt = _required_blob(metadata, "kdf_salt", SALT_LENGTH)
    parameters = KDFParameters(
        n=_parse_int(metadata, "kdf_n", MIN_SCRYPT_N, MAX_SCRYPT_N),
        r=_parse_int(metadata, "kdf_r", 1, MAX_SCRYPT_R),
        p=_parse_int(metadata, "kdf_p", 1, MAX_SCRYPT_P),
    )
    parameters.validate()
    return salt, parameters


def _required_blob(metadata: dict[str, bytes], name: str, length: int) -> bytes:
    value = metadata.get(name)
    if not isinstance(value, bytes) or len(value) != length:
        raise VaultFormatError("Vault metadata is invalid.")
    return value


def _parse_int(metadata: dict[str, bytes], name: str, minimum: int, maximum: int) -> int:
    raw = metadata.get(name)
    if not isinstance(raw, bytes) or not raw or len(raw) > 10 or not raw.isdigit():
        raise VaultFormatError("Vault KDF metadata is invalid.")
    value = int(raw)
    if value < minimum or value > maximum:
        raise VaultFormatError("Vault KDF metadata is invalid.")
    return value


def _encode_int(value: int) -> bytes:
    return str(value).encode("ascii")


def _clear(buffer: bytearray) -> None:
    for index in range(len(buffer)):
        buffer[index] = 0


def _remove_partial_vault(path: Path) -> None:
    for suffix in ("", "-journal", "-shm", "-wal"):
        try:
            Path(f"{path}{suffix}").unlink(missing_ok=True)
        except OSError:
            pass
