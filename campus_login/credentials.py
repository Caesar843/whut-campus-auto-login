import ctypes
import sys
from typing import Optional, Protocol


DEFAULT_CREDENTIAL_TARGET = "WHUTCampusAutoLogin/campus-network-password"
_CRED_TYPE_GENERIC = 1
_CRED_PERSIST_LOCAL_MACHINE = 2
_ERROR_NOT_FOUND = 1168
_MAX_CREDENTIAL_BLOB_SIZE = 5120


class CredentialStore(Protocol):
    def save_password(self, password: str) -> None:
        """Save the campus network password in a secure local credential store."""

    def load_password(self) -> Optional[str]:
        """Load the campus network password from secure local storage."""

    def delete_password(self) -> bool:
        """Delete the campus network password. Return True when one existed."""

    def has_password(self) -> bool:
        """Return whether a campus network password is saved."""


class CredentialStoreError(RuntimeError):
    """Raised when the secure credential store cannot complete an operation."""


class CredentialStoreUnavailable(CredentialStoreError):
    """Raised when the platform has no supported credential backend."""


class UnsupportedCredentialStore:
    def save_password(self, password: str) -> None:
        raise CredentialStoreUnavailable(
            "Secure credential storage is only available on Windows in this build."
        )

    def load_password(self) -> Optional[str]:
        raise CredentialStoreUnavailable(
            "Secure credential storage is only available on Windows in this build."
        )

    def delete_password(self) -> bool:
        raise CredentialStoreUnavailable(
            "Secure credential storage is only available on Windows in this build."
        )

    def has_password(self) -> bool:
        raise CredentialStoreUnavailable(
            "Secure credential storage is only available on Windows in this build."
        )


class WindowsCredentialStore:
    def __init__(self, target_name: str = DEFAULT_CREDENTIAL_TARGET):
        if sys.platform != "win32":
            raise CredentialStoreUnavailable(
                "Windows Credential Manager is only available on Windows."
            )
        self.target_name = target_name
        self._advapi32 = ctypes.WinDLL("Advapi32", use_last_error=True)
        self._configure_api()

    def _configure_api(self) -> None:
        self._advapi32.CredWriteW.argtypes = [ctypes.POINTER(_CREDENTIALW), ctypes.c_uint32]
        self._advapi32.CredWriteW.restype = ctypes.c_bool
        self._advapi32.CredReadW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.POINTER(_CREDENTIALW)),
        ]
        self._advapi32.CredReadW.restype = ctypes.c_bool
        self._advapi32.CredDeleteW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
        ]
        self._advapi32.CredDeleteW.restype = ctypes.c_bool
        self._advapi32.CredFree.argtypes = [ctypes.c_void_p]
        self._advapi32.CredFree.restype = None

    def save_password(self, password: str) -> None:
        blob = password.encode("utf-16-le")
        if len(blob) > _MAX_CREDENTIAL_BLOB_SIZE:
            raise CredentialStoreError("Password is too large for Windows Credential Manager.")

        blob_buffer = ctypes.create_string_buffer(blob)
        credential = _CREDENTIALW()
        credential.Flags = 0
        credential.Type = _CRED_TYPE_GENERIC
        credential.TargetName = self.target_name
        credential.Comment = "WHUT campus network password"
        credential.CredentialBlobSize = len(blob)
        credential.CredentialBlob = ctypes.cast(blob_buffer, ctypes.POINTER(ctypes.c_ubyte))
        credential.Persist = _CRED_PERSIST_LOCAL_MACHINE
        credential.AttributeCount = 0
        credential.Attributes = None
        credential.TargetAlias = None
        credential.UserName = "WHUTCampusAutoLogin"

        if not self._advapi32.CredWriteW(ctypes.byref(credential), 0):
            raise _credential_error("Failed to save password in Windows Credential Manager.")

    def load_password(self) -> Optional[str]:
        credential_ptr = ctypes.POINTER(_CREDENTIALW)()
        if not self._advapi32.CredReadW(
            self.target_name,
            _CRED_TYPE_GENERIC,
            0,
            ctypes.byref(credential_ptr),
        ):
            error_code = ctypes.get_last_error()
            if error_code == _ERROR_NOT_FOUND:
                return None
            raise _credential_error("Failed to read password from Windows Credential Manager.")

        try:
            credential = credential_ptr.contents
            raw = ctypes.string_at(
                credential.CredentialBlob,
                credential.CredentialBlobSize,
            )
            return raw.decode("utf-16-le")
        finally:
            self._advapi32.CredFree(credential_ptr)

    def delete_password(self) -> bool:
        if self._advapi32.CredDeleteW(self.target_name, _CRED_TYPE_GENERIC, 0):
            return True
        error_code = ctypes.get_last_error()
        if error_code == _ERROR_NOT_FOUND:
            return False
        raise _credential_error("Failed to delete password from Windows Credential Manager.")

    def has_password(self) -> bool:
        return self.load_password() is not None


class _FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", ctypes.c_uint32),
        ("dwHighDateTime", ctypes.c_uint32),
    ]


class _CREDENTIALW(ctypes.Structure):
    _fields_ = [
        ("Flags", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
        ("TargetName", ctypes.c_wchar_p),
        ("Comment", ctypes.c_wchar_p),
        ("LastWritten", _FILETIME),
        ("CredentialBlobSize", ctypes.c_uint32),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
        ("Persist", ctypes.c_uint32),
        ("AttributeCount", ctypes.c_uint32),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", ctypes.c_wchar_p),
        ("UserName", ctypes.c_wchar_p),
    ]


def _credential_error(message: str) -> CredentialStoreError:
    error_code = ctypes.get_last_error()
    error = ctypes.WinError(error_code)
    return CredentialStoreError(f"{message} Windows error {error_code}: {error.strerror}")


def get_default_credential_store() -> CredentialStore:
    if sys.platform == "win32":
        return WindowsCredentialStore()
    return UnsupportedCredentialStore()
