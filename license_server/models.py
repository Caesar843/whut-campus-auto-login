from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LicenseResponse:
    status: str
    product_id: str
    device_fingerprint_hash: str
    license_id: str
    license_type: str
    license_status: str
    issued_at: str
    expires_at: str
    signed_license_token: str

    def as_dict(self) -> dict[str, str]:
        return {
            "status": self.status,
            "product_id": self.product_id,
            "device_fingerprint_hash": self.device_fingerprint_hash,
            "license_id": self.license_id,
            "license_type": self.license_type,
            "license_status": self.license_status,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "signed_license_token": self.signed_license_token,
        }
