from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from campus_login.local_config import default_config_path


LOGGER = logging.getLogger(__name__)
PAYMENT_STATE_FILE_NAME = "payment_state.json"
PAYMENT_STATE_SCHEMA_VERSION = 1
TERMINAL_STATUSES = {"PAID", "CLOSED"}
ORDER_STATUSES = {"CREATED", "WAITING_PAYMENT", "PAID", "CLOSED", "ABNORMAL"}


@dataclass(frozen=True)
class PaymentState:
    order_id: str
    product_code: str
    status: str
    created_at: str
    expires_at: str
    updated_at: str
    schema_version: int = PAYMENT_STATE_SCHEMA_VERSION


class PaymentStateStore:
    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = Path(path) if path is not None else default_payment_state_path()

    def load(self) -> Optional[PaymentState]:
        if not self.path.exists():
            return None
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            LOGGER.warning("Local payment state is unreadable: %s", exc.__class__.__name__)
            return None
        return _payment_state(payload)

    def save(self, state: PaymentState) -> None:
        normalized = _validated_state(state)
        if normalized.status in TERMINAL_STATUSES:
            self.clear()
            return

        payload = {
            "schema_version": PAYMENT_STATE_SCHEMA_VERSION,
            "order_id": normalized.order_id,
            "product_code": normalized.product_code,
            "status": normalized.status,
            "created_at": normalized.created_at,
            "expires_at": normalized.expires_at,
            "updated_at": normalized.updated_at,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp_path: Optional[Path] = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                delete=False,
            ) as temp_file:
                temp_path = Path(temp_file.name)
                temp_file.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
            os.replace(temp_path, self.path)
            temp_path = None
        finally:
            if temp_path is not None:
                try:
                    temp_path.unlink(missing_ok=True)
                except OSError:
                    LOGGER.warning("Failed to clean up temporary payment state file.")

    def clear(self) -> bool:
        existed = self.path.exists()
        try:
            self.path.unlink(missing_ok=True)
        except OSError as exc:
            LOGGER.warning("Failed to delete payment state: %s", exc.__class__.__name__)
            return False
        return existed


def default_payment_state_path() -> Path:
    return default_config_path().with_name(PAYMENT_STATE_FILE_NAME)


def new_payment_state(
    *,
    order_id: str,
    product_code: str,
    status: str,
    created_at: str,
    expires_at: str,
) -> PaymentState:
    return PaymentState(
        order_id=order_id,
        product_code=product_code,
        status=status,
        created_at=created_at,
        expires_at=expires_at,
        updated_at=_utc_now(),
    )


def _payment_state(payload: object) -> Optional[PaymentState]:
    if not isinstance(payload, dict):
        return None
    try:
        return _validated_state(
            PaymentState(
                schema_version=int(payload.get("schema_version")),
                order_id=str(payload.get("order_id") or ""),
                product_code=str(payload.get("product_code") or ""),
                status=str(payload.get("status") or ""),
                created_at=str(payload.get("created_at") or ""),
                expires_at=str(payload.get("expires_at") or ""),
                updated_at=str(payload.get("updated_at") or ""),
            )
        )
    except (TypeError, ValueError):
        return None


def _validated_state(state: PaymentState) -> PaymentState:
    order_id = str(state.order_id or "").strip()
    product_code = str(state.product_code or "").strip()
    status = str(state.status or "").strip().upper()
    created_at = str(state.created_at or "").strip()
    expires_at = str(state.expires_at or "").strip()
    updated_at = str(state.updated_at or "").strip()
    if state.schema_version != PAYMENT_STATE_SCHEMA_VERSION:
        raise ValueError("invalid_schema_version")
    if not order_id or not product_code:
        raise ValueError("missing_order")
    if status not in ORDER_STATUSES:
        raise ValueError("invalid_status")
    for value in (created_at, expires_at, updated_at):
        if _parse_utc(value) is None:
            raise ValueError("invalid_time")
    return PaymentState(
        schema_version=PAYMENT_STATE_SCHEMA_VERSION,
        order_id=order_id,
        product_code=product_code,
        status=status,
        created_at=created_at,
        expires_at=expires_at,
        updated_at=updated_at,
    )


def _parse_utc(value: str) -> Optional[datetime]:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
