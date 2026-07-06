from __future__ import annotations

from datetime import datetime

from license_server.signer import datetime_text


def create_license(
    connection,
    *,
    device_id: int,
    license_type: str,
    source: str,
    starts_at: datetime,
    expires_at: datetime,
    order_id: str | None = None,
):
    cursor = connection.execute(
        """
        INSERT INTO licenses (
            device_id, license_type, status, starts_at, expires_at, source, order_id,
            created_at, revoked_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
        """,
        (
            device_id,
            license_type,
            "active",
            datetime_text(starts_at),
            datetime_text(expires_at),
            source,
            order_id,
            datetime_text(starts_at),
        ),
    )
    return connection.execute(
        "SELECT * FROM licenses WHERE id = ?",
        (int(cursor.lastrowid),),
    ).fetchone()


def latest_license(connection, device_id: int):
    paid = latest_paid_license(connection, device_id)
    if paid is not None:
        return paid
    return connection.execute(
        """
        SELECT * FROM licenses
        WHERE device_id = ?
        ORDER BY id DESC LIMIT 1
        """,
        (device_id,),
    ).fetchone()


def latest_paid_license(connection, device_id: int):
    return connection.execute(
        """
        SELECT * FROM licenses
        WHERE device_id = ? AND license_type = 'paid'
        ORDER BY id DESC LIMIT 1
        """,
        (device_id,),
    ).fetchone()


def paid_active_license_exists(
    connection,
    *,
    device_fingerprint_hash: str,
    now: datetime,
) -> bool:
    row = connection.execute(
        """
        SELECT licenses.id
        FROM licenses
        JOIN devices ON devices.id = licenses.device_id
        WHERE devices.device_fingerprint_hash = ?
          AND licenses.license_type = 'paid'
          AND licenses.status = 'active'
          AND licenses.expires_at > ?
        LIMIT 1
        """,
        (device_fingerprint_hash, datetime_text(now)),
    ).fetchone()
    return row is not None
