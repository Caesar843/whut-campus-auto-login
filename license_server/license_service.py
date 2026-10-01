"""免费版授权签发。

免费版只有一种授权：设备注册成功后直接获得一条永久有效的 free 授权。
按时间分级的授权计算与关联字段已随旧模块移除。
"""

from __future__ import annotations

from datetime import datetime, timezone

from license_server.signer import datetime_text


FREE_LICENSE_TYPE = "free"
FREE_LICENSE_SOURCE = "free"
FREE_LICENSE_EXPIRES_AT = datetime(9999, 12, 31, 0, 0, 0, tzinfo=timezone.utc)


def create_license(
    connection,
    *,
    device_id: int,
    license_type: str,
    source: str,
    starts_at: datetime,
    expires_at: datetime,
):
    cursor = connection.execute(
        """
        INSERT INTO licenses (
            device_id, license_type, status, starts_at, expires_at, source, order_id,
            created_at, revoked_at
        ) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, NULL)
        """,
        (
            device_id,
            license_type,
            "active",
            datetime_text(starts_at),
            datetime_text(expires_at),
            source,
            datetime_text(starts_at),
        ),
    )
    return connection.execute(
        "SELECT * FROM licenses WHERE id = ?",
        (int(cursor.lastrowid),),
    ).fetchone()


def create_free_license(connection, *, device_id: int, starts_at: datetime):
    return create_license(
        connection,
        device_id=device_id,
        license_type=FREE_LICENSE_TYPE,
        source=FREE_LICENSE_SOURCE,
        starts_at=starts_at,
        expires_at=FREE_LICENSE_EXPIRES_AT,
    )


def latest_license(connection, device_id: int):
    return connection.execute(
        """
        SELECT * FROM licenses
        WHERE device_id = ?
        ORDER BY id DESC LIMIT 1
        """,
        (device_id,),
    ).fetchone()


def active_license(connection, device_id: int):
    """返回该设备当前可用的授权（active 且未过期），没有则返回 None。"""
    return connection.execute(
        """
        SELECT * FROM licenses
        WHERE device_id = ?
          AND status = 'active'
          AND expires_at > ?
        ORDER BY id DESC LIMIT 1
        """,
        (device_id, datetime_text(datetime.now(timezone.utc))),
    ).fetchone()