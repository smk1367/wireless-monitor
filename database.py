#!/usr/bin/env python3

import sqlite3
import json
from datetime import datetime
from zoneinfo import ZoneInfo
from pathlib import Path


DB_PATH = str(
    Path(__file__).parent / "data" / "data.db"
)


SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,

    device_type TEXT,
    hostname TEXT,

    ssid TEXT,
    frequency TEXT,
    tx_power TEXT,
    rx_power TEXT,
    signal_strength TEXT,
    mac_address TEXT,

    interface_name TEXT,
    channel TEXT,
    bandwidth TEXT,
    mode TEXT,
    noise_floor TEXT,
    ccq TEXT,
    uptime TEXT,

    model TEXT,
    firmware_version TEXT,
    serial_number TEXT,
    vendor TEXT,

    modulation TEXT,
    polarization TEXT,
    antenna_gain TEXT,
    capacity TEXT,

    latitude TEXT,
    longitude TEXT,
    province TEXT,
    city TEXT,

    wireless_registration TEXT,
    interfaces TEXT,
    cpu_memory TEXT,
    ip_routes TEXT,
    bridges TEXT,
    pppoe_vpn TEXT,

    raw_data TEXT,

    last_seen TEXT,
    last_updated TEXT,

    scan_status TEXT DEFAULT 'unknown',
    credential_id TEXT,

    manual_latitude TEXT DEFAULT '',
    manual_longitude TEXT DEFAULT '',
    manual_province TEXT DEFAULT '',
    manual_city TEXT DEFAULT '',
    manual_antenna_gain TEXT DEFAULT '',
    manual_polarization TEXT DEFAULT '',
    manual_capacity TEXT DEFAULT ''
);


CREATE TABLE IF NOT EXISTS scan_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_time TEXT NOT NULL,
    total_ips_scanned INTEGER,
    devices_found INTEGER,
    devices_success INTEGER,
    devices_failed INTEGER,
    duration_seconds REAL
);


CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    ip_address TEXT NOT NULL,
    device_id INTEGER,
    status TEXT,
    snapshot_json TEXT,
    FOREIGN KEY(scan_id) REFERENCES scan_logs(id)
);


CREATE TABLE IF NOT EXISTS blacklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entry TEXT UNIQUE NOT NULL,
    description TEXT DEFAULT '',
    enabled INTEGER DEFAULT 1,
    created_at TEXT NOT NULL
);


CREATE TABLE IF NOT EXISTS manual_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    description TEXT DEFAULT '',
    enabled INTEGER DEFAULT 1,
    created_at TEXT NOT NULL
);


CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'view',
    created_at TEXT NOT NULL,
    enabled INTEGER DEFAULT 1
);
"""


# ============================================================
# Database
# ============================================================

def get_db():
    Path(DB_PATH).parent.mkdir(
        parents=True,
        exist_ok=True
    )

    conn = sqlite3.connect(
        DB_PATH,
        timeout=30
    )

    conn.row_factory = sqlite3.Row

    conn.execute(
        "PRAGMA journal_mode=WAL"
    )

    conn.execute(
        "PRAGMA foreign_keys=ON"
    )

    return conn


# ============================================================
# Init DB
# ============================================================

def init_db():

    conn = get_db()

    conn.executescript(
        SCHEMA
    )

    _migrate(conn)

    conn.commit()
    conn.close()


# ============================================================
# Migration
# ============================================================

def _migrate(conn):

    # --------------------------------------------------------
    # Devices
    # --------------------------------------------------------

    cols = {
        row[1]
        for row in conn.execute(
            "PRAGMA table_info(devices)"
        ).fetchall()
    }

    wanted = {

        "rx_power": "TEXT",
        "serial_number": "TEXT",
        "vendor": "TEXT",

        "modulation": "TEXT",
        "polarization": "TEXT",
        "antenna_gain": "TEXT",
        "capacity": "TEXT",

        "latitude": "TEXT",
        "longitude": "TEXT",
        "province": "TEXT",
        "city": "TEXT",

        "wireless_registration": "TEXT",
        "interfaces": "TEXT",
        "cpu_memory": "TEXT",
        "ip_routes": "TEXT",
        "bridges": "TEXT",
        "pppoe_vpn": "TEXT",

        "credential_id": "TEXT",

        # Manual fields
        "manual_latitude": "TEXT DEFAULT ''",
        "manual_longitude": "TEXT DEFAULT ''",
        "manual_province": "TEXT DEFAULT ''",
        "manual_city": "TEXT DEFAULT ''",
        "manual_antenna_gain": "TEXT DEFAULT ''",
        "manual_polarization": "TEXT DEFAULT ''",
        "manual_capacity": "TEXT DEFAULT ''",
    }

    for name, typ in wanted.items():

        if name not in cols:

            conn.execute(
                f"ALTER TABLE devices ADD COLUMN {name} {typ}"
            )


# ============================================================
# Time
# ============================================================

#def _now():

#    return datetime.now().strftime(
#        "%Y-%m-%d %H:%M:%S"
#    )

def _now():
    return datetime.now(
        ZoneInfo("Asia/Tehran")
    ).strftime(
        "%Y-%m-%d %H:%M:%S"
    )

# ============================================================
# Upsert Device
# ============================================================

def upsert_device(data):

    init_db()

    data = dict(data)

    if not data.get("ip_address"):
        raise ValueError(
            "ip_address is required"
        )

    conn = get_db()

    now = _now()

    data["last_updated"] = now
    data["last_seen"] = now

    # --------------------------------------------------------
    # Existing manual values
    # --------------------------------------------------------

    existing = conn.execute(
        """
        SELECT
            manual_latitude,
            manual_longitude,
            manual_province,
            manual_city,
            manual_antenna_gain,
            manual_polarization,
            manual_capacity
        FROM devices
        WHERE ip_address = ?
        """,
        (data["ip_address"],)
    ).fetchone()

    if existing:

        manual_latitude = (
            existing["manual_latitude"] or ""
        )

        manual_longitude = (
            existing["manual_longitude"] or ""
        )

        manual_province = (
            existing["manual_province"] or ""
        )

        manual_city = (
            existing["manual_city"] or ""
        )

        manual_antenna_gain = (
            existing["manual_antenna_gain"] or ""
        )

        manual_polarization = (
            existing["manual_polarization"] or ""
        )

        manual_capacity = (
            existing["manual_capacity"] or ""
        )

    else:

        manual_latitude = ""
        manual_longitude = ""
        manual_province = ""
        manual_city = ""
        manual_antenna_gain = ""
        manual_polarization = ""
        manual_capacity = ""

    # --------------------------------------------------------
    # Fields from scanner
    # --------------------------------------------------------

    fields = [
        "ip_address",
        "device_type",
        "hostname",
        "ssid",
        "frequency",
        "tx_power",
        "rx_power",
        "signal_strength",
        "mac_address",
        "interface_name",
        "channel",
        "bandwidth",
        "mode",
        "noise_floor",
        "ccq",
        "uptime",
        "model",
        "firmware_version",
        "serial_number",
        "vendor",
        "modulation",
        "polarization",
        "antenna_gain",
        "capacity",
        "latitude",
        "longitude",
        "province",
        "city",
        "wireless_registration",
        "interfaces",
        "cpu_memory",
        "ip_routes",
        "bridges",
        "pppoe_vpn",
        "raw_data",
        "last_seen",
        "last_updated",
        "scan_status",
        "credential_id",
    ]

    values = []

    for field in fields:

        value = data.get(
            field,
            ""
        )

        if isinstance(
            value,
            (dict, list)
        ):

            value = json.dumps(
                value,
                ensure_ascii=False
            )

        values.append(value)

    placeholders = ",".join(
        "?"
        for _ in fields
    )

    names = ",".join(
        fields
    )

    # --------------------------------------------------------
    # Automatic fields update
    # --------------------------------------------------------

    update_parts = []

    for field in fields:

        if field == "ip_address":
            continue

        # Manual protected fields
        if field == "latitude":

            update_parts.append(
                """
                latitude =
                CASE
                    WHEN manual_latitude != ''
                    THEN manual_latitude
                    ELSE excluded.latitude
                END
                """
            )

            continue

        if field == "longitude":

            update_parts.append(
                """
                longitude =
                CASE
                    WHEN manual_longitude != ''
                    THEN manual_longitude
                    ELSE excluded.longitude
                END
                """
            )

            continue

        if field == "province":

            update_parts.append(
                """
                province =
                CASE
                    WHEN manual_province != ''
                    THEN manual_province
                    ELSE excluded.province
                END
                """
            )

            continue

        if field == "city":

            update_parts.append(
                """
                city =
                CASE
                    WHEN manual_city != ''
                    THEN manual_city
                    ELSE excluded.city
                END
                """
            )

            continue

        if field == "antenna_gain":

            update_parts.append(
                """
                antenna_gain =
                CASE
                    WHEN manual_antenna_gain != ''
                    THEN manual_antenna_gain
                    ELSE excluded.antenna_gain
                END
                """
            )

            continue

        if field == "polarization":

            update_parts.append(
                """
                polarization =
                CASE
                    WHEN manual_polarization != ''
                    THEN manual_polarization
                    ELSE excluded.polarization
                END
                """
            )

            continue

        if field == "capacity":

            update_parts.append(
                """
                capacity =
                CASE
                    WHEN manual_capacity != ''
                    THEN manual_capacity
                    ELSE excluded.capacity
                END
                """
            )

            continue

        # Normal fields
        update_parts.append(
            f"{field}=excluded.{field}"
        )

    # --------------------------------------------------------
    # Insert / Update
    # --------------------------------------------------------

    sql = f"""
        INSERT INTO devices ({names})
        VALUES ({placeholders})
        ON CONFLICT(ip_address)
        DO UPDATE SET
            {",".join(update_parts)}
    """

    conn.execute(
        sql,
        values
    )

    conn.commit()

    row = conn.execute(
        """
        SELECT *
        FROM devices
        WHERE ip_address = ?
        """,
        (data["ip_address"],)
    ).fetchone()

    conn.close()

    return row


# ============================================================
# Update Manual Device Data
# ============================================================

def update_manual_device(
    ip,
    latitude=None,
    longitude=None,
    province=None,
    city=None,
    antenna_gain=None,
    polarization=None,
    capacity=None,
):

    init_db()

    conn = get_db()

    row = conn.execute(
        """
        SELECT *
        FROM devices
        WHERE ip_address = ?
        """,
        (ip,)
    ).fetchone()

    if not row:

        conn.close()

        return None

    # Existing values if field wasn't sent
    current = dict(row)

    manual_latitude = (
        current.get("manual_latitude")
        if latitude is None
        else str(latitude).strip()
    )

    manual_longitude = (
        current.get("manual_longitude")
        if longitude is None
        else str(longitude).strip()
    )

    manual_province = (
        current.get("manual_province")
        if province is None
        else str(province).strip()
    )

    manual_city = (
        current.get("manual_city")
        if city is None
        else str(city).strip()
    )

    manual_antenna_gain = (
        current.get("manual_antenna_gain")
        if antenna_gain is None
        else str(antenna_gain).strip()
    )

    manual_polarization = (
        current.get("manual_polarization")
        if polarization is None
        else str(polarization).strip()
    )

    manual_capacity = (
        current.get("manual_capacity")
        if capacity is None
        else str(capacity).strip()
    )

    # --------------------------------------------------------
    # Save manual values + effective values
    # --------------------------------------------------------

    conn.execute(
        """
        UPDATE devices
        SET
            manual_latitude = ?,
            manual_longitude = ?,
            manual_province = ?,
            manual_city = ?,
            manual_antenna_gain = ?,
            manual_polarization = ?,
            manual_capacity = ?,

            latitude = ?,
            longitude = ?,
            province = ?,
            city = ?,
            antenna_gain = ?,
            polarization = ?,
            capacity = ?,

            last_updated = ?
        WHERE ip_address = ?
        """,
        (
            manual_latitude or "",
            manual_longitude or "",
            manual_province or "",
            manual_city or "",
            manual_antenna_gain or "",
            manual_polarization or "",
            manual_capacity or "",

            manual_latitude or "",
            manual_longitude or "",
            manual_province or "",
            manual_city or "",
            manual_antenna_gain or "",
            manual_polarization or "",
            manual_capacity or "",

            _now(),
            ip,
        )
    )

    conn.commit()

    result = conn.execute(
        """
        SELECT *
        FROM devices
        WHERE ip_address = ?
        """,
        (ip,)
    ).fetchone()

    conn.close()

    return result


# ============================================================
# Devices
# ============================================================

def get_all_devices(search=""):

    init_db()

    conn = get_db()

    if search:

        q = "%" + search + "%"

        rows = conn.execute(
            """
            SELECT *
            FROM devices
            WHERE NOT EXISTS (
                SELECT 1
                FROM blacklist b
                WHERE b.enabled=1
                  AND b.entry=devices.ip_address
            )
            AND (
                ip_address LIKE ?
                OR hostname LIKE ?
                OR ssid LIKE ?
                OR device_type LIKE ?
                OR model LIKE ?
                OR vendor LIKE ?
            )
            ORDER BY ip_address
            """,
            (
                q,
                q,
                q,
                q,
                q,
                q,
            )
        ).fetchall()

    else:

        rows = conn.execute(
            """
            SELECT *
            FROM devices d
            WHERE NOT EXISTS (
                SELECT 1
                FROM blacklist b
                WHERE b.enabled=1
                  AND b.entry=d.ip_address
            )
            ORDER BY ip_address
            """
        ).fetchall()

    conn.close()

    return rows


def get_device_by_ip(ip):

    init_db()

    conn = get_db()

    row = conn.execute(
        """
        SELECT *
        FROM devices
        WHERE ip_address = ?
        """,
        (ip,)
    ).fetchone()

    conn.close()

    return row


# ============================================================
# Online Devices Only (for view users)
# ============================================================

def get_online_devices(search=""):

    init_db()

    conn = get_db()

    if search:

        q = "%" + search + "%"

        rows = conn.execute(
            """
            SELECT *
            FROM devices d
            WHERE d.scan_status = 'success'

            AND NOT EXISTS (
                SELECT 1
                FROM blacklist b
                WHERE b.enabled=1
                AND b.entry=d.ip_address
            )

            AND (
                ip_address LIKE ?
                OR hostname LIKE ?
                OR ssid LIKE ?
                OR device_type LIKE ?
                OR model LIKE ?
                OR vendor LIKE ?
            )

            ORDER BY ip_address
            """,
            (
                q,
                q,
                q,
                q,
                q,
                q
            )
        ).fetchall()


    else:

        rows = conn.execute(
            """
            SELECT *
            FROM devices d

            WHERE d.scan_status='success'

            AND NOT EXISTS (
                SELECT 1
                FROM blacklist b
                WHERE b.enabled=1
                AND b.entry=d.ip_address
            )

            ORDER BY ip_address
            """
        ).fetchall()


    conn.close()

    return rows


# ============================================================
# Scan History
# ============================================================

def log_scan(
    total,
    found,
    success,
    failed,
    duration,
    snapshots=None,
):

    init_db()

    conn = get_db()

    cur = conn.execute(
        """
        INSERT INTO scan_logs(
            scan_time,
            total_ips_scanned,
            devices_found,
            devices_success,
            devices_failed,
            duration_seconds
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            _now(),
            total,
            found,
            success,
            failed,
            duration,
        )
    )

    scan_id = cur.lastrowid

    if snapshots:

        for ip, status, snap in snapshots:

            device = conn.execute(
                """
                SELECT id
                FROM devices
                WHERE ip_address = ?
                """,
                (ip,)
            ).fetchone()

            device_id = (
                device["id"]
                if device
                else None
            )

            if isinstance(
                snap,
                (dict, list)
            ):

                snapshot_json = json.dumps(
                    snap,
                    ensure_ascii=False
                )

            else:

                snapshot_json = str(
                    snap
                )

            conn.execute(
                """
                INSERT INTO scan_results(
                    scan_id,
                    ip_address,
                    device_id,
                    status,
                    snapshot_json
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    ip,
                    device_id,
                    status,
                    snapshot_json,
                )
            )

    conn.commit()
    conn.close()

    return scan_id


def get_scan_history(
    limit=20
):

    init_db()

    conn = get_db()

    limit = max(
        1,
        min(
            int(limit),
            500
        )
    )

    rows = conn.execute(
        """
        SELECT *
        FROM scan_logs
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    ).fetchall()

    conn.close()

    return rows


def get_scan_detail(
    scan_id
):

    init_db()

    conn = get_db()

    scan = conn.execute(
        """
        SELECT *
        FROM scan_logs
        WHERE id = ?
        """,
        (scan_id,)
    ).fetchone()

    rows = conn.execute(
        """
        SELECT *
        FROM scan_results
        WHERE scan_id = ?
        ORDER BY ip_address
        """,
        (scan_id,)
    ).fetchall()

    conn.close()

    return scan, rows


# ============================================================
# Blacklist
# ============================================================

def is_blacklisted(ip):

    import ipaddress

    init_db()

    conn = get_db()

    rows = conn.execute(
        """
        SELECT entry
        FROM blacklist
        WHERE enabled = 1
        """
    ).fetchall()

    conn.close()

    obj = ipaddress.ip_address(ip)

    for row in rows:

        try:

            if obj in ipaddress.ip_network(
                row["entry"],
                strict=False
            ):
                return True

        except ValueError:
            pass

    return False


def list_blacklist():

    init_db()

    conn = get_db()

    rows = conn.execute(
        """
        SELECT *
        FROM blacklist
        ORDER BY entry
        """
    ).fetchall()

    conn.close()

    return rows


def add_blacklist(
    entry,
    description=""
):

    import ipaddress

    ipaddress.ip_network(
        entry,
        strict=False
    )

    init_db()

    conn = get_db()

    conn.execute(
        """
        INSERT INTO blacklist(
            entry,
            description,
            created_at
        )
        VALUES (?, ?, ?)
        """,
        (
            entry,
            description,
            _now()
        )
    )

    conn.commit()
    conn.close()


def delete_blacklist(
    item_id
):

    init_db()

    conn = get_db()

    conn.execute(
        """
        DELETE FROM blacklist
        WHERE id = ?
        """,
        (item_id,)
    )

    conn.commit()
    conn.close()


# ============================================================
# Manual IPs
# ============================================================

def list_manual_ips():

    init_db()

    conn = get_db()

    rows = conn.execute(
        """
        SELECT *
        FROM manual_ips
        ORDER BY ip_address
        """
    ).fetchall()

    conn.close()

    return rows


def add_manual_ip(
    ip,
    description=""
):

    import ipaddress

    ipaddress.ip_address(
        ip
    )

    init_db()

    conn = get_db()

    conn.execute(
        """
        INSERT INTO manual_ips(
            ip_address,
            description,
            created_at
        )
        VALUES (?, ?, ?)
        """,
        (
            ip,
            description,
            _now()
        )
    )

    conn.commit()
    conn.close()


def delete_manual_ip(
    item_id
):

    init_db()

    conn = get_db()

    conn.execute(
        """
        DELETE FROM manual_ips
        WHERE id = ?
        """,
        (item_id,)
    )

    conn.commit()
    conn.close()


# ============================================================
# Stats
# ============================================================

def get_stats():

    init_db()

    conn = get_db()

    total = conn.execute(
        """
        SELECT COUNT(*) c
        FROM devices
        WHERE NOT EXISTS (
            SELECT 1
            FROM blacklist b
            WHERE b.enabled=1
              AND b.entry=devices.ip_address
        )
        """
    ).fetchone()["c"]

    by = conn.execute(
        """
        SELECT
            COALESCE(device_type, 'unknown') t,
            COUNT(*) c
        FROM devices d
        WHERE NOT EXISTS (
            SELECT 1
            FROM blacklist b
            WHERE b.enabled=1
              AND b.entry=d.ip_address
        )
        GROUP BY device_type
        """
    ).fetchall()

    last = conn.execute(
        """
        SELECT *
        FROM scan_logs
        ORDER BY id DESC
        LIMIT 1
        """
    ).fetchone()

    online = conn.execute(
        """
        SELECT COUNT(*) c
        FROM devices
        WHERE scan_status='success'
        AND NOT EXISTS (
            SELECT 1
            FROM blacklist b
            WHERE b.enabled=1
              AND b.entry=devices.ip_address
        )
        """
    ).fetchone()["c"]

    conn.close()

    return {
        "total_devices": total,
        "by_type": {
            row["t"]: row["c"]
            for row in by
        },
        "last_scan": (
            dict(last)
            if last
            else None
        ),
        "success_count": online
    }


# ============================================================
# Users
# ============================================================

def user_by_username(
    username
):

    init_db()

    conn = get_db()

    row = conn.execute(
        """
        SELECT *
        FROM users
        WHERE username = ?
          AND enabled = 1
        """,
        (username,)
    ).fetchone()

    conn.close()

    return row


def all_users():

    init_db()

    conn = get_db()

    rows = conn.execute(
        """
        SELECT
            id,
            username,
            role,
            enabled,
            created_at
        FROM users
        ORDER BY username
        """
    ).fetchall()

    conn.close()

    return rows


def create_user(
    username,
    password_hash,
    role
):

    init_db()

    conn = get_db()

    conn.execute(
        """
        INSERT INTO users(
            username,
            password_hash,
            role,
            created_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            username,
            password_hash,
            role,
            _now()
        )
    )

    conn.commit()
    conn.close()


def delete_user(
    uid
):

    init_db()

    conn = get_db()

    conn.execute(
        """
        DELETE FROM users
        WHERE id = ?
        """,
        (uid,)
    )

    conn.commit()
    conn.close()
