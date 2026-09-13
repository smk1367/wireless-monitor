
#!/usr/bin/env python3

import os
import json
import sqlite3
import base64
import ipaddress
import threading
from functools import wraps

from flask import (
    Flask,
    request,
    jsonify,
    send_file,
    send_from_directory,
    Response,
)

app = Flask(__name__, static_folder='images', static_url_path='/images')
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)

from manual_devices import get_manual_devices

from database import (
    get_all_devices,
    get_online_devices,
)

# === EXCEL_FEATURE_IMPORT ===
from excel_import.excel_manager import (
    import_excel,
    export_excel,
    template_excel,
)


# ============================================================
# Configuration
# ============================================================

DB_PATH = os.environ.get(
    "DB_PATH",
    "/app/data/data.db"
)

PORT = int(
    os.environ.get(
        "PORT",
        "5000"
    )
)

# ============================================================
# Flask Application
# ============================================================

app = Flask(__name__)

# ============================================================
# Static Images
# ============================================================

@app.route("/images/<path:filename>")
def serve_image(filename):
    """
    Serve images from /app/images/
    Example:
        /images/sazman.png
        /images/sabanet.png
    """
    images_dir = "/app/images"

    file_path = os.path.join(images_dir, filename)

    # جلوگیری از درخواست فایل‌های غیر موجود
    if not os.path.isfile(file_path):
        return jsonify({
            "error": "Image not found",
            "filename": filename
        }), 404

    return send_from_directory(
        images_dir,
        filename
    )

# ============================================================
# ادامه کدهای api_server.py از اینجا
# ============================================================



# ============================================================
# Scan State
# ============================================================

scan_lock = threading.Lock()

scan_running = False

last_scan_result = None


# ============================================================
# Database
# ============================================================

def get_db():

    os.makedirs(
        os.path.dirname(DB_PATH),
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
# Authentication
# ============================================================

def get_basic_auth():

    auth_header = request.headers.get(
        "Authorization",
        ""
    )

    if not auth_header.startswith(
        "Basic "
    ):
        return None, None

    encoded = auth_header[6:].strip()

    try:

        decoded = base64.b64decode(
            encoded
        ).decode("utf-8")

    except Exception:

        return None, None

    if ":" not in decoded:

        return None, None

    username, password = decoded.split(
        ":",
        1
    )

    return username, password


def authenticate():

    username, password = get_basic_auth()

    if not username or not password:
        return None

    conn = get_db()

    try:

        row = conn.execute(
            """
            SELECT *
            FROM users
            WHERE username = ?
              AND enabled = 1
            """,
            (username,)
        ).fetchone()

    finally:

        conn.close()

    if not row:
        return None

    try:

        valid = check_password_hash(
            row["password_hash"],
            password
        )

    except Exception:

        valid = False

    if not valid:
        return None

    return dict(row)


def require_auth(func):

    @wraps(func)
    def wrapper(*args, **kwargs):

        if request.method == "OPTIONS":
            return (
                "",
                204
            )

        user = authenticate()

        if not user:

            response = jsonify({
                "error": "unauthorized",
                "message":
                    "نام کاربری یا رمز عبور اشتباه است"
            })

            response.status_code = 401

            response.headers[
                "WWW-Authenticate"
            ] = (
                'Basic realm="Wireless Monitor"'
            )

            return response

        request.current_user = user

        return func(
            *args,
            **kwargs
        )

    return wrapper


def require_full(func):

    @wraps(func)
    def wrapper(*args, **kwargs):

        user = getattr(
            request,
            "current_user",
            None
        )

        if not user:

            return jsonify({
                "error": "unauthorized"
            }), 401

        if user.get("role") != "full":

            return jsonify({
                "error": "forbidden",
                "message":
                    "دسترسی مدیریتی ندارید"
            }), 403

        return func(
            *args,
            **kwargs
        )

    return wrapper


# ============================================================
# Background Scanner
# ============================================================

def background_scan():

    global scan_running
    global last_scan_result

    try:

        print(
            "=" * 60
        )

        print(
            "[SCAN] Starting background scan"
        )

        print(
            "=" * 60
        )

        from scanner import run_scan

        result = run_scan()

        last_scan_result = result

        print(
            "[SCAN] Scan completed"
        )

        print(
            result
        )

    except Exception as e:

        print(
            "[SCAN] Scan ERROR:",
            str(e)
        )

        import traceback

        traceback.print_exc()

        last_scan_result = {
            "status": "failed",
            "error": str(e)
        }

    finally:

        scan_running = False


# ============================================================
# Frontend
# ============================================================

@app.get("/")
def index():

    return send_file(
        "/app/index.html"
    )


# ============================================================
# Health
# ============================================================

@app.get("/api/health")
def health():

    return jsonify({
        "status": "ok",
        "service": "wireless-monitor"
    })


# ============================================================
# Current User
# ============================================================

@app.get("/api/me")
@require_auth
def me():

    user = request.current_user

    return jsonify({
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "enabled": user["enabled"]
    })

@app.get("/api/devices")
@require_auth
def devices():

    user = request.current_user


    search = request.args.get(
        "search",
        ""
    ).strip()


    if not search:

        search = request.args.get(
            "q",
            ""
        ).strip()



    # --------------------------------------------
    # Full User
    # همه دستگاه ها
    # --------------------------------------------

    if user.get("role") == "full":

        rows = get_all_devices(
            search
        )


    # --------------------------------------------
    # View User
    # فقط آنلاین ها
    # --------------------------------------------

    else:

        rows = get_online_devices(
            search
        )



    result = []

    for row in rows:

        item = dict(row)


        if user.get("role") == "view":

            item.pop(
                "raw_data",
                None
            )

            item.pop(
                "raw_data_parsed",
                None
            )


        result.append(item)



# --------------------------------------------
# اضافه کردن IP های دستی
# --------------------------------------------

    manual_devices = get_manual_devices()


    result.extend(
        manual_devices
    )


    return jsonify(result)


# ============================================================
# Devices
# ============================================================

# ============================================================
# Device Detail
# ============================================================

@app.get("/api/device/<path:ip>")
@require_auth
def device_detail(ip):

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

    if not row:

        return jsonify({
            "error": "device_not_found",
            "ip": ip
        }), 404

    data = dict(row)

    user = request.current_user

    # View فقط دستگاه آنلاین
    if (
        user.get("role") == "view"
        and data.get("scan_status") != "success"
    ):

        return jsonify({
            "error": "device_offline",
            "message":
                "View user can only access online devices"
        }), 403



    # View user cannot see raw data

    if user.get("role") == "view":

        data.pop(
            "raw_data",
            None
    )

    if data.get("raw_data"):

        try:

            data["raw_data_parsed"] = json.loads(
                data["raw_data"]
            )

        except Exception:

            data["raw_data_parsed"] = {
                "raw": data["raw_data"]
            }

    return jsonify(data)


# ============================================================
# Manual Device Data
# ============================================================

@app.put("/api/device/<path:ip>/manual")
@require_auth
@require_full
def update_manual_device(ip):

    data = request.get_json(
        silent=True
    ) or {}

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

        return jsonify({
            "error": "device_not_found",
            "ip": ip
        }), 404

    current = dict(row)

    # --------------------------------------------------------
    # Values
    # --------------------------------------------------------

    latitude = str(
        data.get(
            "latitude",
            current.get(
                "manual_latitude",
                ""
            )
        )
    ).strip()

    longitude = str(
        data.get(
            "longitude",
            current.get(
                "manual_longitude",
                ""
            )
        )
    ).strip()

    province = str(
        data.get(
            "province",
            current.get(
                "manual_province",
                ""
            )
        )
    ).strip()

    city = str(
        data.get(
            "city",
            current.get(
                "manual_city",
                ""
            )
        )
    ).strip()

    antenna_gain = str(
        data.get(
            "antenna_gain",
            current.get(
                "manual_antenna_gain",
                ""
            )
        )
    ).strip()

    polarization = str(
        data.get(
            "polarization",
            current.get(
                "manual_polarization",
                ""
            )
        )
    ).strip()

    capacity = str(
        data.get(
            "capacity",
            current.get(
                "manual_capacity",
                ""
            )
        )
    ).strip()

    # --------------------------------------------------------
    # Save
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

            last_updated = datetime('now')
        WHERE ip_address = ?
        """,
        (
            latitude,
            longitude,
            province,
            city,
            antenna_gain,
            polarization,
            capacity,

            latitude,
            longitude,
            province,
            city,
            antenna_gain,
            polarization,
            capacity,

            ip
        )
    )

    conn.commit()

    updated = conn.execute(
        """
        SELECT *
        FROM devices
        WHERE ip_address = ?
        """,
        (ip,)
    ).fetchone()

    conn.close()

    return jsonify(
        dict(updated)
    )


# ============================================================
# Excel Import / Export
# ============================================================

@app.get("/api/excel/template")
@require_auth
@require_full
def excel_template():

    output = template_excel()

    return send_file(
        output,
        as_attachment=True,
        download_name="wireless_monitor_antenna_template.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


@app.get("/api/excel/export")
@require_auth
@require_full
def excel_export():

    output = export_excel(DB_PATH)

    return send_file(
        output,
        as_attachment=True,
        download_name="wireless_monitor_antenna_export.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


@app.post("/api/excel/import")
@require_auth
@require_full
def excel_import_route():

    upload = request.files.get("file")

    if upload is None or not upload.filename:
        return jsonify({
            "error": "file_required",
            "message": "لطفاً فایل Excel را انتخاب کنید"
        }), 400

    filename = upload.filename.lower()

    if not (filename.endswith(".xlsx") or filename.endswith(".xlsm")):
        return jsonify({
            "error": "invalid_file_type",
            "message": "فقط فایل XLSX یا XLSM قابل قبول است"
        }), 400

    try:
        result = import_excel(upload.stream, DB_PATH)
    except ValueError as exc:
        return jsonify({
            "error": "excel_validation_error",
            "message": str(exc)
        }), 400
    except Exception:
        app.logger.exception("Excel import failed")
        return jsonify({
            "error": "excel_import_failed",
            "message": "خطا در پردازش فایل Excel"
        }), 500

    return jsonify(result)

# ============================================================
# Statistics
# ============================================================

@app.get("/api/stats")
@require_auth
def stats():

    conn = get_db()

    total = conn.execute(
        """
        SELECT COUNT(*)
        FROM devices
        WHERE NOT EXISTS (
            SELECT 1
            FROM blacklist b
            WHERE b.enabled=1
              AND b.entry=devices.ip_address
        )
        """
    ).fetchone()[0]

    success = conn.execute(
        """
        SELECT COUNT(*)
        FROM devices
        WHERE scan_status = 'success'
        AND NOT EXISTS (
            SELECT 1
            FROM blacklist b
            WHERE b.enabled=1
              AND b.entry=devices.ip_address
        )
        """
    ).fetchone()[0]

    rows = conn.execute(
        """
        SELECT
            device_type,
            COUNT(*) AS count
        FROM devices
        WHERE NOT EXISTS (
            SELECT 1
            FROM blacklist b
            WHERE b.enabled=1
              AND b.entry=devices.ip_address
        )
        GROUP BY device_type
        ORDER BY device_type
        """
    ).fetchall()

    conn.close()

    by_type = {}

    for row in rows:

        by_type[
            row["device_type"] or "Unknown"
        ] = row["count"]

    return jsonify({
        "total_devices": total,
        "success_count": success,
        "by_type": by_type
    })


# ============================================================
# Scan History
# ============================================================

@app.get("/api/scan-history")
@require_auth
def scan_history():

    limit = request.args.get(
        "limit",
        "100"
    )

    try:

        limit = int(
            limit
        )

    except Exception:

        limit = 100

    limit = max(
        1,
        min(
            limit,
            500
        )
    )

    conn = get_db()

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

    return jsonify([
        dict(row)
        for row in rows
    ])


# ============================================================
# Scan Detail
# ============================================================

@app.get("/api/scan/<int:scan_id>")
@require_auth
def scan_detail(scan_id):

    conn = get_db()

    scan = conn.execute(
        """
        SELECT *
        FROM scan_logs
        WHERE id = ?
        """,
        (scan_id,)
    ).fetchone()

    if not scan:

        conn.close()

        return jsonify({
            "error": "scan_not_found",
            "scan_id": scan_id
        }), 404

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

    results = []

    for row in rows:

        item = dict(row)

        if item.get(
            "snapshot_json"
        ):

            try:

                item["snapshot"] = json.loads(
                    item["snapshot_json"]
                )

            except Exception:

                item["snapshot"] = {
                    "raw":
                        item["snapshot_json"]
                }

        else:

            item["snapshot"] = None

        results.append(item)

    return jsonify({
        "scan": dict(scan),
        "results": results
    })


# ============================================================
# Scan Status
# ============================================================

@app.get("/api/scan-status")
@require_auth
def scan_status():

    return jsonify({
        "running": scan_running,
        "last_result": last_scan_result
    })


# ============================================================
# Start Scan
# ============================================================

@app.post("/api/scan-now")
@require_auth
def scan_now():

    global scan_running

    with scan_lock:

        if scan_running:

            return jsonify({
                "status": "running",
                "message":
                    "Scan is already running"
            }), 409

        scan_running = True

    user = request.current_user

    thread = threading.Thread(
        target=background_scan,
        daemon=True
    )

    thread.start()

    return jsonify({
        "status": "started",
        "message":
            "Scan started in background",
        "requested_by":
            user["username"]
    })


# ============================================================
# Blacklist
# ============================================================

@app.get("/api/blacklist")
@require_auth
def get_blacklist():

    conn = get_db()

    rows = conn.execute(
        """
        SELECT *
        FROM blacklist
        ORDER BY entry
        """
    ).fetchall()

    conn.close()

    return jsonify([
        dict(row)
        for row in rows
    ])


@app.post("/api/blacklist")
@require_auth
@require_full
def add_blacklist():

    data = request.get_json(
        silent=True
    ) or {}

    entry = str(
        data.get(
            "entry",
            ""
        )
    ).strip()

    description = str(
        data.get(
            "description",
            ""
        )
    ).strip()

    if not entry:

        return jsonify({
            "error": "entry_required"
        }), 400

    try:

        ipaddress.ip_network(
            entry,
            strict=False
        )

    except ValueError:

        return jsonify({
            "error":
                "invalid_ip_or_cidr"
        }), 400

    conn = get_db()

    try:

        conn.execute(
            """
            INSERT INTO blacklist(
                entry,
                description,
                created_at
            )
            VALUES (?, ?, datetime('now'))
            """,
            (
                entry,
                description
            )
        )

        conn.commit()

    except sqlite3.IntegrityError:

        conn.close()

        return jsonify({
            "error":
                "already_exists"
        }), 409

    conn.close()

    return jsonify({
        "status": "created"
    }), 201


@app.delete(
    "/api/blacklist/<int:item_id>"
)
@require_auth
@require_full
def delete_blacklist(item_id):

    conn = get_db()

    cur = conn.execute(
        """
        DELETE FROM blacklist
        WHERE id = ?
        """,
        (item_id,)
    )

    conn.commit()

    deleted = cur.rowcount

    conn.close()

    if not deleted:

        return jsonify({
            "error": "not_found"
        }), 404

    return jsonify({
        "status": "deleted"
    })


# ============================================================
# Manual IPs
# ============================================================

@app.get("/api/manual-ips")
@require_auth
def get_manual_ips():

    conn = get_db()

    rows = conn.execute(
        """
        SELECT *
        FROM manual_ips
        ORDER BY ip_address
        """
    ).fetchall()

    conn.close()

    return jsonify([
        dict(row)
        for row in rows
    ])


@app.post("/api/manual-ips")
@require_auth
@require_full
def add_manual_ip():

    data = request.get_json(
        silent=True
    ) or {}

    ip = str(
        data.get(
            "ip_address",
            ""
        )
    ).strip()

    description = str(
        data.get(
            "description",
            ""
        )
    ).strip()

    if not ip:

        return jsonify({
            "error":
                "ip_address_required"
        }), 400

    try:

        ipaddress.ip_address(ip)

    except ValueError:

        return jsonify({
            "error": "invalid_ip"
        }), 400

    conn = get_db()

    try:

        conn.execute(
            """
            INSERT INTO manual_ips(
                ip_address,
                description,
                created_at
            )
            VALUES (?, ?, datetime('now'))
            """,
            (
                ip,
                description
            )
        )

        conn.commit()

    except sqlite3.IntegrityError:

        conn.close()

        return jsonify({
            "error":
                "already_exists"
        }), 409

    conn.close()

    return jsonify({
        "status":
            "created"
    }), 201


@app.delete(
    "/api/manual-ips/<int:item_id>"
)
@require_auth
@require_full
def delete_manual_ip(item_id):

    conn = get_db()

    cur = conn.execute(
        """
        DELETE FROM manual_ips
        WHERE id = ?
        """,
        (item_id,)
    )

    conn.commit()

    deleted = cur.rowcount

    conn.close()

    if not deleted:

        return jsonify({
            "error":
                "not_found"
        }), 404

    return jsonify({
        "status":
            "deleted"
    })


# ============================================================
# Users
# ============================================================

@app.get("/api/users")
@require_auth
@require_full
def get_users():

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

    return jsonify([
        dict(row)
        for row in rows
    ])


@app.post("/api/users")
@require_auth
@require_full
def add_user():

    data = request.get_json(
        silent=True
    ) or {}

    username = str(
        data.get(
            "username",
            ""
        )
    ).strip()

    password = str(
        data.get(
            "password",
            ""
        )
    )

    role = str(
        data.get(
            "role",
            "view"
        )
    ).strip().lower()

    if not username:

        return jsonify({
            "error":
                "username_required"
        }), 400

    if not password:

        return jsonify({
            "error":
                "password_required"
        }), 400

    if role not in (
        "view",
        "full"
    ):

        return jsonify({
            "error":
                "invalid_role"
        }), 400

    password_hash = generate_password_hash(
        password
    )

    conn = get_db()

    try:

        conn.execute(
            """
            INSERT INTO users(
                username,
                password_hash,
                role,
                created_at,
                enabled
            )
            VALUES (?, ?, ?, datetime('now'), 1)
            """,
            (
                username,
                password_hash,
                role
            )
        )

        conn.commit()

    except sqlite3.IntegrityError:

        conn.close()

        return jsonify({
            "error":
                "username_already_exists"
        }), 409

    conn.close()

    return jsonify({
        "status":
            "created",
        "username":
            username,
        "role":
            role
    }), 201


@app.delete(
    "/api/users/<int:user_id>"
)
@require_auth
@require_full
def delete_user(user_id):

    current_user = (
        request.current_user
    )

    conn = get_db()

    target = conn.execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    if not target:

        conn.close()

        return jsonify({
            "error":
                "not_found"
        }), 404

    if (
        target["username"]
        == current_user["username"]
    ):

        conn.close()

        return jsonify({
            "error":
                "cannot_delete_current_user"
        }), 400

    conn.execute(
        """
        DELETE FROM users
        WHERE id = ?
        """,
        (user_id,)
    )

    conn.commit()

    conn.close()

    return jsonify({
        "status":
            "deleted"
    })


# ============================================================
# CORS
# ============================================================

@app.after_request
def add_cors_headers(
    response
):

    response.headers[
        "Access-Control-Allow-Origin"
    ] = "*"

    response.headers[
        "Access-Control-Allow-Headers"
    ] = (
        "Content-Type, Authorization"
    )

    response.headers[
        "Access-Control-Allow-Methods"
    ] = (
        "GET, POST, PUT, DELETE, OPTIONS"
    )

    return response


# ============================================================
# Error Handlers
# ============================================================

@app.errorhandler(404)
def not_found(error):

    if request.path.startswith(
        "/api/"
    ):

        return jsonify({
            "error":
                "not_found",
            "path":
                request.path
        }), 404

    return send_file(
        "/app/index.html"
    )


@app.errorhandler(401)
def unauthorized(error):

    response = jsonify({
        "error":
            "unauthorized"
    })

    response.status_code = 401

    response.headers[
        "WWW-Authenticate"
    ] = (
        'Basic realm="Wireless Monitor"'
    )

    return response


@app.errorhandler(403)
def forbidden(error):

    return jsonify({
        "error":
            "forbidden"
    }), 403


@app.errorhandler(500)
def internal_error(error):

    if request.path.startswith(
        "/api/"
    ):

        return jsonify({
            "error":
                "internal_server_error"
        }), 500

    return Response(
        "Internal Server Error",
        status=500,
        mimetype="text/plain"
    )


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("Wireless Monitor API")
    print("=" * 60)
    print(
        f"Database: {DB_PATH}"
    )
    print(
        f"Port: {PORT}"
    )
    print(
        "Dashboard: "
        f"http://0.0.0.0:{PORT}"
    )
    print("=" * 60)

    app.run(
        host="0.0.0.0",
        port=PORT,
        debug=False
    )
