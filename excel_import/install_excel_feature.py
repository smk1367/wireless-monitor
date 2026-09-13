#!/usr/bin/env python3
"""Robust installer for the independent Excel feature."""
from pathlib import Path
import re
import shutil
import sys

ROOT = Path(__file__).resolve().parent.parent
API = ROOT / "api_server.py"
INDEX = ROOT / "index.html"
REQ = ROOT / "requirements.txt"


def backup(path: Path):
    target = path.with_name(path.name + ".before_excel.bak")
    if not target.exists():
        shutil.copy2(path, target)


def update_requirements():
    text = REQ.read_text(encoding="utf-8")
    if re.search(r"(?im)^\s*openpyxl(?:[<>=!~]|$)", text):
        return
    if not text.endswith("\n"):
        text += "\n"
    text += "openpyxl>=3.1.0\n"
    REQ.write_text(text, encoding="utf-8")


def patch_api():
    text = API.read_text(encoding="utf-8")

    if "# === EXCEL_FEATURE_IMPORT ===" not in text:
        pattern = re.compile(
            r"from\s+database\s+import\s*\(\s*"
            r"get_all_devices\s*,\s*"
            r"get_online_devices\s*,?\s*\)",
            re.MULTILINE,
        )
        m = pattern.search(text)
        if not m:
            raise RuntimeError(
                "Could not find the database import block in api_server.py."
            )
        block = m.group(0) + (
            "\n\n# === EXCEL_FEATURE_IMPORT ===\n"
            "from excel_import.excel_manager import (\n"
            "    import_excel,\n"
            "    export_excel,\n"
            "    template_excel,\n"
            ")\n"
        )
        text = text[:m.start()] + block + text[m.end():]

    if 'app.config["MAX_CONTENT_LENGTH"]' not in text:
        m = re.search(r"^app\s*=\s*Flask\([^\n]*\)$", text, re.MULTILINE)
        if m:
            # Configure the first app object. The repository has a second Flask
            # assignment later; existing behavior is preserved.
            replacement = m.group(0) + '\napp.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024'
            text = text[:m.start()] + replacement + text[m.end():]

    if "# Excel Import / Export" not in text:
        marker = re.compile(
            r"#\s*=+\s*\n#\s*Statistics\s*\n#\s*=+\s*\n",
            re.MULTILINE,
        )
        m = marker.search(text)
        if not m:
            raise RuntimeError("Could not find Statistics section in api_server.py.")

        routes = '''# ============================================================
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

'''
        text = text[:m.start()] + routes + text[m.start():]

    API.write_text(text, encoding="utf-8")


def patch_index():
    text = INDEX.read_text(encoding="utf-8")

    if "<!-- EXCEL_FEATURE_CARD -->" not in text:
        # Insert immediately before the User admin card, tolerant of whitespace.
        marker = re.compile(
            r"(?=\s*<div\s+class=\"card\">\s*<h3>\s*User\s*</h3>)",
            re.MULTILINE,
        )
        m = marker.search(text)
        if not m:
            raise RuntimeError("Could not find User card in index.html.")

        card = '''
                <!-- EXCEL_FEATURE_CARD -->
                <div class="card">

                    <h3>
                        📊 اطلاعات آنتن از Excel
                    </h3>

                    <p class="muted">
                        فایل Excel با IP دستگاه‌ها تطبیق داده می‌شود.
                    </p>

                    <input
                        id="excelFile"
                        type="file"
                        accept=".xlsx,.xlsm"
                    >

                    <br><br>

                    <div class="toolbar">

                        <button
                            class="btn primary"
                            onclick="importExcelFile()"
                        >
                            ⬆️ Import Excel
                        </button>

                        <button
                            class="btn"
                            onclick="downloadExcelTemplate()"
                        >
                            📥 قالب Excel
                        </button>

                        <button
                            class="btn"
                            onclick="exportExcelFile()"
                        >
                            📤 Export Excel
                        </button>

                    </div>

                    <div
                        id="excelStatus"
                        class="scan-status"
                    ></div>

                </div>

'''
        text = text[:m.start()] + card + text[m.start():]

    if "/* EXCEL_FEATURE_JS */" not in text:
        marker = re.compile(
            r"/\*\s*=+\s*\n\s*Admin\s*\n\s*=+\s*\*/",
            re.MULTILINE,
        )
        m = marker.search(text)
        if not m:
            raise RuntimeError("Could not find Admin section in index.html.")

        js = '''/* EXCEL_FEATURE_JS */

async function importExcelFile(){

    const input = document.getElementById("excelFile");
    const status = document.getElementById("excelStatus");

    if(!input || !input.files.length){
        alert("ابتدا یک فایل Excel انتخاب کنید");
        return;
    }

    const form = new FormData();
    form.append("file", input.files[0]);
    status.textContent = "در حال وارد کردن اطلاعات...";

    try{
        const response = await fetch(
            API + "/api/excel/import",
            {
                method: "POST",
                headers: { "Authorization": AUTH },
                body: form
            }
        );

        let result = {};
        try { result = await response.json(); } catch {}

        if(!response.ok){
            throw new Error(
                result.message || result.error || `HTTP ${response.status}`
            );
        }

        status.innerHTML =
            `✅ ${result.updated} دستگاه بروزرسانی شد.` +
            (result.not_found ? ` ${result.not_found} IP در سیستم پیدا نشد.` : "");

        input.value = "";
    }
    catch(e){
        status.innerHTML = "❌ خطا: " + h(e.message);
    }
}

function downloadExcelTemplate(){
    window.location.href = API + "/api/excel/template";
}

function exportExcelFile(){
    window.location.href = API + "/api/excel/export";
}
'''
        text = text[:m.start()] + js + "\n\n" + text[m.start():]

    INDEX.write_text(text, encoding="utf-8")


def main():
    missing = [str(p) for p in (API, INDEX, REQ) if not p.exists()]
    if missing:
        print("Run from the wireless-monitor repository root.")
        for p in missing:
            print("Missing:", p)
        sys.exit(1)

    for p in (API, INDEX, REQ):
        backup(p)

    update_requirements()
    patch_api()
    patch_index()

    print("Excel feature installed successfully.")
    print("Backups created: *.before_excel.bak")
    print("Next: docker compose up -d --build")


if __name__ == "__main__":
    main()
