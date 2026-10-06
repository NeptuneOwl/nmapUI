import os
import threading
from datetime import datetime, timezone

from flask import Flask, abort, jsonify, render_template, request

from services import storage, scanner, cpe_mapper, nvd_client, report_builder

app = Flask(__name__)
JOBS = {}   # scan_id -> {status, step, progress, error}


@app.route("/")
def dashboard():
    return render_template("dashboard.html", scans=storage.list_scans(), active="reports")


@app.route("/new-scan")
def new_scan():
    return render_template("new_scan.html", active="new-scan")


@app.route("/report/<scan_id>")
def report(scan_id):
    data = report_builder.build(scan_id)
    if not data:
        abort(404)
    return render_template("report.html", report=data, active="reports")


@app.route("/api/scans", methods=["POST"])
def api_create_scan():
    payload = request.get_json(silent=True) or {}
    target = (payload.get("target") or "").strip()
    if not target:
        return jsonify({"error": "Target is required."}), 400

    mode = payload.get("mode", "normal")
    options = payload.get("options", {}) or {}

    scan_id = storage.new_scan_id(target)
    storage.save_json(scan_id, "meta.json", {
        "target": target,
        "mode": mode,
        "options": options,
        "started": datetime.now(timezone.utc).isoformat(),
        "status": "running",
    })
    JOBS[scan_id] = {"status": "running", "step": "Starting nmap", "progress": 5}
    threading.Thread(
        target=_run_pipeline, args=(scan_id, target, mode, options), daemon=True
    ).start()
    return jsonify({"id": scan_id})


@app.route("/api/scans/<scan_id>/status")
def api_status(scan_id):
    if scan_id in JOBS:
        return jsonify(JOBS[scan_id])
    meta = storage.load_json(scan_id, "meta.json") or {}
    return jsonify({"status": meta.get("status", "unknown"),
                    "error": meta.get("error")})


@app.route("/api/scans/<scan_id>", methods=["DELETE"])
def api_delete(scan_id):
    storage.delete_scan(scan_id)
    JOBS.pop(scan_id, None)
    return jsonify({"ok": True})


# ---------- background pipeline ----------

def _run_pipeline(scan_id, target, mode, options):
    try:
        JOBS[scan_id].update(step="Running nmap scan", progress=10)
        hosts = scanner.run_scan(target, mode, options)
        storage.save_json(scan_id, "scan.json", hosts)

        JOBS[scan_id].update(step="Extracting CPE identifiers", progress=35)
        cpes = cpe_mapper.build_cpes(hosts)
        storage.save_json(scan_id, "cpes.json", cpes)

        JOBS[scan_id].update(step="Querying NVD for vulnerabilities", progress=55)
        client = nvd_client.NVDClient()
        cves = client.search_many([c for lst in cpes.values() for _, c in lst])
        storage.save_json(scan_id, "nvd_search_results.json", cves)

        JOBS[scan_id].update(step="Finalizing report", progress=95)
        meta = storage.load_json(scan_id, "meta.json") or {}
        meta["status"] = "done"
        meta["finished"] = datetime.now(timezone.utc).isoformat()
        storage.save_json(scan_id, "meta.json", meta)

        JOBS[scan_id].update(status="done", progress=100, step="Complete")
    except Exception as exc:                       # noqa: BLE001
        meta = storage.load_json(scan_id, "meta.json") or {}
        meta["status"] = "error"
        meta["error"] = str(exc)
        storage.save_json(scan_id, "meta.json", meta)
        JOBS[scan_id].update(status="error", error=str(exc), step="Failed")


if __name__ == "__main__":
    storage.ensure_dirs()
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)
