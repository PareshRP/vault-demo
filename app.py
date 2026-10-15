from __future__ import annotations

import os
import secrets
import time
import uuid
from datetime import datetime
from urllib.parse import urlparse
from functools import wraps

from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from werkzeug.exceptions import RequestEntityTooLarge

from vault_portal.core import (
    MAX_FILES, MAX_FILE_BYTES, InstructionError, build_preview, parse_instruction,
    apply_operations, validate_secret_path, parse_key_reference,
)
from vault_portal.vault import DemoVault, RealVault, VaultError, WriteOutcomeUnknown

# Single mode switch: True uses synthetic data only; False enables real Vault access.
# Change this only when deliberately preparing a real deployment.
DRY_RUN = False
ALLOWED_VAULT_HOSTS = {
    "vault.sandbox.com",
    "vault.pilot.com",
    "vault.prod.com",
}
PREVIEW_TTL_SECONDS = 15 * 60
ENVIRONMENTS = {
    "Sandbox": {"url": "https://vault.sandbox.com", "token_var": "VAULT_TOKEN_SANDBOX", "tone": "sandbox", "label": "CONTROLLED"},
    "Pilot": {"url": "https://vault.pilot.com", "token_var": "VAULT_TOKEN_PILOT", "tone": "pilot", "label": "CONTROLLED"},
    "Prod": {"url": "https://vault.prod.com", "token_var": "VAULT_TOKEN_PROD", "tone": "prod", "label": "CONTROLLED"},
}

def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32),
        MAX_CONTENT_LENGTH=MAX_FILES * MAX_FILE_BYTES + 256_000,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=False,  # localhost HTTP; enable behind HTTPS
        PERMANENT_SESSION_LIFETIME=900,
        VAULT_MODE="demo" if DRY_RUN else "real",
        TESTING=False,
    )
    if test_config:
        app.config.update(test_config)

    # Server-side in-memory preview storage. Each preview is bound to a random
    # browser-session nonce and expires quickly. For a single-operator localhost app,
    # this avoids persisting uploaded instructions or secret values to disk.
    previews = {}
    app.extensions["vault_previews"] = previews
    demo_clients = {}
    connections = {}  # RealVault objects live only in process memory; tokens are never stored in browser sessions.
    app.extensions["vault_connections"] = connections

    def connection_identity(env):
        if app.config["VAULT_MODE"] != "real":
            return f"demo:{env}"
        if env in connections:
            return connections[env]["id"]
        return f"environment-token:{ENVIRONMENTS[env]['token_var']}"

    def vault_client_factory(env):
        if app.config["VAULT_MODE"] != "real":
            # Keep demo state in memory across requests so applying changes behaves
            # like a real versioned secret store during the local session.
            if env not in demo_clients:
                demo_clients[env] = DemoVault(env)
            return demo_clients[env]
        if env in connections:
            return connections[env]["client"]
        return make_vault_client(app, env)
    app.extensions["vault_client_factory"] = vault_client_factory

    @app.before_request
    def security_headers():
        if "_csrf" not in session:
            session["_csrf"] = secrets.token_urlsafe(32)
        if "_browser_nonce" not in session:
            session["_browser_nonce"] = secrets.token_urlsafe(24)

    @app.after_request
    def add_headers(response):
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
        return response

    def csrf_valid():
        supplied = request.form.get("csrf_token", "")
        expected = session.get("_csrf", "")
        return bool(supplied and expected and secrets.compare_digest(supplied, expected))

    def require_csrf(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not csrf_valid():
                abort(400, description="Your form security token is missing or expired. Refresh the page and try again.")
            return fn(*args, **kwargs)
        return wrapped

    def active_preview():
        pid = session.get("preview_id")
        entry = previews.get(pid) if pid else None
        if not entry:
            return None
        if entry["expires_at"] < time.time() or entry["browser_nonce"] != session.get("_browser_nonce"):
            previews.pop(pid, None)
            session.pop("preview_id", None)
            return None
        return entry

    @app.context_processor
    def common_context():
        return {
            "csrf_token": session.get("_csrf", ""),
            "mode": "REAL" if app.config["VAULT_MODE"] == "real" else "DEMO",
            "environments": ENVIRONMENTS,
            "now_year": datetime.now().year,
            "connection_status": {env: ("connected" if env in connections else "not configured") for env, item in ENVIRONMENTS.items()},
        }

    @app.errorhandler(RequestEntityTooLarge)
    def too_large(_error):
        flash("Upload is too large. Keep each .txt file under 256 KB and the batch within the configured limit.", "error")
        return redirect(url_for("index"))

    @app.errorhandler(400)
    def bad_request(error):
        return render_template("error.html", code=400, message=getattr(error, "description", "Bad request")), 400

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", code=404, message="That page or preview is no longer available."), 404

    @app.get("/connections")
    def connections_page():
        return render_template("connections.html", connections=connections)

    @app.post("/connections/add")
    @require_csrf
    def add_connection():
        if app.config["VAULT_MODE"] != "real":
            flash("Connections can only be tested and saved in REAL mode. Demo mode never makes network requests.", "error")
            return redirect(url_for("connections_page"))
        env = request.form.get("environment", "")
        address = request.form.get("address", "").strip().rstrip("/")
        token = request.form.get("token", "")
        if env not in ENVIRONMENTS:
            flash("Choose a valid environment.", "error")
            return redirect(url_for("connections_page"))
        parsed_url = urlparse(address)
        if parsed_url.scheme != "https" or not parsed_url.hostname or parsed_url.username or parsed_url.password or parsed_url.query or parsed_url.fragment:
            flash("Vault address must be a valid HTTPS URL without embedded credentials, query, or fragment.", "error")
            return redirect(url_for("connections_page"))
        if not token or len(token) > 4096 or "\n" in token or "\r" in token:
            flash("Enter a valid Vault token. Tokens are held in server memory only and are not saved to disk.", "error")
            return redirect(url_for("connections_page"))
        # Optional exact-host allowlist protects against accidental or malicious SSRF.
        allowed_hosts = {host.lower() for host in ALLOWED_VAULT_HOSTS}
        if parsed_url.hostname.lower() not in allowed_hosts:
            flash("This Vault host is not in the code-level ALLOWED_VAULT_HOSTS allowlist.", "error")
            return redirect(url_for("connections_page"))
        try:
            candidate = RealVault(address, token, timeout=5)
            candidate.test_connection()
        except VaultError as exc:
            flash(f"Connection test failed: {exc}", "error")
            return redirect(url_for("connections_page"))
        connections[env] = {"id": uuid.uuid4().hex, "address": address, "client": candidate, "configured_at": time.time()}
        flash(f"{env} connection verified and stored in memory. It will be lost when the app restarts.", "success")
        return redirect(url_for("connections_page"))

    @app.post("/connections/remove/<environment>")
    @require_csrf
    def remove_connection(environment):
        if environment not in ENVIRONMENTS:
            abort(404)
        connections.pop(environment, None)
        flash(f"The in-memory connection for {environment} was removed. Environment-variable fallback, if configured, remains available.", "info")
        return redirect(url_for("connections_page"))

    @app.get("/")
    def index():
        preview = active_preview()
        return render_template("index.html", preview=preview)

    def resolve_references(operations, client):
        resolved = []
        dependencies = []
        for operation in operations:
            item = dict(operation)
            reference = parse_key_reference(item.get("value", ""))
            if reference:
                source_path, source_key = reference
                source_data, source_version = client.read_secret(source_path)
                if source_key not in source_data:
                    raise InstructionError(f"Key reference points to missing key '{source_path}.{source_key}'.")
                source_value = source_data[source_key]
                if not isinstance(source_value, str):
                    raise InstructionError(f"Key reference '{source_path}.{source_key}' is not a string value.")
                item["reference"] = f"Key: <{source_path}.{source_key}>"
                item["value"] = source_value
                dependencies.append({"secret_path": source_path, "version": source_version, "key": source_key, "value": source_value})
            resolved.append(item)
        # Keep only one dependency record per path/key pair.
        unique = {}
        for dependency in dependencies:
            unique[(dependency["secret_path"], dependency["key"])] = dependency
        return resolved, list(unique.values())

    def dependencies_are_current(entry, client):
        for dependency in entry.get("references", []):
            data, version = client.read_secret(dependency["secret_path"])
            if version != dependency["version"] or data.get(dependency["key"]) != dependency["value"]:
                return False
        return True

    @app.post("/preview")
    @require_csrf
    def preview_upload():
        env = request.form.get("environment", "")
        if env not in ENVIRONMENTS:
            flash("Choose a valid Vault environment.", "error")
            return redirect(url_for("index"))

        uploaded = request.files.getlist("files")
        usable = [f for f in uploaded if f and f.filename]
        if not usable:
            flash("Choose a folder or at least one .txt instruction file first.", "error")
            return redirect(url_for("index"))
        if len(usable) > MAX_FILES:
            flash(f"Too many files. The limit is {MAX_FILES} instruction files per preview.", "error")
            return redirect(url_for("index"))

        selected_files = []
        parsed = []
        names = set()
        total_bytes = 0
        try:
            for item in usable:
                relative_name = item.filename.replace("\\", "/").strip("/")
                filename = relative_name.split("/")[-1]
                selected_files.append(relative_name)
                if not filename or not filename.lower().endswith(".txt"):
                    raise InstructionError(f"{filename or 'Unnamed file'}: only .txt files are accepted.")
                raw = item.stream.read(MAX_FILE_BYTES + 1)
                if len(raw) > MAX_FILE_BYTES:
                    raise InstructionError(f"{filename}: exceeds the 256 KB per-file limit.")
                total_bytes += len(raw)
                if total_bytes > MAX_FILES * MAX_FILE_BYTES:
                    raise InstructionError("The total upload exceeds the allowed size.")
                try:
                    text = raw.decode("utf-8-sig")
                except UnicodeDecodeError:
                    raise InstructionError(f"{filename}: file must be UTF-8 text.")
                if not text.strip():
                    raise InstructionError(f"{filename}: file is empty.")
                if filename in names:
                    raise InstructionError(f"Duplicate filename '{filename}'. Rename one file and retry.")
                names.add(filename)
                parsed.append((filename, parse_instruction(text)))
            paths = [instruction["secret_path"] for _, instruction in parsed]
            if len(paths) != len(set(paths)):
                raise InstructionError("Multiple files target the same secret path. Split them into separate previews to keep each file unambiguous.")

            client = app.extensions["vault_client_factory"](env)
            entries = []
            for filename, instruction in parsed:
                current, version = client.read_secret(instruction["secret_path"])
                resolved_operations, dependencies = resolve_references(instruction["operations"], client)
                proposed = apply_operations(current, resolved_operations)
                entries.append({
                    "id": uuid.uuid4().hex,
                    "filename": filename,
                    "environment": env,
                    "secret_path": instruction["secret_path"],
                    "version": version,
                    "operations": resolved_operations,
                    "references": dependencies,
                    "before": current,
                    "after": proposed,
                    "changed": current != proposed,
                    "status": "pending" if current != proposed else "unchanged",
                    "error": None,
                })
            pid = uuid.uuid4().hex
            previews[pid] = {
                "id": pid, "environment": env, "created_at": time.time(),
                "expires_at": time.time() + PREVIEW_TTL_SECONDS,
                "browser_nonce": session["_browser_nonce"], "entries": entries,
                "selected_files": selected_files,
                "connection_identity": connection_identity(env),
            }
            session["preview_id"] = pid
            flash("Preview created. Review every proposed change before applying.", "success")
            return redirect(url_for("index"))
        except (InstructionError, VaultError) as exc:
            # Deliberately do not include raw Vault response bodies or credentials.
            flash(str(exc), "error")
            return redirect(url_for("index"))

    def apply_entry(entry, preview, client):
        if entry["status"] != "pending":
            return
        try:
            if not dependencies_are_current(entry, client):
                entry["status"] = "stale"
                entry["error"] = "A referenced source key changed after preview. Create a fresh preview."
                return
            current, version = client.read_secret(entry["secret_path"])
            if version != entry["version"] or current != entry["before"]:
                entry["status"] = "stale"
                entry["error"] = "Vault changed after preview. Create a fresh preview before applying."
                return
            if current == entry["after"]:
                entry["status"] = "unchanged"
                return
            client.write_secret(entry["secret_path"], entry["after"], cas=version)
            entry["status"] = "applied"
            entry["error"] = None
        except WriteOutcomeUnknown:
            entry["status"] = "outcome_unknown"
            entry["error"] = "The write may have reached Vault, but its response was not received. Do not retry automatically. Inspect Vault, then create a fresh preview."
            raise
        except VaultError as exc:
            if getattr(exc, "stale", False):
                entry["status"] = "stale"
                entry["error"] = "Vault version changed. Create a fresh preview."
            else:
                entry["status"] = "failed"
                entry["error"] = str(exc)
            raise

    @app.post("/apply/<entry_id>")
    @require_csrf
    def apply_one(entry_id):
        preview = active_preview()
        if not preview:
            flash("Preview expired or unavailable. Upload the instruction files again.", "error")
            return redirect(url_for("index"))
        entry = next((e for e in preview["entries"] if e["id"] == entry_id), None)
        if not entry:
            abort(404)
        if preview["environment"] == "Prod" and request.form.get("prod_confirmation") != "Prod":
            flash("For Prod, type Prod exactly in the confirmation field.", "error")
            return redirect(url_for("index"))
        if preview.get("connection_identity") != connection_identity(preview["environment"]):
            flash("The Vault connection changed after preview. Upload the files again and review a fresh preview.", "error")
            return redirect(url_for("index"))
        if entry["status"] != "pending":
            flash("This file is no longer pending and cannot be applied again.", "error")
            return redirect(url_for("index"))
        client = app.extensions["vault_client_factory"](preview["environment"])
        try:
            apply_entry(entry, preview, client)
            flash(f"{entry['filename']}: {entry['status'].replace('_', ' ').upper()}.", "success" if entry["status"] in ("applied", "unchanged") else "error")
        except (VaultError, WriteOutcomeUnknown):
            flash(f"{entry['filename']}: {entry['status'].replace('_', ' ').upper()}. Review the status before doing anything else.", "error")
        return redirect(url_for("index"))

    @app.post("/apply-all")
    @require_csrf
    def apply_all():
        preview = active_preview()
        if not preview:
            flash("Preview expired or unavailable. Upload the instruction files again.", "error")
            return redirect(url_for("index"))
        if preview["environment"] == "Prod" and request.form.get("prod_confirmation") != "Prod":
            flash("For Prod, type Prod exactly in the confirmation field.", "error")
            return redirect(url_for("index"))
        if preview.get("connection_identity") != connection_identity(preview["environment"]):
            flash("The Vault connection changed after preview. Upload the files again and review a fresh preview.", "error")
            return redirect(url_for("index"))
        pending = [e for e in preview["entries"] if e["status"] == "pending"]
        if not pending:
            flash("There are no pending changes to apply.", "info")
            return redirect(url_for("index"))
        client = app.extensions["vault_client_factory"](preview["environment"])
        # Preflight every pending secret before the first write.
        try:
            for entry in pending:
                if not dependencies_are_current(entry, client):
                    entry["status"] = "stale"
                    entry["error"] = "A referenced source key changed after preview. Create a fresh preview."
                    flash(f"Batch stopped before writing: a referenced source for {entry['filename']} is stale. No batch writes were started.", "error")
                    return redirect(url_for("index"))
                current, version = client.read_secret(entry["secret_path"])
                if version != entry["version"] or current != entry["before"]:
                    entry["status"] = "stale"
                    entry["error"] = "Vault changed after preview. Create a fresh preview."
                    flash(f"Batch stopped before writing: {entry['filename']} is stale. No batch writes were started.", "error")
                    return redirect(url_for("index"))
        except VaultError:
            flash("Batch preflight failed. No batch writes were started. Check Vault connectivity/configuration and create a fresh preview.", "error")
            return redirect(url_for("index"))

        for entry in pending:
            try:
                apply_entry(entry, preview, client)
            except (VaultError, WriteOutcomeUnknown):
                flash(f"Batch stopped at {entry['filename']} ({entry['status'].replace('_', ' ').upper()}). Earlier successful writes are not rolled back; Vault has no multi-secret atomic transaction.", "error")
                break
        else:
            flash("All pending entries have been processed. Check each per-file status below.", "success")
        return redirect(url_for("index"))

    @app.post("/clear")
    @require_csrf
    def clear_preview():
        pid = session.pop("preview_id", None)
        if pid:
            previews.pop(pid, None)
        flash("Preview cleared from this browser session.", "info")
        return redirect(url_for("index"))

    return app


def make_vault_client(app, environment):
    if app.config["VAULT_MODE"] != "real":
        return DemoVault(environment)
    raise VaultError(f"No in-memory connection is configured for {environment}. Open Connections and verify a Vault address and token first.")


app = create_app()

if __name__ == "__main__":
    if not DRY_RUN:
        print("Vault Change Portal v2 starting in REAL mode. Confirm target environment before applying.")
    else:
        print("Vault Change Portal v2 starting in DEMO mode — no changes are made to Vault.")
    print("Build: updated Connections / key references / CONTROLLED labels / file picker preview")
    print("Open: http://127.0.0.1:5001")
    app.run(host="127.0.0.1", port=5001, debug=False)
