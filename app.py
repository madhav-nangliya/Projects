# =============================================================================
# app.py — LanSentry Flask Application (Week 4: DB + Chart API routes)
# =============================================================================
# This is the entry point for the Flask web server.
# It wires together scanner.py (data) and templates/ (UI).
#
# Week 4 additions (marked ★):
#   ★ Call init_db() at startup
#   ★ /api/chart/scan-history  — line chart data
#   ★ /api/chart/device-status — doughnut chart data
#   ★ /api/chart/alerts        — bar chart data
#   ★ /api/alerts + dismiss routes
#   ★ /api/status includes DB health
#   ★ All page routes now pass DB data to templates
#
# BUG FIXES (marked ✦):
#   ✦ devices_page() now detects the server's own IP and marks is_me / is_gateway
#     on every device dict before passing to the template.  Previously those two
#     fields were never set, so the "YOU" badge and "Protected" button never
#     appeared and block buttons were shown for the gateway/host machine.
#   ✦ api_devices() applies the same is_me / is_gateway enrichment so the
#     JavaScript live-refresh table also renders them correctly.
# =============================================================================

from flask import Flask, render_template, jsonify, request, redirect, url_for
import logging         # Standard Python logging
import os              # Access environment variables (future .env support)
import socket          # ✦ Used to detect this machine's own IP address
from datetime import datetime

# Our own modules
import database as db                 # ★ Week 4: database layer
from scanner import (
    start_background_scanner,         # Start the background scan thread
    trigger_manual_scan,              # On-demand scan
    get_cached_devices,               # Latest scan from in-memory cache
    get_scan_status,                  # Scanner health info
)

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================
# basicConfig sets up the ROOT logger which all child loggers (scanner, database)
# inherit from. Everything at INFO level and above goes to both console and file.
logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    # asctime   — timestamp
    # name      — which module logged this (scanner, database, app, …)
    # levelname — INFO / WARNING / ERROR
    # message   — the actual log string

    handlers = [
        logging.StreamHandler(),                         # Print to terminal
        logging.FileHandler("lansentry.log", mode="a"), # Append to log file
    ]
)
logger = logging.getLogger("app")   # This module's logger


# =============================================================================
# ✦ HELPER — detect this server's own IP
# =============================================================================

def _get_my_ip():
    """
    Return the primary LAN IP of this machine (e.g. "192.168.1.105").
    Uses a UDP trick: we connect to an external address without sending any
    data — the OS picks the correct outbound interface and we read its IP.
    Falls back to gethostbyname if the trick fails (e.g. no internet route).
    """
    try:
        # This never actually sends a packet; it just forces the OS to
        # choose a source interface for the given destination.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))          # Google DNS — destination only
        ip = s.getsockname()[0]             # Read which local IP was selected
        s.close()
        return ip
    except Exception:
        # Last-resort fallback — returns 127.0.0.1 on headless systems
        return socket.gethostbyname(socket.gethostname())


def _enrich_devices(devices):
    """
    ✦ Add two boolean fields to every device dict so templates and JS can
    render the correct badge / button without duplicating this logic:

        is_me      — True if this device IS the machine running LanSentry
        is_gateway — True if this device is the network gateway (ends in .1)

    These fields are not stored in the DB because they depend on which machine
    the app is running on; they are calculated fresh on each request.
    """
    my_ip = _get_my_ip()

    for d in devices:
        ip = d.get("ip", "")

        # Mark the server's own device
        d["is_me"] = (ip == my_ip)

        # Heuristic: gateways almost always have the last octet = 1
        # e.g. 192.168.1.1, 10.0.0.1 — good enough for home/office networks
        d["is_gateway"] = ip.endswith(".1") and not d["is_me"]

    return devices


# =============================================================================
# FLASK APP INITIALISATION
# =============================================================================
app = Flask(__name__)

# Secret key is required by Flask for session cookies and CSRF.
# In Week 5 (Flask-Login) this becomes critical — use a real random value.
app.secret_key = os.environ.get("LANSENTRY_SECRET", "change-me-in-production-week6")


# =============================================================================
# STARTUP SEQUENCE
# =============================================================================
# This runs before the first request is served.
# We do it here (not at module level) so it only runs once in the main process
# (avoids double-init if Flask's debug reloader forks the process).

def startup():
    """
    1. Initialise the database (create pool + tables).
    2. Start the background scan thread.
    """
    logger.info("=" * 60)
    logger.info("🚀 LanSentry starting up — Week 4 (DB + Charts)")
    logger.info("=" * 60)

    # ★ Initialise the database connection pool + create tables
    if db.init_db():
        logger.info("✅ Database ready")
    else:
        logger.error("❌ Database init failed — running without persistence")
        # The app still works (reads from scan cache) even if DB is down

    # Start the background network scanner
    start_background_scanner()
    logger.info("✅ LanSentry fully started")


# Call startup immediately when app.py is imported/run
startup()


# =============================================================================
# SECTION 1 — PAGE ROUTES (return rendered HTML templates)
# =============================================================================

@app.route("/")
def home():
    """
    Dashboard homepage.
    Passes device stats and unread alert count to home.html.
    """
    # ★ Get live stats from DB for the stat cards
    stats         = db.get_device_stats()
    unread_alerts = db.get_unread_alert_count()

    return render_template(
        "home.html",
        stats         = stats,          # {'total': N, 'online': N, …}
        unread_alerts = unread_alerts,  # Integer — shown in nav badge
        page          = "home"          # Used in base.html to highlight active nav link
    )


@app.route("/devices")
def devices_page():
    """
    Devices table page — shows all known devices with block/unblock buttons.
    Reads from the DB (persistent) rather than just the scan cache.
    """
    # ★ Fetch all devices from DB (includes offline devices, not just current scan)
    all_devices   = db.get_all_devices()
    unread_alerts = db.get_unread_alert_count()

    # ✦ Tag each device with is_me / is_gateway so the template can render
    #    the "YOU" badge and hide the Block button for protected devices.
    #    This was missing before — both fields were always undefined/falsy.
    all_devices = _enrich_devices(all_devices)

    return render_template(
        "devices.html",
        devices       = all_devices,
        unread_alerts = unread_alerts,
        page          = "devices"
    )


@app.route("/alerts")
def alerts_page():
    """
    Alert log page — shows all system events (new devices, offline, blocked).
    """
    all_alerts    = db.get_alerts(limit=200)    # Last 200 alerts
    unread_alerts = db.get_unread_alert_count()

    return render_template(
        "alerts.html",
        alerts        = all_alerts,
        unread_alerts = unread_alerts,
        page          = "alerts"
    )


# =============================================================================
# SECTION 2 — DEVICE API ENDPOINTS
# =============================================================================

@app.route("/api/devices")
def api_devices():
    """
    GET /api/devices
    Returns all devices as JSON.
    Used by the live-refresh JavaScript in devices.html.
    """
    devices = db.get_all_devices()

    # ✦ Enrich with is_me / is_gateway so the JS renderTable() function
    #    can show the correct badge and button — same as the server-side template.
    devices = _enrich_devices(devices)

    # Convert datetime objects to ISO strings so the JSON serialiser doesn't fail
    for d in devices:
        if isinstance(d.get("first_seen"), datetime):
            d["first_seen"] = d["first_seen"].isoformat()
        if isinstance(d.get("last_seen"), datetime):
            d["last_seen"] = d["last_seen"].isoformat()

    return jsonify({"success": True, "devices": devices, "count": len(devices)})


@app.route("/api/devices/<mac>/block", methods=["POST"])
def api_block_device(mac):
    """
    POST /api/devices/<mac>/block
    Toggles the blocked state of a device.
    Body JSON: {"blocked": true} or {"blocked": false}
    Called by the Block/Unblock button in devices.html via fetch().
    """
    data    = request.get_json(silent=True) or {}
    blocked = bool(data.get("blocked", True))   # Default to blocking if not specified

    success = db.set_device_blocked(mac=mac.upper(), blocked=blocked)

    if success:
        action = "blocked" if blocked else "unblocked"
        # ★ Create an alert for the block/unblock action
        device = db.get_device_by_mac(mac.upper())
        if device:
            db.create_alert(
                alert_type  = "blocked_attempt" if blocked else "new_device",
                device_mac  = mac.upper(),
                device_ip   = device.get("ip", ""),
                device_name = device.get("hostname", "Unknown"),
                message     = f"Admin manually {action} device: {device.get('vendor','Unknown')} ({device.get('ip','')})",
                severity    = "warning" if blocked else "info"
            )
        return jsonify({"success": True, "message": f"Device {action}", "mac": mac})

    return jsonify({"success": False, "message": "Device not found"}), 404


# =============================================================================
# SECTION 3 — SCANNER API ENDPOINTS
# =============================================================================

@app.route("/api/scan-status")
def api_scan_status():
    """
    GET /api/scan-status
    Returns current scanner status (running, last scan time, etc.)
    Polled by the dashboard every few seconds for the live indicator.
    """
    status = get_scan_status()
    return jsonify({"success": True, **status})


@app.route("/api/scan/trigger", methods=["POST"])
def api_trigger_scan():
    """
    POST /api/scan/trigger
    Manually kicks off an immediate scan.
    Called by the "Scan Now" button on the dashboard.
    """
    started = trigger_manual_scan()

    if started:
        return jsonify({"success": True, "message": "Manual scan started"})
    return jsonify({"success": False, "message": "Scan already running"}), 409   # 409 Conflict


# =============================================================================
# SECTION 4 ★ — CHART API ENDPOINTS (Week 4 new routes)
# =============================================================================

@app.route("/api/chart/scan-history")
def api_chart_scan_history():
    """
    GET /api/chart/scan-history?hours=24
    Returns time-series data for the LINE CHART on the dashboard.
    Shows how many devices were online across the last N hours.

    Response shape:
    {
      "labels":        ["10:00", "10:01", ...],   ← X-axis labels
      "devices_found": [4, 5, 4, 6, ...],         ← primary dataset
      "new_devices":   [0, 1, 0, 2, ...]          ← secondary dataset
    }
    """
    # Read optional query param: /api/chart/scan-history?hours=48
    hours = request.args.get("hours", 24, type=int)
    hours = max(1, min(hours, 168))   # Clamp between 1 hour and 7 days

    rows = db.get_scan_history_for_chart(hours=hours)

    # Separate the data into parallel arrays (Chart.js format)
    labels        = [row["label"]         for row in rows]
    devices_found = [row["devices_found"] for row in rows]
    new_devices   = [row["new_devices"]   for row in rows]

    return jsonify({
        "success":       True,
        "hours":         hours,
        "labels":        labels,
        "devices_found": devices_found,
        "new_devices":   new_devices,
    })


@app.route("/api/chart/device-status")
def api_chart_device_status():
    """
    GET /api/chart/device-status
    Returns device status counts for the DOUGHNUT CHART on the dashboard.

    Response shape:
    {
      "labels": ["Online", "Offline", "Blocked"],
      "data":   [5, 2, 1]
    }
    """
    stats = db.get_device_stats()   # {'online': N, 'offline': N, 'blocked': N, …}

    return jsonify({
        "success": True,
        "labels":  ["Online", "Offline", "Blocked"],
        "data":    [stats["online"], stats["offline"], stats["blocked"]],
    })


@app.route("/api/chart/alerts")
def api_chart_alerts():
    """
    GET /api/chart/alerts?days=7
    Returns daily alert counts grouped by type for the BAR CHART.

    Response shape:
    {
      "labels":          ["2025-01-15", "2025-01-16", ...],
      "new_device":      [2, 0, 1, ...],
      "blocked_attempt": [0, 1, 0, ...],
      "device_offline":  [1, 0, 2, ...],
      "high_risk":       [0, 0, 1, ...]
    }
    """
    days = request.args.get("days", 7, type=int)
    days = max(1, min(days, 30))   # Clamp 1–30 days

    rows = db.get_alerts_for_chart(days=days)

    # Build parallel arrays for Chart.js
    labels          = [str(row["day"])                  for row in rows]
    new_device      = [int(row["new_device"]      or 0) for row in rows]
    blocked_attempt = [int(row["blocked_attempt"] or 0) for row in rows]
    device_offline  = [int(row["device_offline"]  or 0) for row in rows]
    high_risk       = [int(row["high_risk"]       or 0) for row in rows]

    return jsonify({
        "success":         True,
        "days":            days,
        "labels":          labels,
        "new_device":      new_device,
        "blocked_attempt": blocked_attempt,
        "device_offline":  device_offline,
        "high_risk":       high_risk,
    })


@app.route("/api/chart/risk-breakdown")
def api_chart_risk_breakdown():
    """
    GET /api/chart/risk-breakdown
    Returns device counts by risk level for a secondary doughnut chart.
    """
    devices = db.get_all_devices()

    # Count devices at each risk level
    risk_counts = {"low": 0, "medium": 0, "high": 0}
    for d in devices:
        level = d.get("risk_level", "low")
        if level in risk_counts:
            risk_counts[level] += 1

    return jsonify({
        "success": True,
        "labels":  ["Low Risk", "Medium Risk", "High Risk"],
        "data":    [risk_counts["low"], risk_counts["medium"], risk_counts["high"]],
    })


# =============================================================================
# SECTION 5 — ALERT API ENDPOINTS
# =============================================================================

@app.route("/api/alerts")
def api_alerts():
    """
    GET /api/alerts?limit=50&unread_only=false
    Returns alerts as JSON for the live alert feed.
    """
    limit       = request.args.get("limit", 50, type=int)
    unread_only = request.args.get("unread_only", "false").lower() == "true"

    alerts = db.get_alerts(limit=limit, unread_only=unread_only)

    # Serialise datetime objects
    for a in alerts:
        if isinstance(a.get("alert_time"), datetime):
            a["alert_time"] = a["alert_time"].isoformat()

    return jsonify({
        "success": True,
        "alerts":  alerts,
        "count":   len(alerts),
    })


@app.route("/api/alerts/unread-count")
def api_unread_count():
    """
    GET /api/alerts/unread-count
    Returns just the integer count — polled every 30s for the nav badge.
    """
    return jsonify({"success": True, "count": db.get_unread_alert_count()})


@app.route("/api/alerts/<int:alert_id>/read", methods=["POST"])
def api_mark_alert_read(alert_id):
    """
    POST /api/alerts/<id>/read
    Dismisses (marks as read) a single alert.
    """
    success = db.mark_alert_read(alert_id)
    return jsonify({"success": success})


@app.route("/api/alerts/read-all", methods=["POST"])
def api_mark_all_read():
    """
    POST /api/alerts/read-all
    Clears all unread alerts — called by "Clear All" button.
    """
    count = db.mark_all_alerts_read()
    return jsonify({"success": True, "cleared": count})


# =============================================================================
# SECTION 6 — STATUS / HEALTH ENDPOINT
# =============================================================================

@app.route("/api/status")
def api_status():
    """
    GET /api/status
    Full system health check — combines scanner + DB status.
    Useful for a status page or uptime monitoring.
    """
    scanner_status = get_scan_status()
    db_status      = db.get_db_status()     # ★ Week 4: includes DB row counts

    return jsonify({
        "success":  True,
        "scanner":  scanner_status,
        "database": db_status,
        "version":  "1.4.0",   # Bump version each week for easy tracking
    })


# =============================================================================
# SECTION 7 — ERROR HANDLERS
# =============================================================================

@app.errorhandler(404)
def not_found(e):
    """Custom 404 page so Flask's default HTML doesn't leak to the user."""
    return render_template("base.html", error="404 — Page not found", page="error"), 404


@app.errorhandler(500)
def server_error(e):
    """Catch unhandled exceptions and return a friendly error page."""
    logger.error("❌ Unhandled 500 error: %s", e, exc_info=True)
    return render_template("base.html", error="500 — Internal server error", page="error"), 500


# =============================================================================
# ENTRY POINT
# =============================================================================
if __name__ == "__main__":
    # debug=False in production (Week 6)
    # host="0.0.0.0" makes the app accessible on the local network
    # port=5000 is Flask's default; change if another service uses it
    app.run(
        host  = "0.0.0.0",
        port  = 5000,
        debug = True    # Set False before deploying!
    )