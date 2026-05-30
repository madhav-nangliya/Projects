# =============================================================================
# database.py — LanSentry MySQL Database Layer
# =============================================================================
# This file handles ALL database operations for LanSentry.
# It creates the connection pool, defines the schema, and exposes helper
# functions that the rest of the app (app.py, scanner.py) calls.
#
# Tables we manage:
#   • devices        — every unique device ever seen on the network
#   • scan_history   — one row per completed scan (timestamp + count)
#   • alerts         — new device, blocked attempt, gone-offline events
# =============================================================================

import mysql.connector                        # Official MySQL driver for Python
from mysql.connector import pooling           # Connection-pool support
from datetime import datetime                 # For timestamping rows
import logging                                # For writing errors to the log file

# ---------------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------------
# Gets (or creates) a logger named "database" so log messages are tagged.
# The root logger in app.py decides the actual log level + file destination.
logger = logging.getLogger("database")

# ---------------------------------------------------------------------------
# DATABASE CONFIGURATION
# ---------------------------------------------------------------------------
# Store connection params in one place — change here, reflected everywhere.
# In production (Week 6) move these to a .env file / environment variables.
DB_CONFIG = {
    "host":     "localhost",      # MySQL server address (same machine = localhost)
    "port":     3306,             # Default MySQL port
    "user":     "lansentry_user", # DB user we'll create (see setup instructions below)
    "password": "StrongPass123!", # Change this before deploying!
    "database": "lansentry_db",   # Database / schema name
    "charset":  "utf8mb4",        # Full Unicode support (handles emoji in hostnames)
    "collation":"utf8mb4_unicode_ci",
}

# Connection pool configuration
# A pool keeps N connections open so we don't reconnect on every request.
POOL_CONFIG = {
    "pool_name": "lansentry_pool",  # Identifier for the pool (for debugging)
    "pool_size":  5,                # Max simultaneous DB connections
    "pool_reset_session": True,     # Reset session state when connection is reused
}

# ---------------------------------------------------------------------------
# GLOBAL POOL VARIABLE
# ---------------------------------------------------------------------------
# This will hold our connection pool object after init_db() is called once.
_connection_pool = None   # None until init_db() runs


# =============================================================================
# SECTION 1 — INITIALISATION
# =============================================================================

def init_db():
    """
    Called ONCE at app startup (from app.py).
    Steps:
      1. Create the MySQL connection pool.
      2. Run CREATE TABLE IF NOT EXISTS for every table.
    Returns True on success, False on failure.
    """
    global _connection_pool   # We write to the module-level variable

    try:
        # ------------------------------------------------------------------
        # Step 1: Build the connection pool
        # mysql.connector.pooling.MySQLConnectionPool merges DB_CONFIG +
        # POOL_CONFIG into a single kwargs dict.
        # ------------------------------------------------------------------
        _connection_pool = pooling.MySQLConnectionPool(
            **POOL_CONFIG,       # pool_name, pool_size, pool_reset_session
            **DB_CONFIG          # host, port, user, password, database, …
        )
        logger.info("✅ MySQL connection pool created (size=%d)", POOL_CONFIG["pool_size"])

        # ------------------------------------------------------------------
        # Step 2: Create tables if they don't exist yet
        # ------------------------------------------------------------------
        _create_tables()
        logger.info("✅ Database tables verified / created")
        return True

    except mysql.connector.Error as err:
        # Log the exact MySQL error code + message for easier debugging
        logger.error("❌ Database init failed: %s", err)
        return False


def get_connection():
    """
    Borrow a connection from the pool.
    Caller is responsible for calling connection.close() to return it to the pool.
    Raises RuntimeError if init_db() was never called.
    """
    if _connection_pool is None:
        raise RuntimeError("Database pool not initialised — call init_db() first.")
    return _connection_pool.get_connection()   # Blocks until a connection is free


# =============================================================================
# SECTION 2 — SCHEMA CREATION
# =============================================================================

def _create_tables():
    """
    Private helper — creates all three tables inside a single connection.
    Uses CREATE TABLE IF NOT EXISTS so it's safe to call on every startup.
    """
    conn   = get_connection()   # Borrow a connection from the pool
    cursor = conn.cursor()      # Create a cursor (executes SQL statements)

    try:
        # ------------------------------------------------------------------
        # TABLE 1: devices
        # Stores every unique network device identified by its MAC address.
        # MAC is the primary key because it never changes (unlike IP).
        # ------------------------------------------------------------------
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id           INT          AUTO_INCREMENT PRIMARY KEY,
                -- Auto-incrementing numeric ID (internal use)

                mac          VARCHAR(17)  NOT NULL UNIQUE,
                -- MAC address in AA:BB:CC:DD:EE:FF format — unique identifier

                ip           VARCHAR(15)  NOT NULL,
                -- Current IPv4 address (can change via DHCP — we update it)

                hostname     VARCHAR(255) DEFAULT 'Unknown',
                -- Resolved hostname from nmap -sn / reverse DNS

                vendor       VARCHAR(255) DEFAULT 'Unknown',
                -- NIC manufacturer resolved from MAC OUI (nmap does this)

                os_guess     VARCHAR(255) DEFAULT 'Unknown',
                -- OS fingerprint from nmap -O (best effort)

                open_ports   TEXT         DEFAULT '',
                -- Comma-separated list e.g. "22,80,443" — updated each scan

                status       ENUM('online','offline','blocked') DEFAULT 'online',
                -- Current status: online=seen this scan, offline=not seen, blocked=firewalled

                is_blocked   TINYINT(1)   DEFAULT 0,
                -- 1 = admin manually blocked this device, 0 = normal

                risk_level   ENUM('low','medium','high') DEFAULT 'low',
                -- Calculated risk: high if many open ports or unknown device

                first_seen   DATETIME     DEFAULT CURRENT_TIMESTAMP,
                -- When this device was discovered for the first time

                last_seen    DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                -- Auto-updated every time we touch this row
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)

        # ------------------------------------------------------------------
        # TABLE 2: scan_history
        # One row per completed network scan.
        # Used to draw the "Devices Over Time" line chart on the dashboard.
        # ------------------------------------------------------------------
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id              INT      AUTO_INCREMENT PRIMARY KEY,
                -- Auto ID

                scan_time       DATETIME DEFAULT CURRENT_TIMESTAMP,
                -- When the scan finished (index this for fast time-range queries)

                devices_found   INT      DEFAULT 0,
                -- How many devices were online during this scan

                new_devices     INT      DEFAULT 0,
                -- How many of those had never been seen before

                scan_duration   FLOAT    DEFAULT 0.0,
                -- How long the scan took in seconds (useful for performance monitoring)

                subnet          VARCHAR(50) DEFAULT '',
                -- Which subnet was scanned e.g. "192.168.1.0/24"

                INDEX idx_scan_time (scan_time)
                -- Index on scan_time for fast ORDER BY / range queries
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)

        # ------------------------------------------------------------------
        # TABLE 3: alerts
        # Event log — new device spotted, blocked device tried to connect, etc.
        # Used to populate the Alerts page and the dashboard alert count badge.
        # ------------------------------------------------------------------
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id           INT          AUTO_INCREMENT PRIMARY KEY,

                alert_time   DATETIME     DEFAULT CURRENT_TIMESTAMP,
                -- When the event was detected

                alert_type   VARCHAR(50)  NOT NULL,
                -- Short category string:
                --   'new_device'     — first time this MAC was seen
                --   'device_offline' — was online, now gone
                --   'blocked_attempt'— blocked MAC was detected on the network
                --   'port_change'    — open ports changed since last scan
                --   'high_risk'      — device flagged as high risk

                device_mac   VARCHAR(17)  DEFAULT '',
                -- MAC of the device that triggered the alert

                device_ip    VARCHAR(15)  DEFAULT '',
                -- IP at the time of the alert

                device_name  VARCHAR(255) DEFAULT 'Unknown',
                -- Hostname or vendor name for display in the alerts table

                message      TEXT         NOT NULL,
                -- Human-readable description shown in the UI

                severity     ENUM('info','warning','critical') DEFAULT 'info',
                -- Used to colour-code the alert row in alerts.html

                is_read      TINYINT(1)   DEFAULT 0,
                -- 0 = unread (shown in badge count), 1 = dismissed by admin

                INDEX idx_alert_time (alert_time),
                -- Fast queries ordered by time
                INDEX idx_is_read (is_read)
                -- Fast queries filtering unread alerts
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)

        conn.commit()   # Commit DDL (CREATE TABLE) — required by some MySQL configs

    except mysql.connector.Error as err:
        logger.error("❌ Table creation error: %s", err)
        conn.rollback()   # Roll back any partial DDL
        raise             # Re-raise so init_db() can catch it and return False

    finally:
        cursor.close()   # Always close cursor
        conn.close()     # Always return connection to pool (NOT a real disconnect)


# =============================================================================
# SECTION 3 — DEVICE FUNCTIONS
# =============================================================================

def upsert_device(mac, ip, hostname="Unknown", vendor="Unknown",
                  os_guess="Unknown", open_ports="", status="online"):
    """
    INSERT a new device OR UPDATE an existing one (identified by MAC).
    Returns: (row_id, is_new_device)
        row_id       — the devices.id value
        is_new_device— True if this MAC had never been seen before
    Called by scanner.py after every scan.
    """
    conn   = get_connection()
    cursor = conn.cursor()

    try:
        # ------------------------------------------------------------------
        # First, check if this MAC already exists in the table.
        # We need to know this to generate a 'new_device' alert.
        # ------------------------------------------------------------------
        cursor.execute(
            "SELECT id FROM devices WHERE mac = %s",   # %s = parameterised query (safe from SQL injection)
            (mac,)                                      # Tuple — always use parameterised queries!
        )
        existing = cursor.fetchone()   # Returns (id,) tuple or None
        is_new   = existing is None    # True if no row matched

        if is_new:
            # --------------------------------------------------------------
            # INSERT — brand new device
            # --------------------------------------------------------------
            cursor.execute("""
                INSERT INTO devices
                    (mac, ip, hostname, vendor, os_guess, open_ports, status)
                VALUES
                    (%s,  %s, %s,      %s,     %s,       %s,         %s)
            """, (mac, ip, hostname, vendor, os_guess, open_ports, status))

            row_id = cursor.lastrowid   # MySQL gives us the auto-increment ID

        else:
            # --------------------------------------------------------------
            # UPDATE — device seen before; refresh mutable fields.
            # We do NOT overwrite first_seen (it stays as the original date).
            # last_seen updates automatically via ON UPDATE CURRENT_TIMESTAMP.
            # --------------------------------------------------------------
            row_id = existing[0]   # Extract the integer ID from the tuple

            cursor.execute("""
                UPDATE devices
                SET ip         = %s,
                    hostname   = %s,
                    vendor     = %s,
                    os_guess   = %s,
                    open_ports = %s,
                    status     = %s
                WHERE mac = %s
            """, (ip, hostname, vendor, os_guess, open_ports, status, mac))

        conn.commit()   # Persist INSERT or UPDATE
        return row_id, is_new

    except mysql.connector.Error as err:
        logger.error("❌ upsert_device(%s): %s", mac, err)
        conn.rollback()
        return None, False

    finally:
        cursor.close()
        conn.close()


def get_all_devices():
    """
    Fetch every row from the devices table, ordered newest first.
    Returns a list of dicts — one dict per device.
    Called by app.py for the /devices route and /api/devices endpoint.
    """
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)   # dictionary=True → rows come back as {col: value}

    try:
        cursor.execute("""
            SELECT
                id, mac, ip, hostname, vendor, os_guess,
                open_ports, status, is_blocked, risk_level,
                first_seen, last_seen
            FROM devices
            ORDER BY last_seen DESC   -- Most recently seen device at the top
        """)
        return cursor.fetchall()   # List of dicts, empty list if no devices yet

    except mysql.connector.Error as err:
        logger.error("❌ get_all_devices: %s", err)
        return []

    finally:
        cursor.close()
        conn.close()


def get_device_by_mac(mac):
    """
    Fetch a single device row by its MAC address.
    Returns a dict or None if not found.
    """
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("SELECT * FROM devices WHERE mac = %s", (mac,))
        return cursor.fetchone()   # One dict or None

    except mysql.connector.Error as err:
        logger.error("❌ get_device_by_mac(%s): %s", mac, err)
        return None

    finally:
        cursor.close()
        conn.close()


def set_device_blocked(mac, blocked: bool):
    """
    Toggle the is_blocked flag for a device.
    blocked=True  → block (status='blocked', is_blocked=1)
    blocked=False → unblock (status='online',  is_blocked=0)
    Returns True on success.
    Called by app.py when admin clicks Block/Unblock button.
    """
    conn   = get_connection()
    cursor = conn.cursor()

    # Choose the right status string based on the blocked flag
    status = "blocked" if blocked else "online"
    flag   = 1         if blocked else 0

    try:
        cursor.execute("""
            UPDATE devices
            SET is_blocked = %s,
                status     = %s
            WHERE mac = %s
        """, (flag, status, mac))

        conn.commit()
        return cursor.rowcount > 0   # rowcount = number of rows affected; 0 means MAC not found

    except mysql.connector.Error as err:
        logger.error("❌ set_device_blocked(%s, %s): %s", mac, blocked, err)
        conn.rollback()
        return False

    finally:
        cursor.close()
        conn.close()


def mark_devices_offline(active_macs: list):
    """
    After a scan, mark any device NOT in active_macs as 'offline'.
    active_macs — list of MAC strings that were found in the LATEST scan.

    Uses a NOT IN clause with a parameterised tuple.
    If active_macs is empty we skip the update (avoid wiping everything).
    """
    if not active_macs:
        return   # Safety guard: don't mark everything offline on empty scan

    conn   = get_connection()
    cursor = conn.cursor()

    try:
        # Build a (?, ?, ?) placeholder string matching the list length
        placeholders = ", ".join(["%s"] * len(active_macs))   # "%s, %s, %s, ..."

        cursor.execute(f"""
            UPDATE devices
            SET status = 'offline'
            WHERE mac NOT IN ({placeholders})
              AND is_blocked = 0          -- Don't change status of blocked devices
              AND status = 'online'       -- Only update currently-online devices
        """, tuple(active_macs))          # Convert list to tuple for the driver

        conn.commit()
        if cursor.rowcount:
            logger.info("📴 Marked %d device(s) offline", cursor.rowcount)

    except mysql.connector.Error as err:
        logger.error("❌ mark_devices_offline: %s", err)
        conn.rollback()

    finally:
        cursor.close()
        conn.close()


def get_device_stats():
    """
    Returns a summary dict used by the dashboard stat cards:
    {
        'total':   int,   # All devices ever seen
        'online':  int,   # Currently online
        'offline': int,   # Currently offline
        'blocked': int,   # Currently blocked
        'high_risk': int  # Devices with risk_level='high'
    }
    Uses a single query with conditional SUM for efficiency.
    """
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT
                COUNT(*)                                    AS total,
                SUM(status = 'online')                      AS online,
                SUM(status = 'offline')                     AS offline,
                SUM(status = 'blocked')                     AS blocked,
                SUM(risk_level = 'high')                    AS high_risk
            FROM devices
        """)
        # fetchone() returns one dict; default to 0 for any NULL column
        row = cursor.fetchone()
        return {k: (v or 0) for k, v in row.items()}   # Replace None with 0

    except mysql.connector.Error as err:
        logger.error("❌ get_device_stats: %s", err)
        return {"total": 0, "online": 0, "offline": 0, "blocked": 0, "high_risk": 0}

    finally:
        cursor.close()
        conn.close()


# =============================================================================
# SECTION 4 — SCAN HISTORY FUNCTIONS
# =============================================================================

def save_scan_result(devices_found, new_devices, scan_duration, subnet=""):
    """
    Append one row to scan_history after every completed scan.
    Called by scanner.py at the end of run_scan().
    Returns the new row's ID or None on failure.
    """
    conn   = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO scan_history
                (devices_found, new_devices, scan_duration, subnet)
            VALUES
                (%s,            %s,          %s,            %s)
        """, (devices_found, new_devices, scan_duration, subnet))

        conn.commit()
        return cursor.lastrowid   # ID of the newly inserted row

    except mysql.connector.Error as err:
        logger.error("❌ save_scan_result: %s", err)
        conn.rollback()
        return None

    finally:
        cursor.close()
        conn.close()


def get_scan_history(limit=50):
    """
    Fetch the most recent `limit` scan records, newest first.
    Returns a list of dicts:
    [
      {'id': 1, 'scan_time': datetime(...), 'devices_found': 5, ...},
      ...
    ]
    Called by app.py for the /api/chart/scan-history endpoint.
    """
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT
                id, scan_time, devices_found,
                new_devices, scan_duration, subnet
            FROM scan_history
            ORDER BY scan_time DESC
            LIMIT %s
        """, (limit,))
        return cursor.fetchall()

    except mysql.connector.Error as err:
        logger.error("❌ get_scan_history: %s", err)
        return []

    finally:
        cursor.close()
        conn.close()


def get_scan_history_for_chart(hours=24):
    """
    Fetch scan data for the past `hours` hours, ordered oldest→newest.
    The Chart.js line chart needs data in chronological order (left→right).
    Returns list of {'label': 'HH:MM', 'devices_found': N} dicts.
    """
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT
                DATE_FORMAT(scan_time, '%%H:%%i') AS label,
                -- Format datetime as "14:35" for X-axis labels
                -- Note: %% is an escaped % (Python format string + MySQL format string)

                devices_found,
                new_devices,
                scan_time
            FROM scan_history
            WHERE scan_time >= NOW() - INTERVAL %s HOUR
            -- Only rows within the requested time window

            ORDER BY scan_time ASC
            -- Ascending so chart reads left (oldest) to right (newest)
        """, (hours,))
        return cursor.fetchall()

    except mysql.connector.Error as err:
        logger.error("❌ get_scan_history_for_chart: %s", err)
        return []

    finally:
        cursor.close()
        conn.close()


# =============================================================================
# SECTION 5 — ALERT FUNCTIONS
# =============================================================================

def create_alert(alert_type, device_mac, device_ip,
                 device_name, message, severity="info"):
    """
    Insert one alert row.
    alert_type  — category string (e.g. 'new_device', 'blocked_attempt')
    severity    — 'info' | 'warning' | 'critical'
    Returns the new alert ID or None on failure.
    Called by scanner.py whenever a notable event is detected.
    """
    conn   = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO alerts
                (alert_type, device_mac, device_ip, device_name, message, severity)
            VALUES
                (%s,         %s,         %s,        %s,          %s,      %s)
        """, (alert_type, device_mac, device_ip, device_name, message, severity))

        conn.commit()
        logger.info("🚨 Alert created: [%s] %s", severity.upper(), message)
        return cursor.lastrowid

    except mysql.connector.Error as err:
        logger.error("❌ create_alert: %s", err)
        conn.rollback()
        return None

    finally:
        cursor.close()
        conn.close()


def get_alerts(limit=100, unread_only=False):
    """
    Fetch recent alerts, newest first.
    unread_only=True → only rows where is_read=0 (for the badge counter).
    Returns a list of dicts.
    """
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Build the WHERE clause conditionally
        where = "WHERE is_read = 0" if unread_only else ""

        cursor.execute(f"""
            SELECT
                id, alert_time, alert_type,
                device_mac, device_ip, device_name,
                message, severity, is_read
            FROM alerts
            {where}
            ORDER BY alert_time DESC
            LIMIT %s
        """, (limit,))
        return cursor.fetchall()

    except mysql.connector.Error as err:
        logger.error("❌ get_alerts: %s", err)
        return []

    finally:
        cursor.close()
        conn.close()


def mark_alert_read(alert_id):
    """
    Mark a single alert as read (is_read=1).
    Called when admin clicks "Dismiss" in alerts.html.
    """
    conn   = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "UPDATE alerts SET is_read = 1 WHERE id = %s",
            (alert_id,)
        )
        conn.commit()
        return cursor.rowcount > 0   # True if the alert ID existed

    except mysql.connector.Error as err:
        logger.error("❌ mark_alert_read(%s): %s", alert_id, err)
        conn.rollback()
        return False

    finally:
        cursor.close()
        conn.close()


def mark_all_alerts_read():
    """
    Mark every unread alert as read — called when admin clicks "Clear All".
    """
    conn   = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("UPDATE alerts SET is_read = 1 WHERE is_read = 0")
        conn.commit()
        return cursor.rowcount   # Number of rows updated

    except mysql.connector.Error as err:
        logger.error("❌ mark_all_alerts_read: %s", err)
        conn.rollback()
        return 0

    finally:
        cursor.close()
        conn.close()


def get_alerts_for_chart(days=7):
    """
    Count alerts per day for the past `days` days, grouped by alert_type.
    Returns data shaped for a Chart.js bar chart:
    [
      {'day': '2025-01-15', 'new_device': 3, 'blocked_attempt': 1, ...},
      ...
    ]
    """
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT
                DATE(alert_time) AS day,
                -- Extract just the date part (no time)

                SUM(alert_type = 'new_device')      AS new_device,
                SUM(alert_type = 'blocked_attempt') AS blocked_attempt,
                SUM(alert_type = 'device_offline')  AS device_offline,
                SUM(alert_type = 'high_risk')       AS high_risk,
                COUNT(*)                             AS total
            FROM alerts
            WHERE alert_time >= CURDATE() - INTERVAL %s DAY
            GROUP BY DATE(alert_time)   -- One row per calendar day
            ORDER BY day ASC
        """, (days,))
        return cursor.fetchall()

    except mysql.connector.Error as err:
        logger.error("❌ get_alerts_for_chart: %s", err)
        return []

    finally:
        cursor.close()
        conn.close()


def get_unread_alert_count():
    """
    Returns just the integer count of unread alerts.
    Fast — used on every page load to update the nav badge.
    """
    conn   = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE is_read = 0")
        result = cursor.fetchone()
        return result[0] if result else 0   # result is (count,) tuple

    except mysql.connector.Error as err:
        logger.error("❌ get_unread_alert_count: %s", err)
        return 0

    finally:
        cursor.close()
        conn.close()


# =============================================================================
# SECTION 6 — UTILITY / MAINTENANCE
# =============================================================================

def purge_old_scan_history(keep_days=30):
    """
    Delete scan_history rows older than `keep_days` days.
    Prevents the table from growing indefinitely.
    Good to call weekly via a scheduled task (Week 6 / cron).
    """
    conn   = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            DELETE FROM scan_history
            WHERE scan_time < NOW() - INTERVAL %s DAY
        """, (keep_days,))
        conn.commit()
        deleted = cursor.rowcount
        logger.info("🧹 Purged %d old scan_history rows (older than %d days)", deleted, keep_days)
        return deleted

    except mysql.connector.Error as err:
        logger.error("❌ purge_old_scan_history: %s", err)
        conn.rollback()
        return 0

    finally:
        cursor.close()
        conn.close()


def get_db_status():
    """
    Quick health check — returns a dict with connection status and row counts.
    Called by app.py's /api/status endpoint so the dashboard can show DB health.
    """
    try:
        conn   = get_connection()
        cursor = conn.cursor()

        # Run a trivial query to confirm connectivity
        cursor.execute("SELECT 1")
        cursor.fetchone()

        # Count rows in each table
        counts = {}
        for table in ("devices", "scan_history", "alerts"):
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            counts[table] = cursor.fetchone()[0]

        cursor.close()
        conn.close()

        return {
            "connected": True,
            "row_counts": counts
        }

    except Exception as err:   # Broad catch — any DB error means not connected
        return {
            "connected": False,
            "error":     str(err),
            "row_counts": {}
        }


# =============================================================================
# SETUP INSTRUCTIONS (run these in MySQL before starting the app)
# =============================================================================
# 1. Log into MySQL as root:
#       mysql -u root -p
#
# 2. Create the database:
#       CREATE DATABASE lansentry_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
#
# 3. Create a dedicated user (don't use root in production!):
#       CREATE USER 'lansentry_user'@'localhost' IDENTIFIED BY 'StrongPass123!';
#
# 4. Grant permissions on our database only:
#       GRANT ALL PRIVILEGES ON lansentry_db.* TO 'lansentry_user'@'localhost';
#       FLUSH PRIVILEGES;
#
# 5. The tables are created automatically when you run app.py (init_db()).
# =============================================================================