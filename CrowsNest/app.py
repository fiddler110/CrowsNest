import atexit
import hmac
import ipaddress
import json as _json
import os
import re
import subprocess
import hashlib
import secrets
import threading
import time
import zoneinfo
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from flask import Flask, g, render_template, request, session, redirect, url_for, jsonify, Response, stream_with_context
from dotenv import dotenv_values
import requests as http_client
from apscheduler.schedulers.background import BackgroundScheduler

BASE_DIR = Path(__file__).parent
ENV_FILE = Path(os.environ.get("ENV_FILE", str(BASE_DIR / ".env")))
WINDROSE_ENV_FILE = Path(os.environ.get("WINDROSE_ENV_FILE", str(BASE_DIR / ".env")))
CONTAINER_NAME = "windrose"
WINDROSE_COMPOSE_FILE = os.environ.get("WINDROSE_COMPOSE_FILE", "")
VALID_USERS = {"scott", "jeff"}
PBKDF2_ITERATIONS = 260_000

# Trusted proxy networks — requests arriving from these may carry X-Forwarded-For
# headers that the rate limiter will honour as the real client IP (e.g. Caddy on
# a Docker bridge network).
TRUSTED_PROXY_NETS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

# Sentinel for uninitialised caches — distinguishable from a cached None result.
_UNSET = object()

# ---------------------------------------------------------------------------
# Env-config cache  (avoids re-reading .env from disk on every function call)
# ---------------------------------------------------------------------------
_env_cache: dict | None = None
_env_cache_ts: float = 0.0
_env_cache_lock = threading.Lock()
_ENV_CACHE_TTL = 5.0

# ---------------------------------------------------------------------------
# Container-status cache  (2-second TTL)
# ---------------------------------------------------------------------------
_container_status_result: object = _UNSET
_container_status_ts: float = 0.0
_container_status_lock = threading.Lock()
_CONTAINER_STATUS_TTL = 2.0

# ---------------------------------------------------------------------------
# Windrose+ HTTP API — cookie state + /api/status result  (4-second TTL)
# All fields protected by _wplus_lock.
# ---------------------------------------------------------------------------
_wplus_lock = threading.Lock()
_wplus_http_cookie: str | None = None
_wplus_http_cookie_expires: float = 0.0
_wplus_status_result: object = _UNSET
_wplus_status_ts: float = 0.0
_WPLUS_STATUS_TTL = 4.0

# ---------------------------------------------------------------------------
# Container-started-at cache  (10-second TTL — docker inspect per call is wasteful)
# ---------------------------------------------------------------------------
_started_at_cache: object = _UNSET
_started_at_ts: float = 0.0
_started_at_lock = threading.Lock()
_STARTED_AT_TTL = 10.0

# ---------------------------------------------------------------------------
# Stats cache  (2-second TTL — docker stats takes ~1s per call)
# ---------------------------------------------------------------------------
_stats_result: object = _UNSET
_stats_result_ts: float = 0.0
_stats_lock = threading.Lock()
_STATS_TTL = 2.0


def get_env_config() -> dict:
    global _env_cache, _env_cache_ts
    with _env_cache_lock:
        now = time.time()
        if _env_cache is not None and now - _env_cache_ts < _ENV_CACHE_TTL:
            return _env_cache
        result = dotenv_values(ENV_FILE) if ENV_FILE.exists() else {}
        _env_cache = result
        _env_cache_ts = now
        return result


def set_env_value(key: str, value: str, target: Path | None = None) -> None:
    """Update an existing key's value in a .env file, or append it if missing."""
    global _env_cache
    env_path = target if target is not None else ENV_FILE
    if env_path.exists():
        lines = env_path.read_text().splitlines(keepends=True)
    else:
        lines = []

    key_prefix = f"{key}="
    new_line = f"{key}={value}\n"
    found = False
    new_lines = []
    for line in lines:
        if line.lstrip().startswith(key_prefix):
            new_lines.append(new_line)
            found = True
        else:
            new_lines.append(line)

    if not found:
        if new_lines and not new_lines[-1].endswith("\n"):
            new_lines[-1] += "\n"
        new_lines.append(new_line)

    env_path.write_text("".join(new_lines))
    # Invalidate the env-config cache whenever we write to the primary .env
    if env_path == ENV_FILE:
        with _env_cache_lock:
            _env_cache = None


def get_or_create_secret_key() -> str:
    config = get_env_config()
    secret = config.get("SESSION_SECRET")
    if secret:
        return secret

    secret = secrets.token_hex(32)
    mode = "a" if ENV_FILE.exists() else "w"
    with open(ENV_FILE, mode) as f:
        existing = ENV_FILE.read_text() if mode == "a" else ""
        if existing and not existing.endswith("\n"):
            f.write("\n")
        f.write(f"SESSION_SECRET={secret}\n")
    return secret


app = Flask(__name__)
app.secret_key = get_or_create_secret_key()

# Cookie security — INSECURE_COOKIE=true disables the Secure flag for plain-HTTP dev
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("INSECURE_COOKIE", "").lower() != "true"


@app.before_request
def set_csp_nonce():
    """Generate a unique CSP nonce per request, accessible in templates as g.csp_nonce."""
    g.csp_nonce = secrets.token_urlsafe(16)


@app.after_request
def set_security_headers(response):
    nonce = getattr(g, "csp_nonce", "")
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "geolocation=(), camera=(), microphone=(), usb=(), payment=()"
    )
    response.headers["Content-Security-Policy"] = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self' 'unsafe-inline'; "
        f"img-src 'self' data:; "
        f"connect-src 'self'; "
        f"frame-ancestors 'none'"
    )
    # Prevent caching of API responses
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


# ---------------------------------------------------------------------------
# Rate limiting (in-memory, per IP)
# ---------------------------------------------------------------------------

_login_attempts: dict[str, list[float]] = defaultdict(list)
_rate_limit_lock = threading.Lock()
_RATE_WINDOW = 60   # seconds
_RATE_MAX    = 10   # max POST attempts per window per IP


def _get_client_ip() -> str:
    """Return the real client IP.

    When the immediate peer is a trusted proxy (e.g. Caddy on a Docker bridge
    network), reads the leftmost IP from X-Forwarded-For instead of
    request.remote_addr so each real client gets its own rate-limit bucket.
    """
    remote = request.remote_addr or "0.0.0.0"
    try:
        remote_ip = ipaddress.ip_address(remote)
        is_trusted = any(remote_ip in net for net in TRUSTED_PROXY_NETS)
    except ValueError:
        is_trusted = False
    if is_trusted:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            candidate = xff.split(",")[0].strip()
            try:
                ipaddress.ip_address(candidate)  # validate before trusting
                return candidate
            except ValueError:
                pass
    return remote


def _check_rate_limit(ip: str) -> bool:
    """Record an attempt from *ip* and return True if the limit is exceeded."""
    now = time.time()
    with _rate_limit_lock:
        attempts = [t for t in _login_attempts[ip] if now - t < _RATE_WINDOW]
        attempts.append(now)
        _login_attempts[ip] = attempts
        # Prune stale IPs to bound memory growth
        if len(_login_attempts) > 500:
            stale = [k for k, v in list(_login_attempts.items())
                     if k != ip and not any(now - t < _RATE_WINDOW for t in v)]
            for k in stale:
                del _login_attempts[k]
        return len(attempts) > _RATE_MAX


def hash_password(plain_password: str) -> str:
    """Return a PBKDF2-SHA256 hash string with an embedded random salt."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", plain_password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(plain_password: str, stored: str) -> bool:
    """Verify *plain_password* against a stored PBKDF2 hash string."""
    try:
        scheme, iterations, salt_hex, digest_hex = stored.split("$")
    except ValueError:
        return False
    if scheme != "pbkdf2_sha256":
        return False
    try:
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac("sha256", plain_password.encode(), salt, int(iterations))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def get_stored_hash(username: str) -> str | None:
    config = get_env_config()
    return config.get(f"{username.upper()}_PASSWORD_HASH")


def get_container_status() -> str:
    """Return container status with a 2-second TTL cache."""
    global _container_status_result, _container_status_ts
    now = time.time()
    with _container_status_lock:
        if _container_status_result is not _UNSET and now - _container_status_ts < _CONTAINER_STATUS_TTL:
            return _container_status_result  # type: ignore[return-value]
        result = _get_container_status_uncached()
        _container_status_result = result
        _container_status_ts = now
        return result


def _get_container_status_uncached() -> str:
    try:
        result = subprocess.run(
            [
                "docker", "ps",
                "--filter", f"name=^{CONTAINER_NAME}$",
                "--format", "{{.Status}}",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return "offline"

        # Container is running — check whether the game server is actually ready.
        # Unreal Engine rotates R5.log to a timestamped backup at startup, so
        # R5.log only contains output from the current session.
        exec_result = subprocess.run(
            [
                "docker", "exec", CONTAINER_NAME,
                "grep", "-q", "Host server is ready for owner to connect",
                "/home/steam/server-files/R5/Saved/Logs/R5.log",
            ],
            capture_output=True,
            timeout=10,
        )
        if exec_result.returncode == 0:
            return "online"
        return "starting"
    except subprocess.TimeoutExpired:
        return "unknown"
    except Exception:
        return "unknown"


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Windrose+ integration helpers
# ---------------------------------------------------------------------------

# HTTP API session state — globals declared at module top, protected by _wplus_lock.


def _get_wplus_http_url() -> str:
    """Return the Windrose+ HTTP API base URL (no trailing slash)."""
    config = get_env_config()
    return config.get("WPLUS_HTTP_URL", "http://host.docker.internal:8780").rstrip("/")


def _wplus_http_login() -> bool:
    """POST to /login with the RCON password. Cache the session cookie on success."""
    global _wplus_http_cookie, _wplus_http_cookie_expires
    password = _get_wplus_rcon_password()
    if not password:
        return False
    url = _get_wplus_http_url()
    try:
        resp = http_client.post(
            f"{url}/login",
            data={"password": password},
            allow_redirects=False,
            timeout=5,
        )
        cookie = resp.cookies.get("wp_session")
        if cookie:
            _wplus_http_cookie = cookie
            _wplus_http_cookie_expires = time.time() + 82800  # 23h (Max-Age is 24h)
            return True
    except Exception:
        pass
    _wplus_http_cookie = None
    return False


def _wplus_api_status() -> dict | None:
    """GET /api/status from the Windrose+ HTTP API.

    Results are cached for _WPLUS_STATUS_TTL seconds. Cookie expiry and auth
    rejections trigger a single re-login attempt. All mutable state is
    protected by _wplus_lock. Returns the parsed JSON dict or None on error.
    """
    global _wplus_http_cookie, _wplus_http_cookie_expires, _wplus_status_result, _wplus_status_ts

    # Fast path: serve from cache without acquiring the lock (GIL makes the
    # individual reads atomic; the double-check under the lock handles any race).
    now = time.time()
    cached = _wplus_status_result
    if cached is not _UNSET and now - _wplus_status_ts < _WPLUS_STATUS_TTL:
        return cached  # type: ignore[return-value]

    with _wplus_lock:
        # Re-check under lock in case another thread just refreshed.
        now = time.time()
        if _wplus_status_result is not _UNSET and now - _wplus_status_ts < _WPLUS_STATUS_TTL:
            return _wplus_status_result  # type: ignore[return-value]

        if not _wplus_http_cookie or now >= _wplus_http_cookie_expires:
            if not _wplus_http_login():
                _wplus_status_result = None
                _wplus_status_ts = time.time()
                return None

        url = _get_wplus_http_url()
        try:
            resp = http_client.get(
                f"{url}/api/status",
                cookies={"wp_session": _wplus_http_cookie},
                timeout=5,
            )
            data = resp.json()
            if isinstance(data, dict) and data.get("error") == "Authentication required":
                # Cookie rejected — re-login once
                _wplus_http_cookie = None
                if not _wplus_http_login():
                    _wplus_status_result = None
                    _wplus_status_ts = time.time()
                    return None
                resp = http_client.get(
                    f"{url}/api/status",
                    cookies={"wp_session": _wplus_http_cookie},
                    timeout=5,
                )
                data = resp.json()
                if isinstance(data, dict) and "error" in data:
                    _wplus_status_result = None
                    _wplus_status_ts = time.time()
                    return None
            result = data if isinstance(data, dict) else None
            _wplus_status_result = result
            _wplus_status_ts = time.time()
            return result
        except Exception:
            _wplus_status_result = None
            _wplus_status_ts = time.time()
            return None


def _wplus_http_rcon(command: str, *, timeout: float = 6.0) -> str | None:
    """Send an RCON command via the Windrose+ HTTP API (POST /api/rcon).

    Uses the existing session cookie from _wplus_api_status; re-authenticates
    once if the cookie is rejected.  Returns the response message string on
    success, or None on failure.  Thread-safe — acquires _wplus_lock only for
    the brief cookie read/refresh, not during the HTTP call.
    """
    global _wplus_http_cookie, _wplus_http_cookie_expires

    # Ensure we have a valid cookie (fast path: no HTTP call needed inside lock)
    with _wplus_lock:
        if not _wplus_http_cookie or time.time() >= _wplus_http_cookie_expires:
            if not _wplus_http_login():
                return None
        cookie = _wplus_http_cookie

    url = _get_wplus_http_url()
    try:
        resp = http_client.post(
            f"{url}/api/rcon",
            json={"command": command},
            cookies={"wp_session": cookie},
            timeout=timeout,
        )
        data = resp.json()
        if isinstance(data, dict) and data.get("error") == "Authentication required":
            # Cookie expired mid-session — re-login once
            with _wplus_lock:
                _wplus_http_cookie = None
                if not _wplus_http_login():
                    return None
                cookie = _wplus_http_cookie
            resp = http_client.post(
                f"{url}/api/rcon",
                json={"command": command},
                cookies={"wp_session": cookie},
                timeout=timeout,
            )
            data = resp.json()
        if isinstance(data, dict) and data.get("status") == "ok":
            return data.get("message", "")
        return None
    except Exception:
        return None


def _get_wplus_rcon_password() -> str:
    """Read the RCON password from the .env file."""
    config = get_env_config()
    return config.get("WINDROSE_PLUS_RCON_PASSWORD", "").strip()


def _get_container_started_at() -> datetime | None:
    """Return the windrose container's start time as a UTC-aware datetime (10-second TTL cache)."""
    global _started_at_cache, _started_at_ts
    now = time.time()
    with _started_at_lock:
        if _started_at_cache is not _UNSET and now - _started_at_ts < _STARTED_AT_TTL:
            return _started_at_cache  # type: ignore[return-value]
        result = _get_container_started_at_uncached()
        _started_at_cache = result
        _started_at_ts = now
        return result


def _get_container_started_at_uncached() -> datetime | None:
    """Return the windrose container's start time as a UTC-aware datetime."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.StartedAt}}", CONTAINER_NAME],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return None
        ts = result.stdout.strip()
        # Truncate nanoseconds to microseconds: "2026-04-29T12:12:35.032837805Z" → "…+00:00"
        ts = re.sub(r'(\.\d{6})\d*Z$', r'\1+00:00', ts)
        ts = re.sub(r'Z$', '+00:00', ts)
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def get_container_uptime_str() -> str | None:
    """Return a human-readable uptime string derived from docker inspect StartedAt."""
    started_at = _get_container_started_at()
    if started_at is None:
        return None
    elapsed = int((datetime.now(timezone.utc) - started_at).total_seconds())
    days, rem = divmod(elapsed, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes or not parts:
        parts.append(f"{minutes}m")
    return " ".join(parts)


def _api_data_is_stale(api_data: dict | None) -> bool:
    """Return True when the API data timestamp predates the current container session.

    This happens when Windrose+ hasn't written fresh data yet after a restart
    (e.g. stuck in boot mode).  Player data from the old session should be ignored.
    """
    if api_data is None:
        return True
    status_ts = api_data.get("timestamp", 0)
    started_at = _get_container_started_at()
    if started_at is None:
        return False  # can't tell, assume fresh
    return status_ts < started_at.timestamp()


def get_player_info() -> dict:
    """Return current player count and names from the Windrose+ HTTP API.

    Uses the API's mode field to detect boot state (plugin not yet connected).
    In degraded mode the HTTP API can't query the game thread, so falls back
    to RCON wp.connections for the active connection count.
    Returns {"count": int, "names": [str, ...], "available": bool}.
    """
    api_data = _wplus_api_status()
    if api_data is None or _api_data_is_stale(api_data):
        return {"count": 0, "names": [], "available": False}

    mode = api_data.get("mode", "boot")
    if mode == "boot":
        return {"count": 0, "names": [], "available": False}

    players_raw = api_data.get("players") or []
    names = [p.get("name", "Player") for p in players_raw if isinstance(p, dict)]
    count = max(api_data.get("server", {}).get("player_count", len(names)), len(names))

    # In degraded mode the game thread is starved; the API reports player_count=0
    # even with active connections — use RCON wp.connections as a fallback.
    if count == 0 and mode == "degraded":
        msg = _wplus_http_rcon("wp.connections", timeout=5)
        if msg:
            m = re.search(r"Active:\s*(\d+)", msg)
            if m:
                count = int(m.group(1))

    return {"count": count, "names": names, "available": True}


def get_windrose_info() -> dict:
    """Collect rich server info from the Windrose+ HTTP API and RCON.

    Player count, names, and coordinates come from the HTTP API (/api/status).
    Dynamic data (time, weather, connections, memory) is fetched via HTTP RCON
    (/api/rcon) concurrently — only when Windrose+ is not in boot mode, to avoid
    blocking timeouts when the plugin hasn't connected yet.
    """
    out: dict = {
        "available": False,
        "mode": None,
        "version": None,
        "player_count": 0,
        "players": [],
        "uptime": None,
        "time_of_day": None,
        "day_duration": None,
        "night_duration": None,
        "wind_speed": None,
        "wave_height": None,
        "temperature": None,
        "connections_active": None,
        "connections_zombies": None,
        "connections_mode": None,
        "connections_last_player": None,
        "multipliers": {},
        "memory_working_set": None,
        "memory_virtual": None,
        "memory_page_file": None,
    }

    # Uptime from docker inspect — always reliable when the container is running
    docker_uptime = get_container_uptime_str()
    if docker_uptime:
        out["uptime"] = docker_uptime

    # Primary: Windrose+ HTTP API
    api_data = _wplus_api_status()
    if api_data is None:
        return out

    out["available"] = True
    srv = api_data.get("server") or {}
    out["version"] = srv.get("windrose_plus")
    mode = api_data.get("mode", "boot")
    out["mode"] = mode

    # Multipliers are valid regardless of mode or staleness
    mults_raw = api_data.get("multipliers") or {}
    mults = {}
    for key in ("loot", "xp", "stack_size", "craft_efficiency", "crop_speed", "weight"):
        if key in mults_raw:
            mults[key] = mults_raw[key]
    out["multipliers"] = mults

    # Player data only when the API data is from this container session
    if not _api_data_is_stale(api_data):
        players_raw = api_data.get("players") or []
        players = [
            {
                "name": p.get("name", "Player"),
                "x": str(round(p["x"])) if p.get("x") is not None else "?",
                "y": str(round(p["y"])) if p.get("y") is not None else "?",
                "z": str(round(p["z"])) if p.get("z") is not None else "?",
            }
            for p in players_raw if isinstance(p, dict)
        ]
        srv_count = srv.get("player_count", len(players))
        out["player_count"] = max(srv_count, len(players))
        out["players"] = players

    # Skip RCON entirely when Windrose+ is in boot mode — commands won't be processed
    if mode == "boot":
        return out

    # Fetch all dynamic data concurrently via HTTP RCON (replaces file-spool approach).
    # In degraded mode wp.time/wp.weather/wp.memory return UObject addresses rather
    # than real values, so their regex patterns won't match — fields stay None.
    rcon_commands = ("wp.time", "wp.weather", "wp.connections", "wp.memory")
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {cmd: pool.submit(_wplus_http_rcon, cmd, timeout=6) for cmd in rcon_commands}
        results = {cmd: fut.result() for cmd, fut in futures.items()}

    for cmd, msg in results.items():
        if msg is None:
            continue

        if cmd == "wp.time":
            m = re.search(r"TimeOfDay\s*=\s*([\d.]+)", msg)
            if m:
                out["time_of_day"] = float(m.group(1))
            m = re.search(r"DayCycleDuration\s*=\s*([\d.]+)", msg)
            if m:
                out["day_duration"] = int(float(m.group(1)))
            m = re.search(r"NightCycleDuration\s*=\s*([\d.]+)", msg)
            if m:
                out["night_duration"] = int(float(m.group(1)))

        elif cmd == "wp.weather":
            m = re.search(r"WindSpeed\s*=\s*([\d.]+)", msg)
            if m:
                out["wind_speed"] = float(m.group(1))
            m = re.search(r"WaveHeight\s*=\s*([\d.]+)", msg)
            if m:
                out["wave_height"] = float(m.group(1))
            m = re.search(r"TemperatureMultiplier\s*=\s*([\d.]+)", msg)
            if m:
                out["temperature"] = float(m.group(1))

        elif cmd == "wp.connections":
            m = re.search(r"Active:\s*(\d+)", msg)
            if m:
                out["connections_active"] = int(m.group(1))
            m = re.search(r"Zombie Controllers:\s*(\d+)", msg)
            if m:
                out["connections_zombies"] = int(m.group(1))
            m = re.search(r"Mode:\s*(\w+)", msg)
            if m:
                out["connections_mode"] = m.group(1)
            m = re.search(r"Last Player:\s*(.+)", msg)
            if m:
                out["connections_last_player"] = m.group(1).strip()

        elif cmd == "wp.memory":
            m = re.search(r"Working Set:\s*([\d,]+\s*\w+)", msg)
            if m:
                out["memory_working_set"] = m.group(1).strip()
            m = re.search(r"Virtual:\s*([\d,]+\s*\w+)", msg)
            if m:
                out["memory_virtual"] = m.group(1).strip()
            m = re.search(r"Page File:\s*([\d,]+\s*\w+)", msg)
            if m:
                out["memory_page_file"] = m.group(1).strip()

    # In degraded mode the HTTP API reports player_count=0 even with active connections;
    # reconcile with the RCON connection count.
    if out["player_count"] == 0 and out.get("connections_active"):
        out["player_count"] = out["connections_active"]

    return out


def send_discord_notification(message: str) -> bool:
    """POST a plain-text message to the configured Discord webhook."""
    config = get_env_config()
    webhook_url = config.get("DISCORD_WEBHOOK_URL", "").strip()
    if not webhook_url:
        return False
    if not webhook_url.startswith("https://discord.com/api/webhooks/"):
        app.logger.warning("DISCORD_WEBHOOK_URL does not look like a Discord webhook URL — skipping")
        return False
    try:
        resp = http_client.post(
            webhook_url,
            json={"content": message},
            timeout=10,
        )
        return resp.status_code in (200, 204)
    except Exception:
        return False


def _get_controller_tz() -> zoneinfo.ZoneInfo:
    """Return the ZoneInfo for the controller's configured timezone.

    Resolution order:
    1. TZ in CrowsNest/.env
    2. TZ OS environment variable (forwarded from root .env via compose.yaml)
    3. UTC (fallback)
    """
    config = get_env_config()
    tz_name = (
        config.get("TZ", "").strip()
        or os.environ.get("TZ", "").strip()
    )
    if tz_name:
        try:
            return zoneinfo.ZoneInfo(tz_name)
        except (zoneinfo.ZoneInfoNotFoundError, KeyError):
            app.logger.warning(
                "TZ %r is not a valid IANA timezone — falling back to UTC", tz_name
            )
    return zoneinfo.ZoneInfo("UTC")


def _parse_shutdown_window() -> tuple[int, int, int]:
    """Read NIGHT_SHUTDOWN_START, NIGHT_SHUTDOWN_END, NIGHT_SHUTDOWN_INTERVAL from .env.

    Returns (start_hour, end_hour, interval_minutes).
    start_hour : 0-23  — first hour checks begin (default 23)
    end_hour   : 0-23  — last hour that checks run (exclusive upper bound, default 5)
    interval   : minutes between checks (default 30, must be 1/2/3/4/5/6/10/12/15/20/30/60)
    """
    config = get_env_config()
    try:
        start = int(config.get("NIGHT_SHUTDOWN_START", "23"))
        start = max(0, min(23, start))
    except ValueError:
        start = 23
    try:
        end = int(config.get("NIGHT_SHUTDOWN_END", "5"))
        end = max(0, min(23, end))
    except ValueError:
        end = 5
    try:
        interval = int(config.get("NIGHT_SHUTDOWN_INTERVAL", "30"))
        # APScheduler cron minute= only supports evenly divisible-into-60 values
        valid = [1, 2, 3, 4, 5, 6, 10, 12, 15, 20, 30, 60]
        if interval not in valid:
            interval = min(valid, key=lambda v: abs(v - interval))
    except ValueError:
        interval = 30
    return start, end, interval


def _build_cron_hours(start: int, end: int) -> str:
    """Build a comma-separated hour string spanning start..end (wrapping midnight)."""
    if start <= end:
        hours = list(range(start, end))
    else:
        # wraps midnight e.g. 23 → 5  =>  23,0,1,2,3,4
        hours = list(range(start, 24)) + list(range(0, end))
    return ",".join(str(h) for h in hours) if hours else str(start)


def _schedule_night_shutdown() -> None:
    """(Re)schedule the night_shutdown job using current .env values."""
    start, end, interval = _parse_shutdown_window()
    tz = _get_controller_tz()
    hour_expr = _build_cron_hours(start, end)
    minute_expr = f"0/{interval}"
    app.logger.info(
        "Night shutdown scheduled: hour=%s minute=%s tz=%s (start=%s end=%s interval=%s min)",
        hour_expr, minute_expr, tz, start, end, interval,
    )
    _scheduler.add_job(
        night_shutdown_check,
        trigger="cron",
        hour=hour_expr,
        minute=minute_expr,
        timezone=tz,
        id="night_shutdown",
        replace_existing=True,
        misfire_grace_time=300,
    )


def night_shutdown_check() -> None:
    """Scheduled job: shut down the server if it is online and empty."""
    try:
        _night_shutdown_check_inner()
    except Exception as exc:
        app.logger.exception("Night shutdown job raised an unexpected error: %s", exc)


def _night_shutdown_check_inner() -> None:
    """Inner implementation — wrapped by night_shutdown_check for exception safety.

    The active window and interval are controlled by .env:
      NIGHT_SHUTDOWN_START    (default 23)
      NIGHT_SHUTDOWN_END      (default 5)
      NIGHT_SHUTDOWN_INTERVAL (default 30 minutes)
    Only executes when NIGHT_SHUTDOWN_ENABLED=true (the default).
    """
    config = get_env_config()
    if config.get("NIGHT_SHUTDOWN_ENABLED", "true").strip().lower() != "true":
        return

    # Guard: re-check the time window at runtime so .env changes take effect
    # without needing to reschedule (belt-and-suspenders).
    start, end, _ = _parse_shutdown_window()
    tz = _get_controller_tz()
    now_local = datetime.now(tz)
    now_hour = now_local.hour
    if start <= end:
        in_window = start <= now_hour < end
    else:
        in_window = now_hour >= start or now_hour < end
    if not in_window:
        return

    status = get_container_status()
    if status != "online":
        return  # Nothing to do if server is already offline or still starting

    player_info = get_player_info()

    if not player_info["available"]:
        app.logger.warning(
            "Night shutdown check: Windrose+ unreachable — skipping shutdown for safety"
        )
        return

    now_str = now_local.strftime("%H:%M")
    if player_info["count"] == 0:
        app.logger.info(
            "Night shutdown: no players online at %s — stopping server", now_str
        )
        send_discord_notification(
            f"\U0001f319 **Windrose Server** is shutting down for the night "
            f"(no players active at {now_str})."
        )
        try:
            subprocess.run(
                ["docker", "stop", CONTAINER_NAME],
                capture_output=True,
                timeout=60,
            )
        except Exception as exc:
            app.logger.error("Night shutdown: failed to stop container: %s", exc)
    else:
        names = ", ".join(player_info["names"]) if player_info["names"] else "unknown"
        app.logger.info(
            "Night shutdown check at %s: %d player(s) online (%s) — skipping shutdown",
            now_str,
            player_info["count"],
            names,
        )


# ---------------------------------------------------------------------------
# Background scheduler (night shutdown)
# Window and interval are read from .env at startup and whenever rescheduled.
# ---------------------------------------------------------------------------

_scheduler = BackgroundScheduler(daemon=True)
_scheduler.start()
_schedule_night_shutdown()
atexit.register(lambda: _scheduler.shutdown(wait=False))


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect(url_for("index"))

    error = None
    if request.method == "POST":
        if _check_rate_limit(_get_client_ip()):
            return render_template("login.html", error="Too many login attempts. Please wait a moment."), 429

        username = request.form.get("username", "").lower().strip()
        password = request.form.get("password", "")

        if username in VALID_USERS:
            stored_hash = get_stored_hash(username)
            if stored_hash and verify_password(password, stored_hash):
                session.clear()  # Prevent session fixation
                session["user"] = username
                session.permanent = False
                return redirect(url_for("index"))

        # Generic error to avoid user enumeration
        error = "Invalid username or password."

    return render_template("login.html", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    status = get_container_status()
    windrose_config = dotenv_values(WINDROSE_ENV_FILE) if WINDROSE_ENV_FILE.exists() else {}
    update_on_start = windrose_config.get("UPDATE_ON_START", "false").strip().lower() == "true"
    return render_template("index.html", status=status, user=session["user"],
                           update_on_start=update_on_start)


@app.route("/api/status")
@login_required
def api_status():
    return jsonify({"status": get_container_status()})


@app.route("/api/start", methods=["POST"])
@login_required
def api_start():
    try:
        # If the container already exists (stopped), just start it.
        # Only use docker compose up for a genuinely fresh deployment
        # where the container has never been created.
        probe = subprocess.run(
            ["docker", "ps", "-a", "--filter", f"name=^{CONTAINER_NAME}$", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=10,
        )
        container_exists = CONTAINER_NAME in probe.stdout

        if container_exists:
            cmd = ["docker", "start", CONTAINER_NAME]
        elif WINDROSE_COMPOSE_FILE:
            env_file = str(Path(WINDROSE_COMPOSE_FILE).parent / ".env")
            cmd = [
                "docker", "compose",
                "-f", WINDROSE_COMPOSE_FILE,
                "--env-file", env_file,
                "--profile", "windrose",
                "up", "-d", CONTAINER_NAME,
            ]
        else:
            cmd = ["docker", "start", CONTAINER_NAME]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        success = result.returncode == 0
        return jsonify(
            {
                "success": success,
                "message": "Container started." if success else "Failed to start container.",
                "output": result.stderr.strip() if not success else "",
            }
        )
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "message": "Command timed out."}), 500
    except Exception:
        return jsonify({"success": False, "message": "Internal error."}), 500


@app.route("/api/stop", methods=["POST"])
@login_required
def api_stop():
    try:
        result = subprocess.run(
            ["docker", "stop", CONTAINER_NAME],
            capture_output=True,
            text=True,
            timeout=60,
        )
        success = result.returncode == 0
        return jsonify(
            {
                "success": success,
                "message": "Container stopped." if success else "Failed to stop container.",
                "output": result.stderr.strip() if not success else "",
            }
        )
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "message": "Command timed out."}), 500
    except Exception:
        return jsonify({"success": False, "message": "Internal error."}), 500


@app.route("/api/logs")
@login_required
def api_logs():
    """Stream docker logs -f windrose as Server-Sent Events."""
    tail = request.args.get("tail", "200")
    # Validate tail is a safe integer or 'all'
    if tail != "all":
        try:
            tail = str(int(tail))
        except ValueError:
            tail = "200"

    def generate():
        proc = None
        try:
            proc = subprocess.Popen(
                ["docker", "logs", "-f", "--tail", tail, CONTAINER_NAME],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            for line in proc.stdout:
                # Escape SSE special characters
                safe = line.rstrip("\n").replace("\r", "")
                yield f"data: {safe}\n\n"
        except GeneratorExit:
            pass
        finally:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/api/update-on-start", methods=["GET"])
@login_required
def api_get_update_on_start():
    windrose_config = dotenv_values(WINDROSE_ENV_FILE) if WINDROSE_ENV_FILE.exists() else {}
    value = windrose_config.get("UPDATE_ON_START", "false").strip().lower()
    return jsonify({"value": value == "true"})


@app.route("/api/update-on-start", methods=["POST"])
@login_required
def api_toggle_update_on_start():
    windrose_config = dotenv_values(WINDROSE_ENV_FILE) if WINDROSE_ENV_FILE.exists() else {}
    current = windrose_config.get("UPDATE_ON_START", "false").strip().lower() == "true"
    new_value = "false" if current else "true"
    set_env_value("UPDATE_ON_START", new_value, target=WINDROSE_ENV_FILE)
    return jsonify({"value": new_value == "true"})


@app.route("/api/stats")
@login_required
def api_stats():
    global _stats_result, _stats_result_ts
    now = time.time()
    with _stats_lock:
        if _stats_result is not _UNSET and now - _stats_result_ts < _STATS_TTL:
            return jsonify(_stats_result)  # type: ignore[arg-type]
        result = _get_stats_uncached()
        _stats_result = result
        _stats_result_ts = now
        return jsonify(result)


def _get_stats_uncached() -> dict:
    stats: dict = {
        "cpu": None,
        "mem_used": None,
        "mem_total": None,
        "mem_pct": None,
        "gpu_util": None,
        "gpu_mem_used": None,
        "gpu_mem_total": None,
    }

    # Container CPU + memory via docker stats
    try:
        result = subprocess.run(
            [
                "docker", "stats", "--no-stream", "--format",
                "{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}",
                CONTAINER_NAME,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            parts = result.stdout.strip().split("\t")
            if len(parts) >= 1:
                stats["cpu"] = parts[0].replace("%", "").strip()
            if len(parts) >= 2:
                mem_parts = parts[1].split("/")
                if len(mem_parts) == 2:
                    stats["mem_used"] = mem_parts[0].strip()
                    stats["mem_total"] = mem_parts[1].strip()
            if len(parts) >= 3:
                stats["mem_pct"] = parts[2].replace("%", "").strip()
    except Exception:
        pass

    # GPU utilisation + memory via nvidia-smi (host-level)
    try:
        gpu_result = subprocess.run(
            [
                "nvidia-smi",
                "--query-gpu=utilization.gpu,memory.used,memory.total",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if gpu_result.returncode == 0 and gpu_result.stdout.strip():
            gpu_parts = [p.strip() for p in gpu_result.stdout.strip().split(",")]
            if len(gpu_parts) >= 1:
                stats["gpu_util"] = gpu_parts[0]
            if len(gpu_parts) >= 2:
                stats["gpu_mem_used"] = gpu_parts[1] + " MiB"
            if len(gpu_parts) >= 3:
                stats["gpu_mem_total"] = gpu_parts[2] + " MiB"
    except Exception:
        pass

    return stats


@app.route("/api/players")
@login_required
def api_players():
    """Return current player count and names from Windrose+."""
    info = get_player_info()
    return jsonify(info)


@app.route("/api/windrose-info")
@login_required
def api_windrose_info():
    """Return rich Windrose+ server data: players, world state, multipliers, memory."""
    return jsonify(get_windrose_info())


@app.route("/api/night-shutdown", methods=["GET"])
@login_required
def api_get_night_shutdown():
    config = get_env_config()
    enabled = config.get("NIGHT_SHUTDOWN_ENABLED", "true").strip().lower() == "true"
    windrose_plus_configured = bool(_get_wplus_rcon_password())
    start, end, interval = _parse_shutdown_window()
    next_run = None
    job = _scheduler.get_job("night_shutdown")
    if job and job.next_run_time:
        tz = _get_controller_tz()
        next_run = job.next_run_time.astimezone(tz).strftime("%Y-%m-%d %H:%M %Z")
    return jsonify({
        "enabled": enabled,
        "windrose_plus_configured": windrose_plus_configured,
        "next_run": next_run,
        "start_hour": start,
        "end_hour": end,
        "interval_minutes": interval,
    })


@app.route("/api/night-shutdown", methods=["POST"])
@login_required
def api_toggle_night_shutdown():
    config = get_env_config()
    current = config.get("NIGHT_SHUTDOWN_ENABLED", "true").strip().lower() == "true"
    new_value = "false" if current else "true"
    set_env_value("NIGHT_SHUTDOWN_ENABLED", new_value)
    return jsonify({"enabled": new_value == "true"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
