import http.server
import socketserver
import os
import sys
import json
import sqlite3
import hashlib
import time
import base64
import urllib.parse
import hmac
import struct
import traceback
import secrets
import re
import ipaddress
import math
from contextlib import closing

from webauthn import verify_registration_response, verify_authentication_response
from webauthn.helpers import base64url_to_bytes

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("PORT", 3000))
PERSIST_DIR = os.environ.get("PERSIST_DIR", BASE_DIR)
DIST_DIR = os.path.join(BASE_DIR, "dist")
DB_PATH = os.path.join(PERSIST_DIR, "hrt_server.db")
SESSION_MAX_AGE = 7 * 86400
SESSION_IDLE_TIMEOUT = 3 * 86400
CHALLENGE_MAX_AGE = 300


def normalize_origin(value):
    value = value.strip().rstrip('/')
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme not in ('http', 'https') or not parsed.hostname
            or parsed.username is not None or parsed.password is not None or parsed.path or parsed.query or parsed.fragment
            or any(c.isspace() for c in value) or '*' in value or '\\' in value
            or (parsed.scheme == 'http' and parsed.hostname not in ('localhost', '127.0.0.1', '::1'))):
        raise ValueError('WebAuthn origins must be HTTPS origins (HTTP is only allowed for localhost)')
    host = parsed.hostname.encode('idna').decode('ascii').lower()
    authority = f'[{host}]' if ':' in host else host
    port = parsed.port
    if port is not None and port != (443 if parsed.scheme == 'https' else 80):
        authority += f':{port}'
    return f'{parsed.scheme}://{authority}'


def load_webauthn_config():
    legacy_origin = os.environ.get('PUBLIC_APP_ORIGIN', '').strip()
    configured = os.environ.get('WEBAUTHN_ALLOWED_ORIGINS', '').strip()
    origins = tuple(dict.fromkeys(normalize_origin(value) for value in
                                 (configured or legacy_origin or f'http://localhost:{PORT}').split(',')))
    rp_id = os.environ.get('WEBAUTHN_RP_ID', '').strip().lower()
    rp_id = rp_id or urllib.parse.urlsplit(origins[0]).hostname
    rp_id = rp_id.encode('idna').decode('ascii')
    if (not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', rp_id)
            or len(rp_id) > 253 or ('.' not in rp_id and rp_id != 'localhost')):
        raise ValueError('WEBAUTHN_RP_ID must be a domain without a scheme, port or path')
    if not any(origin_supports_rp(origin, rp_id) for origin in origins):
        raise ValueError('WEBAUTHN_RP_ID must match an allowed origin host or its parent domain')
    return origins, rp_id


def origin_supports_rp(origin, rp_id):
    host = urllib.parse.urlsplit(origin).hostname
    return host == rp_id or host.endswith('.' + rp_id)


ALLOWED_ORIGINS, RP_ID = load_webauthn_config()
TRUSTED_PROXY_CIDRS = tuple(ipaddress.ip_network(value.strip()) for value in
                            os.environ.get('TRUSTED_PROXY_CIDRS', '').split(',') if value.strip())


class RateLimitExceeded(Exception):
    def __init__(self, retry_after):
        self.retry_after = retry_after
        super().__init__('Too many authentication attempts; try again later')


def check_auth_rate_limit(scope, identity, limit, now=None):
    """Consume a durable bucket slot before opening an action transaction."""
    now = time.time() if now is None else now
    key = hashlib.sha256((scope + '\0' + identity).encode('utf-8')).hexdigest()
    with closing(sqlite3.connect(DB_PATH, timeout=30)) as conn, conn:
        conn.execute('BEGIN IMMEDIATE')
        conn.execute('DELETE FROM auth_rate_limits WHERE window_start + 60 <= ?', (now,))
        row = conn.execute('SELECT window_start, count FROM auth_rate_limits WHERE key = ?', (key,)).fetchone()
        if row and row[1] >= limit:
            return max(1, math.ceil(row[0] + 60 - now))
        if row:
            conn.execute('UPDATE auth_rate_limits SET count = count + 1 WHERE key = ?', (key,))
        else:
            conn.execute('INSERT INTO auth_rate_limits (key, window_start, count) VALUES (?, ?, 1)', (key, now))
    return 0


def auth_client_ip(peer, forwarded_for=None):
    """Ignore forwarding headers unless the socket peer is an explicitly trusted proxy."""
    address = ipaddress.ip_address(peer)
    trusted = lambda ip: any(ip in network for network in TRUSTED_PROXY_CIDRS)
    if not trusted(address) or not forwarded_for:
        return str(address)
    try:
        chain = [ipaddress.ip_address(part.strip()) for part in forwarded_for.split(',')]
    except ValueError:
        return str(address)
    for hop in reversed(chain):
        if not trusted(address):
            break
        address = hop
    return str(address)


# --- 数据库初始化与自动结构热升级 ---
def init_db():
    os.makedirs(PERSIST_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE COLLATE NOCASE,
            password_hash TEXT,
            salt TEXT,
            totp_secret TEXT,
            backup_codes TEXT,
            avatar_data TEXT,
            created_at INTEGER
        )
    ''')
    
    # 自动升级已存在的旧版数据库表结构，杜绝 "no such column: totp_secret" 致命崩溃
    c.execute("PRAGMA table_info(users)")
    existing_cols = [row[1] for row in c.fetchall()]
    for col in ['totp_secret', 'backup_codes', 'avatar_data']:
        if col not in existing_cols:
            try:
                c.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT")
            except Exception:
                pass

    if 'totp_last_step' not in existing_cols:
        c.execute('ALTER TABLE users ADD COLUMN totp_last_step INTEGER')
    c.execute('''CREATE TABLE IF NOT EXISTS auth_rate_limits (
        key TEXT PRIMARY KEY, window_start REAL NOT NULL, count INTEGER NOT NULL
    )''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            sid TEXT,
            user_id TEXT,
            created_at INTEGER,
            last_used INTEGER
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS passkeys (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            credential_id TEXT UNIQUE,
            device_name TEXT,
            created_at INTEGER
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS backups (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            data TEXT,
            created_at INTEGER,
            data_size INTEGER
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS webauthn_challenges (
            token TEXT PRIMARY KEY,
            purpose TEXT NOT NULL,
            user_id TEXT,
            challenge TEXT NOT NULL,
            origin TEXT NOT NULL,
            rp_id TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        )
    ''')
    c.execute('PRAGMA table_info(webauthn_challenges)')
    if 'session_id' not in {row[1] for row in c.fetchall()}:
        c.execute('ALTER TABLE webauthn_challenges ADD COLUMN session_id TEXT')
    c.execute('PRAGMA table_info(passkeys)')
    passkey_cols = {row[1] for row in c.fetchall()}
    if 'public_key' not in passkey_cols:
        c.execute('ALTER TABLE passkeys ADD COLUMN public_key TEXT')
        c.execute('ALTER TABLE passkeys ADD COLUMN sign_count INTEGER NOT NULL DEFAULT 0')
    c.execute('PRAGMA table_info(sessions)')
    if 'auth_version' not in {row[1] for row in c.fetchall()}:
        c.execute('ALTER TABLE sessions ADD COLUMN auth_version INTEGER NOT NULL DEFAULT 0')
        # Sessions issued before verified passkey authentication cannot be trusted.
        c.execute('DELETE FROM sessions')
    c.execute('CREATE TABLE IF NOT EXISTS server_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
    if 'rp_id' not in passkey_cols:
        c.execute('ALTER TABLE passkeys ADD COLUMN rp_id TEXT')
        legacy_origin = os.environ.get('PUBLIC_APP_ORIGIN', '').strip()
        previous_rp = urllib.parse.urlsplit(normalize_origin(legacy_origin)).hostname if legacy_origin else None
        # Old public keys have no RP metadata; never relabel an unknown key as belonging to a new domain.
        if previous_rp:
            c.execute('UPDATE passkeys SET rp_id = ? WHERE public_key IS NOT NULL', (previous_rp,))
    c.execute('INSERT OR IGNORE INTO server_settings (key, value) VALUES (?, ?)',
              ('session_signing_key', secrets.token_hex(32)))
    global SESSION_SIGNING_KEY
    SESSION_SIGNING_KEY = bytes.fromhex(c.execute(
        'SELECT value FROM server_settings WHERE key = ?', ('session_signing_key',)).fetchone()[0])
    conn.commit()
    conn.close()

init_db()

# --- 密码与令牌计算 ---
def hash_password(password: str, salt: str) -> str:
    return hashlib.sha256((salt + password + "hrt_salt_2026").encode('utf-8')).hexdigest()

def b64url_encode(data_bytes: bytes) -> str:
    return base64.urlsafe_b64encode(data_bytes).decode('utf-8').rstrip('=')

def make_token(user_id: str, username: str, sid: str) -> str:
    header = b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode('utf-8'))
    claims = {
        "sub": user_id,
        "username": username,
        "sid": sid,
        "iat": int(time.time()),
        "exp": int(time.time()) + SESSION_MAX_AGE
    }
    payload = b64url_encode(json.dumps(claims).encode('utf-8'))
    sig = b64url_encode(hmac.new(SESSION_SIGNING_KEY, f'{header}.{payload}'.encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


def create_session(conn, user_id, username):
    sid = secrets.token_urlsafe(32)
    token = make_token(user_id, username, sid)
    now = int(time.time())
    conn.execute('''INSERT INTO sessions
        (token, sid, user_id, created_at, last_used, auth_version) VALUES (?, ?, ?, ?, ?, 1)''',
                 (token, sid, user_id, now, now))
    return token

def verify_token(token: str):
    if not token:
        return None
    try:
        header, payload, signature = token.split('.')
        expected = b64url_encode(hmac.new(SESSION_SIGNING_KEY, f'{header}.{payload}'.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            return None
        claims = json.loads(base64url_to_bytes(payload))
        now = int(time.time())
        with closing(sqlite3.connect(DB_PATH)) as conn, conn:
            row = conn.execute('''SELECT s.user_id, s.sid, s.created_at, s.last_used, u.username
                FROM sessions s JOIN users u ON u.id = s.user_id
                WHERE s.token = ? AND s.auth_version = 1''', (token,)).fetchone()
            if not row:
                return None
            if (claims.get('sub') != row[0] or claims.get('sid') != row[1]
                    or not isinstance(claims.get('exp'), (int, float)) or claims['exp'] <= now
                    or row[2] + SESSION_MAX_AGE <= now or row[3] + SESSION_IDLE_TIMEOUT <= now):
                conn.execute('DELETE FROM sessions WHERE token = ?', (token,))
                return None
            conn.execute('UPDATE sessions SET last_used = ? WHERE token = ?', (now, token))
            return {"user_id": row[0], "username": row[4], "sid": row[1]}
    except (ValueError, TypeError, UnicodeError):
        return None


def create_challenge(conn, purpose, origin, user_id=None, session_id=None):
    token = secrets.token_urlsafe(32)
    challenge = b64url_encode(os.urandom(32))
    now = int(time.time())
    conn.execute('DELETE FROM webauthn_challenges WHERE expires_at <= ?', (now,))
    conn.execute('''INSERT INTO webauthn_challenges
        (token, purpose, user_id, challenge, origin, rp_id, expires_at, session_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                 (token, purpose, user_id, challenge, origin, RP_ID, now + CHALLENGE_MAX_AGE, session_id))
    return token, challenge


def consume_challenge(conn, token, purpose, origin, user_id=None, session_id=None):
    row = conn.execute('''SELECT user_id, challenge, origin, rp_id, session_id FROM webauthn_challenges
        WHERE token = ? AND purpose = ? AND expires_at > ? AND origin = ? AND rp_id = ?''',
                       (token, purpose, int(time.time()), origin, RP_ID)).fetchone()
    if (not row or (user_id is not None and row[0] != user_id)
            or (session_id is not None and row[4] != session_id)):
        raise ValueError('Invalid or expired challenge')
    conn.execute('DELETE FROM webauthn_challenges WHERE token = ?', (token,))
    return row[:4]

def verify_passkey(conn, proof, purpose, origin, user_id=None, session_id=None):
    bound_user, challenge, origin, rp_id = consume_challenge(
        conn, proof.get('challengeToken'), purpose, origin, user_id, session_id)
    credential = proof.get('credential') or {}
    row = conn.execute('''SELECT p.user_id, p.id, p.public_key, p.sign_count, u.username
        FROM passkeys p JOIN users u ON u.id = p.user_id
        WHERE p.credential_id = ? AND p.public_key IS NOT NULL AND p.rp_id = ?''',
                       (credential.get('id'), rp_id)).fetchone()
    if not row or (bound_user is not None and row[0] != bound_user):
        raise ValueError('Credential does not belong to this account')
    verified = verify_authentication_response(
        credential=credential, expected_challenge=base64url_to_bytes(challenge),
        expected_origin=origin, expected_rp_id=rp_id,
        credential_public_key=base64url_to_bytes(row[2]),
        credential_current_sign_count=row[3], require_user_verification=purpose == 'authenticate')
    conn.execute('UPDATE passkeys SET sign_count = ? WHERE id = ?', (verified.new_sign_count, row[1]))
    return row[0], row[4]


# --- 双重认证 (TOTP RFC 6238) ---
def generate_totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode('ascii').rstrip('=')

def match_totp_step(secret: str, code: str, now=None):
    """Return the matching step, or None; codes must be exactly six ASCII digits."""
    if not secret or not isinstance(code, str) or not re.fullmatch(r'[0-9]{6}', code):
        return None
    try:
        secret_clean = secret.replace(' ', '').upper()
        pad = (8 - len(secret_clean) % 8) % 8
        key = base64.b32decode((secret_clean + '=' * pad).encode('ascii'))
        current_step = int((time.time() if now is None else now) // 30)
        matched = None
        for step in [current_step - 1, current_step, current_step + 1]:
            if step < 0:
                continue
            msg = struct.pack('>Q', step)
            h = hmac.new(key, msg, hashlib.sha1).digest()
            o = h[19] & 15
            token = (struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff) % 1000000
            if hmac.compare_digest(f'{token:06d}', code):
                matched = step
        return matched
    except (ValueError, TypeError, UnicodeError):
        return None


def totp_key_identity(secret):
    clean = secret.replace(' ', '').upper().rstrip('=')
    key = base64.b32decode(clean + '=' * (-len(clean) % 8))
    return (hashlib.sha1(key).digest() if len(key) > 64 else key).ljust(64, b'\0')


def consume_totp(conn, user, secret, code):
    """Atomically consume a step inside the caller's BEGIN IMMEDIATE transaction."""
    step = match_totp_step(secret, code)
    if step is None:
        return False
    return conn.execute('''UPDATE users SET totp_last_step = ?
        WHERE id = ? AND totp_secret = ?
        AND (totp_last_step IS NULL OR totp_last_step < ?)''',
                        (step, user, secret, step)).rowcount == 1


def generate_backup_codes() -> list:
    return [hashlib.md5(os.urandom(16)).hexdigest()[:8].upper() for _ in range(8)]

# --- 多线程 HTTP 请求处理器 ---
class HRTServerHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIST_DIR, **kwargs)

    def send_cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')

    def send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_cors()
        self.send_header('Cache-Control', 'no-store')
        if status == 429:
            self.send_header('Retry-After', str(self._retry_after))
            self.send_header('Access-Control-Expose-Headers', 'Retry-After')
            self.close_connection = True
        if status == 401 and data.get('code') == 'UNAUTHORIZED':
            self.send_header('X-Session-Invalid', '1')
            self.send_header('Access-Control-Expose-Headers', 'X-Session-Invalid')
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, status: int, code: str, message: str, extra: dict = None):
        payload = {"code": code, "message": message}
        if extra:
            payload.update(extra)
        self.send_json(payload, status)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_cors()
        self.end_headers()

    def auth_rate_limit(self, scope, identity, limit):
        retry = check_auth_rate_limit(scope, identity, limit)
        if retry:
            raise RateLimitExceeded(retry)

    def limit_auth_ip(self):
        forwarded = ','.join(self.headers.get_all('X-Forwarded-For', []))
        self.auth_rate_limit('ip', auth_client_ip(self.client_address[0], forwarded), 60)

    def get_token_user(self):
        auth_header = self.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:].strip()
            user = verify_token(token)
            path = urllib.parse.urlparse(self.path).path
            protected_checks = {
                '/api/user/password', '/api/user/2fa/enable', '/api/user/2fa',
                '/api/user/2fa/backup-codes/generate', '/api/user/passkey/register',
                '/api/user/passkey/auth-options', '/api/user/passkey/register-options',
                '/api/user/2fa/setup',
            }
            if user and ((self.command == 'POST' and path in protected_checks)
                         or (self.command == 'DELETE' and
                             (path in ('/api/user/me', '/api/user/2fa') or path.startswith('/api/user/passkeys/')))):
                # Charge once, after token verification and before any action transaction.
                self.limit_auth_ip()
                self.auth_rate_limit('user', user['user_id'], 10)
            return user
        return None

    def read_json_body(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
            if length > 0:
                raw = self.rfile.read(length).decode('utf-8')
                return json.loads(raw)
        except Exception:
            pass
        return {}

    def check_webauthn_origin(self):
        try:
            origin = normalize_origin(self.headers.get('Origin', ''))
        except ValueError:
            origin = None
        if origin not in ALLOWED_ORIGINS:
            self.send_error_json(400, 'INVALID_REQUEST',
                                 'Untrusted origin: configure WEBAUTHN_ALLOWED_ORIGINS with the browser origin')
            return None
        if not origin_supports_rp(origin, RP_ID):
            self.send_error_json(400, 'INVALID_REQUEST',
                                 'This origin cannot use WEBAUTHN_RP_ID; sign in with your password and register a passkey on the new domain')
            return None
        return origin

    def current_rp_available(self):
        origin = self.headers.get('Origin')
        if origin is None:
            referer = self.headers.get('Referer')
            if not referer:
                return True
            parsed = urllib.parse.urlsplit(referer)
            origin = f'{parsed.scheme}://{parsed.netloc}'
        try:
            origin = normalize_origin(origin)
        except ValueError:
            return False
        return origin in ALLOWED_ORIGINS and origin_supports_rp(origin, RP_ID)

    def require_password(self, conn, user_id, data, require_totp=False, code_field='code'):
        row = conn.execute('SELECT password_hash, salt, totp_secret FROM users WHERE id = ?', (user_id,)).fetchone()
        password = data.get('password')
        if (not row or not isinstance(password, str) or not password
                or not hmac.compare_digest(hash_password(password, row[1]), row[0])):
            self.send_error_json(401, 'INVALID_CREDENTIALS', 'Current password is required and must be correct')
            return False
        if require_totp and row[2] and not consume_totp(conn, user_id, row[2], data.get(code_field) or ''):
            self.send_error_json(401, 'TWO_FACTOR_INVALID', 'Current authenticator code is required')
            return False
        return True

    def disable_totp(self):
        auth_user = self.get_token_user()
        if not auth_user:
            return self.send_error_json(401, 'UNAUTHORIZED', '未登录')
        data = self.read_json_body()
        with closing(sqlite3.connect(DB_PATH)) as conn, conn:
            conn.execute('BEGIN IMMEDIATE')
            if not self.require_password(conn, auth_user['user_id'], data, require_totp=True):
                return
            conn.execute('UPDATE users SET totp_secret = NULL, backup_codes = NULL, totp_last_step = NULL WHERE id = ?', (auth_user['user_id'],))
        return self.send_json({'success': True})

    def factor_methods(self, conn, user_id):
        methods = []
        row = conn.execute('SELECT totp_secret FROM users WHERE id = ?', (user_id,)).fetchone()
        if row and row[0]:
            methods.append('totp')
        if conn.execute('SELECT 1 FROM passkeys WHERE user_id = ? AND public_key IS NOT NULL AND rp_id = ?',
                        (user_id, RP_ID)).fetchone():
            methods.append('passkey')
        return methods

    def verify_second_factor(self, conn, user_id, data, purpose, session_id=None):
        methods = self.factor_methods(conn, user_id)
        if not methods:
            return True
        code = data.get('totp_code') or data.get('code')
        backup = data.get('backup_code')
        proof = data.get('passkey')
        if proof:
            origin = self.check_webauthn_origin()
            if not origin:
                return False
            try:
                if 'passkey' not in methods or not isinstance(proof, dict):
                    raise ValueError('Passkey is not available')
                verify_passkey(conn, proof, purpose, origin, user_id, session_id)
                return True
            except Exception:
                self.send_error_json(401, 'TWO_FACTOR_INVALID', 'Passkey verification failed')
                return False
        if backup:
            row = conn.execute('SELECT backup_codes FROM users WHERE id = ?', (user_id,)).fetchone()
            codes = json.loads(row[0] or '[]')
            clean = str(backup).strip().upper()
            if clean in codes:
                codes.remove(clean)
                conn.execute('UPDATE users SET backup_codes = ? WHERE id = ?', (json.dumps(codes), user_id))
                return True
        elif code and 'totp' in methods:
            secret = conn.execute('SELECT totp_secret FROM users WHERE id = ?', (user_id,)).fetchone()[0]
            if consume_totp(conn, user_id, secret, code):
                return True
        if not code and not backup:
            self.send_error_json(401, 'TWO_FACTOR_REQUIRED', 'A second factor is required',
                                 {'needs2FA': True, 'method': methods[0], 'methods': methods})
        else:
            self.send_error_json(401, 'TWO_FACTOR_INVALID', 'Invalid second factor')
        return False

    def passkey_auth_options(self, username, password=None, purpose='authenticate', auth_user=None):
        username = username.strip().lower()
        if purpose == 'login':
            self.auth_rate_limit('account', username, 10)
        origin = self.check_webauthn_origin()
        if not origin:
            return
        with closing(sqlite3.connect(DB_PATH)) as conn, conn:
            conn.execute('BEGIN IMMEDIATE')
            user_id = auth_user['user_id'] if auth_user else None
            session_id = auth_user['sid'] if auth_user else None
            credential_ids = []
            if purpose != 'authenticate':
                if purpose == 'login':
                    row = conn.execute('SELECT id FROM users WHERE username = ? COLLATE NOCASE', (username,)).fetchone()
                    user_id = row[0] if row else None
                if not user_id or not self.require_password(conn, user_id, {'password': password}):
                    if not user_id:
                        self.send_error_json(401, 'INVALID_CREDENTIALS', 'Invalid credentials')
                    return
            elif username:
                row = conn.execute('SELECT id FROM users WHERE username = ? COLLATE NOCASE', (username,)).fetchone()
                user_id = row[0] if row else secrets.token_urlsafe(32)
            if user_id:
                credential_ids = [r[0] for r in conn.execute(
                    'SELECT credential_id FROM passkeys WHERE user_id = ? AND public_key IS NOT NULL AND rp_id = ?', (user_id, RP_ID))]
            token, challenge = create_challenge(conn, purpose, origin, user_id, session_id)
        return self.send_json({'challengeToken': token, 'challenge': challenge,
                               'credentialIds': credential_ids, 'rpId': RP_ID,
                               'timeout': 60000, 'userVerification': 'required' if purpose == 'authenticate' else 'preferred'})

    def do_POST(self):
        try:
            url = urllib.parse.urlparse(self.path)
            path = url.path

            if path in ('/api/login', '/api/register', '/api/auth/passkey-options', '/api/auth/passkey-verify'):
                self.limit_auth_ip()

            # 2FA 密钥申请: POST /api/user/2fa/setup
            if path == '/api/user/2fa/setup':
                auth_user = self.get_token_user()
                if not auth_user:
                    return self.send_error_json(401, 'UNAUTHORIZED', '未登录')
                secret = generate_totp_secret()
                issuer = 'HRT Tracker'
                uri = f'otpauth://totp/{urllib.parse.quote(issuer)}:{urllib.parse.quote(auth_user["username"])}?secret={secret}&issuer={urllib.parse.quote(issuer)}&algorithm=SHA1&digits=6&period=30'
                return self.send_json({'secret': secret, 'uri': uri})

            # 通行密钥注册选项: POST /api/user/passkey/register-options
            if path == '/api/user/passkey/register-options':
                auth_user = self.get_token_user()
                if not auth_user:
                    return self.send_error_json(401, 'UNAUTHORIZED', '未登录')
                origin = self.check_webauthn_origin()
                if not origin:
                    return
                user_id_encoded = b64url_encode(auth_user['user_id'].encode('utf-8'))
                with closing(sqlite3.connect(DB_PATH)) as conn, conn:
                    enrolled = [r[0] for r in conn.execute(
                        'SELECT credential_id FROM passkeys WHERE user_id = ? AND public_key IS NOT NULL AND rp_id = ?',
                        (auth_user['user_id'], RP_ID))]
                    challenge_token, challenge = create_challenge(conn, 'register', origin, auth_user['user_id'])
                return self.send_json({
                    'challengeToken': challenge_token,
                    'challenge': challenge,
                    'rp': {'id': RP_ID, 'name': 'HRT Tracker'},
                    'user': {'id': user_id_encoded, 'name': auth_user['username'], 'displayName': auth_user['username']},
                    'pubKeyCredParams': [{'type': 'public-key', 'alg': -7}, {'type': 'public-key', 'alg': -257}],
                    'timeout': 60000,
                    'authenticatorSelection': {'residentKey': 'preferred', 'userVerification': 'preferred'},
                    'attestation': 'none',
                    'excludeCredentialIds': enrolled
                })

            # 通行密钥注册确认: POST /api/user/passkey/register
            if path == '/api/user/passkey/register':
                auth_user = self.get_token_user()
                if not auth_user:
                    return self.send_error_json(401, 'UNAUTHORIZED', '未登录')
                origin = self.check_webauthn_origin()
                if not origin:
                    return
                data = self.read_json_body()
                with closing(sqlite3.connect(DB_PATH)) as conn, conn:
                    conn.execute('BEGIN IMMEDIATE')
                    if not self.require_password(conn, auth_user['user_id'], data, require_totp=True):
                        return
                    try:
                        _, challenge, origin, rp_id = consume_challenge(
                            conn, data.get('challengeToken'), 'register', origin, auth_user['user_id'])
                        verified = verify_registration_response(
                            credential=data.get('credential') or {},
                            expected_challenge=base64url_to_bytes(challenge),
                            expected_rp_id=rp_id, expected_origin=origin)
                    except Exception:
                        conn.commit()
                        return self.send_error_json(400, 'INVALID_REQUEST', 'Invalid passkey registration')
                    pk_id = secrets.token_urlsafe(24)
                    try:
                        conn.execute('''INSERT INTO passkeys
                            (id, user_id, credential_id, device_name, created_at, public_key, sign_count, rp_id)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                                     (pk_id, auth_user['user_id'], b64url_encode(verified.credential_id),
                                      data.get('deviceName') or '通行密钥硬件', int(time.time()),
                                      b64url_encode(verified.credential_public_key), verified.sign_count, rp_id))
                    except sqlite3.IntegrityError:
                        conn.commit()
                        return self.send_error_json(409, 'CONFLICT', 'Credential already registered')
                    backup_row = conn.execute('SELECT backup_codes FROM users WHERE id = ?', (auth_user['user_id'],)).fetchone()
                    backup_codes = []
                    if not json.loads(backup_row[0] or '[]'):
                        backup_codes = generate_backup_codes()
                        conn.execute('UPDATE users SET backup_codes = ? WHERE id = ?',
                                     (json.dumps(backup_codes), auth_user['user_id']))
                return self.send_json({'message': 'Passkey registered', 'id': pk_id, 'backupCodes': backup_codes}, 201)

            # 通行密钥免密登录选项: POST /api/auth/passkey-options
            if path == '/api/auth/passkey-options':
                data = self.read_json_body()
                purpose = data.get('purpose', 'authenticate')
                if purpose not in ('authenticate', 'login'):
                    return self.send_error_json(400, 'INVALID_REQUEST', 'Invalid authentication purpose')
                return self.passkey_auth_options((data.get('username') or '').strip(), data.get('password'), purpose)

            if path == '/api/user/passkey/auth-options':
                auth_user = self.get_token_user()
                if not auth_user:
                    return self.send_error_json(401, 'UNAUTHORIZED', '未登录')
                data = self.read_json_body()
                purpose = data.get('purpose')
                if purpose not in ('password', 'delete'):
                    return self.send_error_json(400, 'INVALID_REQUEST', 'Invalid authentication purpose')
                return self.passkey_auth_options('', data.get('password'), purpose, auth_user)

            # 通行密钥免密登录验证: POST /api/auth/passkey-verify
            if path == '/api/auth/passkey-verify':
                origin = self.check_webauthn_origin()
                if not origin:
                    return
                data = self.read_json_body()
                with closing(sqlite3.connect(DB_PATH)) as conn, conn:
                    conn.execute('BEGIN IMMEDIATE')
                    try:
                        user_id, username = verify_passkey(conn, data, 'authenticate', origin)
                    except Exception:
                        conn.commit()
                        return self.send_error_json(401, 'INVALID_CREDENTIALS', 'Passkey verification failed: user verification is required')
                    token = create_session(conn, user_id, username)
                return self.send_json({'token': token, 'user': {'id': user_id, 'username': username}})

            # 1. 注册: POST /api/register
            if path == '/api/register':
                data = self.read_json_body()
                username = (data.get('username') or '').strip()
                password = data.get('password') or ''
                if not username or not password:
                    return self.send_error_json(400, 'INVALID_INPUT', '请输入用户名和密码')

                salt = hashlib.md5(f"{time.time()}_{username}".encode()).hexdigest()[:8]
                pw_hash = hash_password(password, salt)
                user_id = f"u_{hashlib.sha256(username.lower().encode()).hexdigest()[:20]}"

                try:
                    conn = sqlite3.connect(DB_PATH)
                    c = conn.cursor()
                    c.execute(
                        'INSERT INTO users (id, username, password_hash, salt, created_at) VALUES (?, ?, ?, ?, ?)',
                        (user_id, username, pw_hash, salt, int(time.time()))
                    )
                    token = create_session(conn, user_id, username)
                    conn.commit()
                    conn.close()
                    return self.send_json({"token": token, "user": {"id": user_id, "username": username}})
                except sqlite3.IntegrityError:
                    return self.send_error_json(409, 'USER_EXISTS', '该用户名已存在')

            # 2. 登录: POST /api/login
            if path == '/api/login':
                data = self.read_json_body()
                username = (data.get('username') or '').strip().lower()
                self.auth_rate_limit('account', username, 10)
                password = data.get('password') or ''
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                # Serialize credential validation with password changes and factor replacement.
                c.execute('BEGIN IMMEDIATE')
                c.execute('SELECT id, password_hash, salt, username FROM users WHERE username = ? COLLATE NOCASE', (username,))
                row = c.fetchone()
                if not row:
                    conn.close()
                    return self.send_error_json(401, 'INVALID_CREDENTIALS', '用户名或密码错误')

                user_id, pw_hash, salt, real_username = row
                if hash_password(password, salt) != pw_hash:
                    conn.close()
                    return self.send_error_json(401, 'INVALID_CREDENTIALS', '用户名或密码错误')

                if not self.verify_second_factor(conn, user_id, data, 'login'):
                    conn.commit()
                    conn.close()
                    return

                token = create_session(conn, user_id, real_username)
                conn.commit()
                conn.close()
                return self.send_json({"token": token, "user": {"id": user_id, "username": real_username}})

            # 3. 密码修改: POST /api/user/password
            if path == '/api/user/password':
                auth_user = self.get_token_user()
                if not auth_user:
                    return self.send_error_json(401, 'UNAUTHORIZED', '登录已过期')
                data = self.read_json_body()
                
                # 关键修复：同时兼容前端传来的 currentPassword 与 oldPassword
                old_pw = data.get('currentPassword') or data.get('oldPassword') or data.get('password') or ''
                new_pw = data.get('newPassword') or data.get('newPass') or ''

                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute('BEGIN IMMEDIATE')
                c.execute('SELECT password_hash, salt FROM users WHERE id = ?', (auth_user['user_id'],))
                row = c.fetchone()
                if not row or hash_password(old_pw, row[1]) != row[0]:
                    conn.close()
                    return self.send_error_json(401, 'WRONG_PASSWORD', '当前密码不正确')

                if not isinstance(new_pw, str) or not 8 <= len(new_pw) <= 128:
                    conn.close()
                    return self.send_error_json(400, 'INVALID_REQUEST', 'Password must be 8-128 characters')
                if not self.verify_second_factor(conn, auth_user['user_id'], data, 'password', auth_user['sid']):
                    conn.commit()
                    conn.close()
                    return
                new_salt = secrets.token_hex(16)
                c.execute(
                    'UPDATE users SET password_hash = ?, salt = ? WHERE id = ?',
                    (hash_password(new_pw, new_salt), new_salt, auth_user['user_id'])
                )
                c.execute('DELETE FROM sessions WHERE user_id = ? AND sid != ?', (auth_user['user_id'], auth_user['sid']))
                c.execute('DELETE FROM webauthn_challenges WHERE user_id = ?', (auth_user['user_id'],))
                conn.commit()
                conn.close()
                return self.send_json({"success": True})

            # 4. 开启 2FA: POST /api/user/2fa/enable
            if path == '/api/user/2fa/enable':
                auth_user = self.get_token_user()
                if not auth_user:
                    return self.send_error_json(401, 'UNAUTHORIZED', '未登录')
                data = self.read_json_body()
                secret = data.get('secret') or ''
                code = data.get('code') or ''

                # Validate the replacement before consuming the old authenticator code.
                if not isinstance(secret, str) or not re.fullmatch(r'[A-Z2-7]{16,64}', secret, re.IGNORECASE):
                    return self.send_error_json(400, 'INVALID_CODE', '验证码不匹配，请核对手机时间与输入')
                secret = secret.upper()
                step = match_totp_step(secret, code)
                if step is None:
                    return self.send_error_json(400, 'INVALID_CODE', '验证码不匹配，请核对手机时间与输入')
                with closing(sqlite3.connect(DB_PATH)) as conn, conn:
                    conn.execute('BEGIN IMMEDIATE')
                    if not self.require_password(conn, auth_user['user_id'], data, require_totp=True, code_field='currentCode'):
                        return
                    old = conn.execute('SELECT totp_secret, totp_last_step FROM users WHERE id = ?',
                                       (auth_user['user_id'],)).fetchone()
                    # Re-saving the same secret must never lower its replay high-water mark.
                    if old[0] and hmac.compare_digest(totp_key_identity(old[0]), totp_key_identity(secret)) and old[1] is not None:
                        step = max(step, old[1])
                    codes = generate_backup_codes()
                    conn.execute('UPDATE users SET totp_secret = ?, backup_codes = ?, totp_last_step = ? WHERE id = ?',
                                 (secret, json.dumps(codes), step, auth_user['user_id']))
                return self.send_json({"backupCodes": codes})

            # 5. 关闭 2FA: POST /api/user/2fa
            if path == '/api/user/2fa':
                return self.disable_totp()

            # 6. 生成新备用码: POST /api/user/2fa/backup-codes/generate
            if path == '/api/user/2fa/backup-codes/generate':
                auth_user = self.get_token_user()
                if not auth_user:
                    return self.send_error_json(401, 'UNAUTHORIZED', '未登录')
                data = self.read_json_body()
                with closing(sqlite3.connect(DB_PATH)) as conn, conn:
                    conn.execute('BEGIN IMMEDIATE')
                    if not self.require_password(conn, auth_user['user_id'], data, require_totp=True):
                        return
                    codes = generate_backup_codes()
                    conn.execute('UPDATE users SET backup_codes = ? WHERE id = ?', (json.dumps(codes), auth_user['user_id']))
                return self.send_json({"codes": codes, "backupCodes": codes})

            # 7. 上传云端备份: POST /api/content
            if path == '/api/content':
                auth_user = self.get_token_user()
                if not auth_user:
                    return self.send_error_json(401, 'UNAUTHORIZED', '请先登录后再进行备份')
                data = self.read_json_body()
                content_data = data.get('data')
                if isinstance(content_data, dict):
                    content_str = json.dumps(content_data)
                else:
                    content_str = str(content_data or '')

                bk_id = f"bk_{int(time.time()*1000)}"
                now_ts = int(time.time())
                data_size = len(content_str.encode('utf-8'))

                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute(
                    'INSERT INTO backups (id, user_id, data, created_at, data_size) VALUES (?, ?, ?, ?, ?)',
                    (bk_id, auth_user['user_id'], content_str, now_ts, data_size)
                )
                conn.commit()
                conn.close()
                return self.send_json({"id": bk_id})

            return self.send_error_json(404, 'NOT_FOUND', 'Not Found')
        except RateLimitExceeded as e:
            self._retry_after = e.retry_after
            return self.send_error_json(429, 'RATE_LIMITED', str(e))
        except Exception as e:
            traceback.print_exc()
            return self.send_error_json(500, 'INTERNAL_SERVER_ERROR', str(e))

    def do_GET(self):
        try:
            url = urllib.parse.urlparse(self.path)
            path = url.path

            # 1. 认证状态检查: GET /api/user/me 或 /api/user/profile
            if path in ('/api/user/me', '/api/user/profile'):
                auth_user = self.get_token_user()
                if not auth_user:
                    return self.send_error_json(401, 'UNAUTHORIZED', '未登录')
                return self.send_json({"id": auth_user['user_id'], "username": auth_user['username']})

            # 2. 2FA 状态: GET /api/user/2fa/status
            if path == '/api/user/2fa/status':
                auth_user = self.get_token_user()
                if not auth_user:
                    return self.send_json({"enabled": False, "totp": False, "passkey": False})
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute('SELECT totp_secret FROM users WHERE id = ?', (auth_user['user_id'],))
                row = c.fetchone()
                c.execute('SELECT COUNT(*) FROM passkeys WHERE user_id = ? AND public_key IS NOT NULL AND rp_id = ?', (auth_user['user_id'], RP_ID))
                pk_cnt = c.fetchone()[0]
                conn.close()
                has_totp = bool(row and row[0])
                has_passkey = pk_cnt > 0 and self.current_rp_available()
                return self.send_json({"enabled": has_totp or has_passkey, "totp": has_totp, "passkey": has_passkey})

            # 3. 2FA 设置密钥申请: GET /api/user/2fa/setup
            if path == '/api/user/2fa/setup':
                auth_user = self.get_token_user()
                if not auth_user:
                    return self.send_error_json(401, 'UNAUTHORIZED', '未登录')
                secret = generate_totp_secret()
                issuer = "HRT Tracker"
                uri = f"otpauth://totp/{urllib.parse.quote(issuer)}:{urllib.parse.quote(auth_user['username'])}?secret={secret}&issuer={urllib.parse.quote(issuer)}&algorithm=SHA1&digits=6&period=30"
                return self.send_json({"secret": secret, "uri": uri})

            # 4. 2FA 备用码剩余: GET /api/user/2fa/backup-codes
            if path == '/api/user/2fa/backup-codes':
                auth_user = self.get_token_user()
                if not auth_user:
                    return self.send_error_json(401, 'UNAUTHORIZED', '未登录')
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute('SELECT backup_codes FROM users WHERE id = ?', (auth_user['user_id'],))
                row = c.fetchone()
                conn.close()
                codes = json.loads(row[0] or '[]') if row else []
                return self.send_json({"remaining": len(codes)})

            # 5. 会话列表: GET /api/user/sessions
            if path == '/api/user/sessions':
                auth_user = self.get_token_user()
                if not auth_user:
                    return self.send_error_json(401, 'UNAUTHORIZED', '未登录')
                now = int(time.time())
                with closing(sqlite3.connect(DB_PATH)) as conn, conn:
                    rows = conn.execute('''SELECT sid, created_at, last_used FROM sessions
                        WHERE user_id = ? AND auth_version = 1 AND created_at > ? AND last_used > ?
                        ORDER BY created_at DESC''',
                                        (auth_user['user_id'], now - SESSION_MAX_AGE, now - SESSION_IDLE_TIMEOUT)).fetchall()
                return self.send_json([{
                    'id': row[0], 'user_id': auth_user['user_id'],
                    'created_at': row[1], 'last_used_at': row[2],
                    'device_info': '本地多设备共享服务器', 'ip': '',
                    'is_current': row[0] == auth_user['sid']
                } for row in rows])

            # 通行密钥列表: GET /api/user/passkeys
            if path == '/api/user/passkeys':
                auth_user = self.get_token_user()
                if not auth_user:
                    return self.send_error_json(401, 'UNAUTHORIZED', '未登录')
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute('SELECT id, credential_id, device_name, created_at, rp_id FROM passkeys WHERE user_id = ? AND public_key IS NOT NULL ORDER BY created_at DESC', (auth_user['user_id'],))
                rows = c.fetchall()
                conn.close()
                available = self.current_rp_available()
                res = [{'id': r[0], 'credential_id': r[1], 'device_name': r[2], 'created_at': r[3],
                        'rp_id': r[4], 'is_current_rp': r[4] == RP_ID and available} for r in rows]
                return self.send_json(res)

            # 通行密钥免密登录选项: GET /api/auth/passkey-options
            if path == '/api/auth/passkey-options':
                self.limit_auth_ip()
                query = urllib.parse.parse_qs(url.query)
                return self.passkey_auth_options((query.get('username', [''])[0]).strip())

            # 7. 云端备份列表: GET /api/content
            if path == '/api/content':
                auth_user = self.get_token_user()
                if not auth_user:
                    return self.send_error_json(401, 'UNAUTHORIZED', '请先登录')
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute('SELECT id, created_at, data_size FROM backups WHERE user_id = ? ORDER BY created_at DESC', (auth_user['user_id'],))
                rows = c.fetchall()
                conn.close()
                res = [{"id": r[0], "created_at": r[1], "data_size": r[2]} for r in rows]
                return self.send_json(res)

            # 8. 单个备份读取: GET /api/content/<id>
            if path.startswith('/api/content/'):
                auth_user = self.get_token_user()
                if not auth_user:
                    return self.send_error_json(401, 'UNAUTHORIZED', '请先登录')
                bk_id = urllib.parse.unquote(path[len('/api/content/'):])
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute('SELECT id, user_id, data, created_at FROM backups WHERE id = ? AND user_id = ?', (bk_id, auth_user['user_id']))
                row = c.fetchone()
                conn.close()
                if not row:
                    return self.send_error_json(404, 'NOT_FOUND', '备份不存在')
                return self.send_json({"id": row[0], "user_id": row[1], "data": row[2], "created_at": row[3]})

            # 9. 系统公告: GET /api/admin/notice
            if path == '/api/admin/notice':
                return self.send_json({"revision": 1, "title": "多设备互通服务就绪", "content": "账号与用药数据已在本地服务器数据库就绪。"})

            # 10. 静态资源响应 (SPA 路由回退)
            req_path = os.path.join(DIST_DIR, path.lstrip('/'))
            if not os.path.exists(req_path) or os.path.isdir(req_path):
                self.path = '/index.html'
            return super().do_GET()
        except RateLimitExceeded as e:
            self._retry_after = e.retry_after
            return self.send_error_json(429, 'RATE_LIMITED', str(e))
        except Exception as e:
            traceback.print_exc()
            return self.send_error_json(500, 'INTERNAL_SERVER_ERROR', str(e))

    def do_DELETE(self):
        try:
            url = urllib.parse.urlparse(self.path)
            path = url.path

            # 删除自身账号: DELETE /api/user/me
            if path == '/api/user/me':
                auth_user = self.get_token_user()
                if not auth_user:
                    return self.send_error_json(401, 'UNAUTHORIZED', '未登录')
                data = self.read_json_body()
                password = data.get('password') or ''
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute('BEGIN IMMEDIATE')
                c.execute('SELECT password_hash, salt FROM users WHERE id = ?', (auth_user['user_id'],))
                row = c.fetchone()
                if not row:
                    conn.close()
                    return self.send_error_json(404, 'NOT_FOUND', '用户不存在')

                pw_hash, salt = row
                if hash_password(password, salt) != pw_hash:
                    conn.close()
                    return self.send_error_json(401, 'INVALID_CREDENTIALS', '密码错误')

                if not self.verify_second_factor(conn, auth_user['user_id'], data, 'delete', auth_user['sid']):
                    conn.commit()
                    conn.close()
                    return

                # 物理删除该用户的一切数据
                uid = auth_user['user_id']
                c.execute('DELETE FROM users WHERE id = ?', (uid,))
                c.execute('DELETE FROM sessions WHERE user_id = ?', (uid,))
                c.execute('DELETE FROM backups WHERE user_id = ?', (uid,))
                c.execute('DELETE FROM passkeys WHERE user_id = ?', (uid,))
                c.execute('DELETE FROM webauthn_challenges WHERE user_id = ?', (uid,))
                conn.commit()
                conn.close()
                return self.send_json({'message': 'Account deleted'})

            # 删除通行密钥: DELETE /api/user/passkeys/:id
            if path.startswith('/api/user/passkeys/'):
                auth_user = self.get_token_user()
                if not auth_user:
                    return self.send_error_json(401, 'UNAUTHORIZED', '未登录')
                pk_id = urllib.parse.unquote(path.split('/')[-1])
                data = self.read_json_body()
                with closing(sqlite3.connect(DB_PATH)) as conn, conn:
                    conn.execute('BEGIN IMMEDIATE')
                    if not self.require_password(conn, auth_user['user_id'], data, require_totp=True):
                        return
                    conn.execute('DELETE FROM passkeys WHERE id = ? AND user_id = ?', (pk_id, auth_user['user_id']))
                return self.send_json({'message': 'Passkey deleted'})

            # 关闭 2FA: DELETE /api/user/2fa
            if path == '/api/user/2fa':
                return self.disable_totp()

            # 删除单个备份: DELETE /api/content/<id>
            if path.startswith('/api/content/'):
                auth_user = self.get_token_user()
                if not auth_user:
                    return self.send_error_json(401, 'UNAUTHORIZED', '请先登录')
                bk_id = urllib.parse.unquote(path[len('/api/content/'):])
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute('DELETE FROM backups WHERE id = ? AND user_id = ?', (bk_id, auth_user['user_id']))
                conn.commit()
                conn.close()
                return self.send_json({"success": True})

            # 注销会话: DELETE /api/user/sessions/:id
            if path == '/api/user/sessions' or re.fullmatch(r'/api/user/sessions/[^/]+', path):
                auth_user = self.get_token_user()
                if not auth_user:
                    return self.send_error_json(401, 'UNAUTHORIZED', '未登录')
                with closing(sqlite3.connect(DB_PATH)) as conn, conn:
                    if path == '/api/user/sessions':
                        conn.execute('DELETE FROM sessions WHERE user_id = ? AND sid != ?',
                                     (auth_user['user_id'], auth_user['sid']))
                    else:
                        sid = urllib.parse.unquote(path.split('/')[-1])
                        conn.execute('DELETE FROM sessions WHERE user_id = ? AND sid = ?',
                                     (auth_user['user_id'], sid))
                return self.send_json({"success": True})

            return self.send_error_json(404, 'NOT_FOUND', 'Not Found')
        except RateLimitExceeded as e:
            self._retry_after = e.retry_after
            return self.send_error_json(429, 'RATE_LIMITED', str(e))
        except Exception as e:
            traceback.print_exc()
            return self.send_error_json(500, 'INTERNAL_SERVER_ERROR', str(e))


# 使用多线程服务器，彻底消灭单线程排队超时导致的 "Failed to fetch"
class ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

if __name__ == '__main__':
    url = f"http://0.0.0.0:{PORT}"
    print("=" * 60)
    print(f"🚀 HRT Tracker 服务器已启动！")
    print(f"👉 本地访问地址: http://localhost:{PORT}")
    print(f"👉 局域网/服务器访问: {url}")
    print(f"🗄️ 账户与备份数据库: {DB_PATH} (SQLite 驱动，支持 2FA TOTP & Passkeys)")
    print(f"📁 前端静态资源目录: {DIST_DIR}")
    print("=" * 60)
    sys.stdout.flush()

    with ThreadingServer(("0.0.0.0", PORT), HRTServerHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n服务器已停止。")
