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

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("PORT", 3000))
PERSIST_DIR = os.environ.get("PERSIST_DIR", BASE_DIR)
DIST_DIR = os.path.join(BASE_DIR, "dist")
DB_PATH = os.path.join(PERSIST_DIR, "hrt_server.db")

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
        "exp": int(time.time()) + 86400 * 365
    }
    payload = b64url_encode(json.dumps(claims).encode('utf-8'))
    sig = b64url_encode(hashlib.sha256(f"{header}.{payload}.hrt_secret_key".encode('utf-8')).digest())
    return f"{header}.{payload}.{sig}"

def verify_token(token: str):
    if not token:
        return None
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        pad = (4 - len(payload_b64) % 4) % 4
        claims = json.loads(base64.urlsafe_b64decode((payload_b64 + '=' * pad).encode('utf-8')).decode('utf-8'))
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT user_id, sid FROM sessions WHERE token = ?', (token,))
        row = c.fetchone()
        conn.close()
        
        if row:
            return {"user_id": row[0], "username": claims.get("username", "user"), "sid": row[1]}
        return None
    except Exception:
        return None

# --- 双重认证 (TOTP RFC 6238) ---
def generate_totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode('ascii').rstrip('=')

def verify_totp(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    try:
        secret_clean = secret.replace(' ', '').upper()
        pad = (8 - len(secret_clean) % 8) % 8
        key = base64.b32decode((secret_clean + '=' * pad).encode('ascii'))
        current_step = int(time.time() // 30)
        for step in [current_step, current_step - 1, current_step + 1]:
            msg = struct.pack('>Q', step)
            h = hmac.new(key, msg, hashlib.sha1).digest()
            o = h[19] & 15
            token = (struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff) % 1000000
            if f'{token:06d}' == str(code).strip():
                return True
        return False
    except Exception:
        return False

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

    def get_token_user(self):
        auth_header = self.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:].strip()
            return verify_token(token)
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

    def do_POST(self):
        try:
            url = urllib.parse.urlparse(self.path)
            path = url.path

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
                origin = self.headers.get('Origin', '') or f'http://{self.headers.get("Host", "localhost")}'
                try:
                    rp_id = urllib.parse.urlparse(origin).hostname or 'localhost'
                except:
                    rp_id = 'localhost'
                challenge = b64url_encode(os.urandom(32))
                user_id_encoded = b64url_encode(auth_user['user_id'].encode('utf-8'))
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute('SELECT credential_id FROM passkeys WHERE user_id = ?', (auth_user['user_id'],))
                enrolled = [r[0] for r in c.fetchall()]
                conn.close()
                challenge_token = make_token(auth_user['user_id'], auth_user['username'], f'challenge_{challenge}')
                return self.send_json({
                    'challengeToken': challenge_token,
                    'challenge': challenge,
                    'rp': {'id': rp_id, 'name': 'HRT Tracker'},
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
                data = self.read_json_body()
                cred = data.get('credential') or {}
                device_name = data.get('deviceName') or '通行密钥硬件'
                cred_id = cred.get('id') or b64url_encode(os.urandom(16))
                pk_id = f'pk_{int(time.time()*1000)}'
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute('INSERT OR REPLACE INTO passkeys (id, user_id, credential_id, device_name, created_at) VALUES (?, ?, ?, ?, ?)',
                          (pk_id, auth_user['user_id'], cred_id, device_name, int(time.time())))
                conn.commit()
                conn.close()
                return self.send_json({'message': 'Passkey registered', 'id': pk_id, 'backupCodes': []}, 201)

            # 通行密钥免密登录选项: POST /api/auth/passkey-options
            if path == '/api/auth/passkey-options':
                data = self.read_json_body()
                username = (data.get('username') or '').strip()
                origin = self.headers.get('Origin', '') or f'http://{self.headers.get("Host", "localhost")}'
                try:
                    rp_id = urllib.parse.urlparse(origin).hostname or 'localhost'
                except Exception:
                    rp_id = 'localhost'
                challenge = b64url_encode(os.urandom(32))

                credential_ids = []
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                if username:
                    c.execute('SELECT id FROM users WHERE username = ? COLLATE NOCASE', (username,))
                    urow = c.fetchone()
                    if urow:
                        c.execute('SELECT credential_id FROM passkeys WHERE user_id = ?', (urow[0],))
                        credential_ids = [r[0] for r in c.fetchall()]
                else:
                    c.execute('SELECT credential_id FROM passkeys')
                    credential_ids = [r[0] for r in c.fetchall()]
                conn.close()

                challenge_token = make_token("auth", username or "any", f"challenge_{challenge}")
                return self.send_json({
                    'challengeToken': challenge_token,
                    'challenge': challenge,
                    'credentialIds': credential_ids,
                    'rpId': rp_id,
                    'timeout': 60000,
                    'userVerification': 'preferred'
                })

            # 通行密钥免密登录验证: POST /api/auth/passkey-verify
            if path == '/api/auth/passkey-verify':
                data = self.read_json_body()
                cred = data.get('credential') or {}
                cred_id = cred.get('id')
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute('SELECT u.id, u.username FROM users u JOIN passkeys p ON u.id = p.user_id WHERE p.credential_id = ?', (cred_id,))
                row = c.fetchone()
                if not row:
                    conn.close()
                    return self.send_error_json(401, 'INVALID_CREDENTIALS', '未找到匹配的通行密钥')
                user_id, username = row
                sid = f'sid_{int(time.time()*1000)}'
                token = make_token(user_id, username, sid)
                c.execute('INSERT INTO sessions (token, sid, user_id, created_at, last_used) VALUES (?, ?, ?, ?, ?)',
                          (token, sid, user_id, int(time.time()), int(time.time())))
                conn.commit()
                conn.close()
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
                    sid = f"sid_{int(time.time()*1000)}"
                    token = make_token(user_id, username, sid)
                    c.execute(
                        'INSERT INTO sessions (token, sid, user_id, created_at, last_used) VALUES (?, ?, ?, ?, ?)',
                        (token, sid, user_id, int(time.time()), int(time.time()))
                    )
                    conn.commit()
                    conn.close()
                    return self.send_json({"token": token, "user": {"id": user_id, "username": username}})
                except sqlite3.IntegrityError:
                    return self.send_error_json(409, 'USER_EXISTS', '该用户名已存在')

            # 2. 登录: POST /api/login
            if path == '/api/login':
                data = self.read_json_body()
                username = (data.get('username') or '').strip()
                password = data.get('password') or ''
                totp_code = data.get('totp_code')
                backup_code = data.get('backup_code')

                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute('SELECT id, password_hash, salt, username, totp_secret, backup_codes FROM users WHERE username = ? COLLATE NOCASE', (username,))
                row = c.fetchone()
                if not row:
                    conn.close()
                    return self.send_error_json(401, 'INVALID_CREDENTIALS', '用户名或密码错误')

                user_id, pw_hash, salt, real_username, totp_sec, bk_codes_raw = row
                if hash_password(password, salt) != pw_hash:
                    conn.close()
                    return self.send_error_json(401, 'INVALID_CREDENTIALS', '用户名或密码错误')

                # 检查 2FA 双重认证
                if totp_sec:
                    if not totp_code and not backup_code:
                        conn.close()
                        return self.send_error_json(
                            401, 'TWO_FACTOR_REQUIRED', '需要双重认证验证码',
                            {"needs2FA": True, "method": "totp"}
                        )

                    if totp_code:
                        if not verify_totp(totp_sec, str(totp_code)):
                            conn.close()
                            return self.send_error_json(401, 'TWO_FACTOR_INVALID', '两步验证码错误')
                    elif backup_code:
                        codes = json.loads(bk_codes_raw or '[]')
                        clean_code = str(backup_code).strip().upper()
                        if clean_code in codes:
                            codes.remove(clean_code)
                            c.execute('UPDATE users SET backup_codes = ? WHERE id = ?', (json.dumps(codes), user_id))
                            conn.commit()
                        else:
                            conn.close()
                            return self.send_error_json(401, 'TWO_FACTOR_INVALID', '备用恢复码无效')

                sid = f"sid_{int(time.time()*1000)}"
                token = make_token(user_id, real_username, sid)
                c.execute(
                    'INSERT INTO sessions (token, sid, user_id, created_at, last_used) VALUES (?, ?, ?, ?, ?)',
                    (token, sid, user_id, int(time.time()), int(time.time()))
                )
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
                c.execute('SELECT password_hash, salt FROM users WHERE id = ?', (auth_user['user_id'],))
                row = c.fetchone()
                if not row or hash_password(old_pw, row[1]) != row[0]:
                    conn.close()
                    return self.send_error_json(401, 'WRONG_PASSWORD', '当前密码不正确')

                new_salt = hashlib.md5(f"{time.time()}_{new_pw}".encode()).hexdigest()[:8]
                c.execute(
                    'UPDATE users SET password_hash = ?, salt = ? WHERE id = ?',
                    (hash_password(new_pw, new_salt), new_salt, auth_user['user_id'])
                )
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

                if not verify_totp(secret, code):
                    return self.send_error_json(400, 'INVALID_CODE', '验证码不匹配，请核对手机时间与输入')

                codes = generate_backup_codes()
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute(
                    'UPDATE users SET totp_secret = ?, backup_codes = ? WHERE id = ?',
                    (secret, json.dumps(codes), auth_user['user_id'])
                )
                conn.commit()
                conn.close()
                return self.send_json({"backupCodes": codes})

            # 5. 关闭 2FA: POST /api/user/2fa
            if path == '/api/user/2fa':
                auth_user = self.get_token_user()
                if not auth_user:
                    return self.send_error_json(401, 'UNAUTHORIZED', '未登录')
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute('UPDATE users SET totp_secret = NULL, backup_codes = NULL WHERE id = ?', (auth_user['user_id'],))
                conn.commit()
                conn.close()
                return self.send_json({"success": True})

            # 6. 生成新备用码: POST /api/user/2fa/backup-codes/generate
            if path == '/api/user/2fa/backup-codes/generate':
                auth_user = self.get_token_user()
                if not auth_user:
                    return self.send_error_json(401, 'UNAUTHORIZED', '未登录')
                codes = generate_backup_codes()
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute('UPDATE users SET backup_codes = ? WHERE id = ?', (json.dumps(codes), auth_user['user_id']))
                conn.commit()
                conn.close()
                return self.send_json({"backupCodes": codes})

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
                c.execute('SELECT COUNT(*) FROM passkeys WHERE user_id = ?', (auth_user['user_id'],))
                pk_cnt = c.fetchone()[0]
                conn.close()
                has_totp = bool(row and row[0])
                has_passkey = bool(pk_cnt > 0)
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
                return self.send_json([{
                    "id": auth_user.get('sid', 'curr'),
                    "user_id": auth_user['user_id'],
                    "created_at": int(time.time()),
                    "last_used_at": int(time.time()),
                    "device_info": "本地多设备共享服务器",
                    "ip": self.client_address[0],
                    "is_current": True
                }])

            # 通行密钥列表: GET /api/user/passkeys
            if path == '/api/user/passkeys':
                auth_user = self.get_token_user()
                if not auth_user:
                    return self.send_error_json(401, 'UNAUTHORIZED', '未登录')
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute('SELECT id, credential_id, device_name, created_at FROM passkeys WHERE user_id = ? ORDER BY created_at DESC', (auth_user['user_id'],))
                rows = c.fetchall()
                conn.close()
                res = [{'id': r[0], 'credential_id': r[1], 'device_name': r[2], 'created_at': r[3]} for r in rows]
                return self.send_json(res)

            # 通行密钥免密登录选项: GET /api/auth/passkey-options
            if path == '/api/auth/passkey-options':
                query = urllib.parse.parse_qs(url.query)
                username = (query.get('username', [''])[0]).strip()
                origin = self.headers.get('Origin', '') or f'http://{self.headers.get("Host", "localhost")}'
                try:
                    rp_id = urllib.parse.urlparse(origin).hostname or 'localhost'
                except Exception:
                    rp_id = 'localhost'
                challenge = b64url_encode(os.urandom(32))

                credential_ids = []
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                if username:
                    c.execute('SELECT id FROM users WHERE username = ? COLLATE NOCASE', (username,))
                    urow = c.fetchone()
                    if urow:
                        c.execute('SELECT credential_id FROM passkeys WHERE user_id = ?', (urow[0],))
                        credential_ids = [r[0] for r in c.fetchall()]
                else:
                    c.execute('SELECT credential_id FROM passkeys')
                    credential_ids = [r[0] for r in c.fetchall()]
                conn.close()

                challenge_token = make_token("auth", username or "any", f"challenge_{challenge}")
                return self.send_json({
                    'challengeToken': challenge_token,
                    'challenge': challenge,
                    'credentialIds': credential_ids,
                    'rpId': rp_id,
                    'timeout': 60000,
                    'userVerification': 'preferred'
                })

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
                code = data.get('code') or ''
                backup_code = data.get('backup_code') or ''

                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute('SELECT password_hash, salt, totp_secret, backup_codes FROM users WHERE id = ?', (auth_user['user_id'],))
                row = c.fetchone()
                if not row:
                    conn.close()
                    return self.send_error_json(404, 'NOT_FOUND', '用户不存在')

                pw_hash, salt, totp_sec, bk_codes_raw = row
                if hash_password(password, salt) != pw_hash:
                    conn.close()
                    return self.send_error_json(401, 'INVALID_CREDENTIALS', '密码错误')

                # 校验 2FA 验证码
                if totp_sec:
                    if not code and not backup_code:
                        conn.close()
                        return self.send_error_json(400, 'TWO_FACTOR_REQUIRED', '需要两步验证码')
                    if code:
                        if not verify_totp(totp_sec, str(code)):
                            conn.close()
                            return self.send_error_json(400, 'TWO_FACTOR_INVALID', '两步验证码错误')
                    elif backup_code:
                        codes = json.loads(bk_codes_raw or '[]')
                        if str(backup_code).strip().upper() not in codes:
                            conn.close()
                            return self.send_error_json(400, 'TWO_FACTOR_INVALID', '备用恢复码无效')

                # 物理删除该用户的一切数据
                uid = auth_user['user_id']
                c.execute('DELETE FROM users WHERE id = ?', (uid,))
                c.execute('DELETE FROM sessions WHERE user_id = ?', (uid,))
                c.execute('DELETE FROM backups WHERE user_id = ?', (uid,))
                c.execute('DELETE FROM passkeys WHERE user_id = ?', (uid,))
                conn.commit()
                conn.close()
                return self.send_json({'message': 'Account deleted'})

            # 删除通行密钥: DELETE /api/user/passkeys/:id
            if path.startswith('/api/user/passkeys/'):
                auth_user = self.get_token_user()
                if not auth_user:
                    return self.send_error_json(401, 'UNAUTHORIZED', '未登录')
                pk_id = urllib.parse.unquote(path.split('/')[-1])
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute('DELETE FROM passkeys WHERE id = ? AND user_id = ?', (pk_id, auth_user['user_id']))
                conn.commit()
                conn.close()
                return self.send_json({'message': 'Passkey deleted'})

            # 关闭 2FA: DELETE /api/user/2fa
            if path == '/api/user/2fa':
                auth_user = self.get_token_user()
                if not auth_user:
                    return self.send_error_json(401, 'UNAUTHORIZED', '未登录')
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute('UPDATE users SET totp_secret = NULL, backup_codes = NULL WHERE id = ?', (auth_user['user_id'],))
                conn.commit()
                conn.close()
                return self.send_json({'success': True})

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
            if path.startswith('/api/user/sessions'):
                return self.send_json({"success": True})

            return self.send_error_json(404, 'NOT_FOUND', 'Not Found')
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
    print(f"🚀 绪山真寻 HRT Tracker 高并发多设备互通服务器已启动！")
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
