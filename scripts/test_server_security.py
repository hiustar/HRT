#!/usr/bin/env python3
"""HTTP regressions using a temporary database and real WebAuthn signatures."""

import base64
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from contextlib import closing, contextmanager
import hashlib
import hmac
import http.client
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import sqlite3
import struct
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
import uuid
from urllib.parse import quote

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "https://hrt.example"
RP_ID = "hrt.example"
PASSWORD = "Correct-security-password-2026!"
NEW_PASSWORD = "Replacement-security-password-2026!"
SECRET = "JBSWY3DPEHPK3PXP"
NEW_SECRET = "KRUGS4ZANFZSAYJA"

try:
    import cbor2
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    import webauthn  # noqa: F401 -- require the real verification dependency
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def totp(secret, step=None):
    """Independent RFC 6238 SHA-1/6 digit implementation, without a TOTP package."""
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    step = int(time.time() // 30) if step is None else step
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 15
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff
    return f"{number % 1000000:06d}"


def invalid_totp(secret):
    now = int(time.time() // 30)
    valid = {totp(secret, now + delta) for delta in range(-2, 3)}
    return next(f"{n:06d}" for n in range(1000000) if f"{n:06d}" not in valid)


class Authenticator:
    """Small software authenticator producing real ES256/COSE WebAuthn data."""

    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(32)
        numbers = self.key.public_key().public_numbers()
        self.cose = cbor2.dumps({1: 2, 3: -7, -1: 1,
                                -2: numbers.x.to_bytes(32, "big"),
                                -3: numbers.y.to_bytes(32, "big")})

    def client_data(self, kind, challenge, origin):
        return json.dumps({"type": kind, "challenge": challenge,
                           "origin": origin, "crossOrigin": False},
                          separators=(",", ":")).encode()

    def registration(self, options, origin=ORIGIN, rp_id=RP_ID):
        client = self.client_data("webauthn.create", options["challenge"], origin)
        # UP | UV | AT, signCount=0, zero AAGUID, then credential ID and COSE key.
        auth = (hashlib.sha256(rp_id.encode()).digest() + b"\x45" +
                struct.pack(">I", 0) + bytes(16) +
                struct.pack(">H", len(self.credential_id)) +
                self.credential_id + self.cose)
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth})
        return {"id": b64(self.credential_id), "rawId": b64(self.credential_id),
                "type": "public-key", "authenticatorAttachment": "cross-platform",
                "clientExtensionResults": {},
                "response": {"clientDataJSON": b64(client),
                             "attestationObject": b64(attestation),
                             "transports": ["usb"]}}

    def assertion(self, options, origin=ORIGIN, rp_id=RP_ID, counter=0,
                  bad_signature=False, user_id=None, user_verified=True):
        client = self.client_data("webauthn.get", options["challenge"], origin)
        flags = b"\x05" if user_verified else b"\x01"
        auth = (hashlib.sha256(rp_id.encode()).digest() + flags +
                struct.pack(">I", counter))
        key = ec.generate_private_key(ec.SECP256R1()) if bad_signature else self.key
        signature = key.sign(auth + hashlib.sha256(client).digest(),
                             ec.ECDSA(hashes.SHA256()))
        return {"id": b64(self.credential_id), "rawId": b64(self.credential_id),
                "type": "public-key", "clientExtensionResults": {},
                "response": {"clientDataJSON": b64(client),
                             "authenticatorData": b64(auth),
                             "signature": b64(signature),
                             "userHandle": b64(user_id.encode()) if user_id else None}}


class SecurityHTTPCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="hrt-security-")
        cls.old_env = {name: os.environ.get(name)
                       for name in ("PERSIST_DIR", "PUBLIC_APP_ORIGIN",
                                    "WEBAUTHN_ALLOWED_ORIGINS", "WEBAUTHN_RP_ID")}
        os.environ["PERSIST_DIR"] = cls.temp.name
        os.environ["PUBLIC_APP_ORIGIN"] = ORIGIN
        os.environ.pop("WEBAUTHN_ALLOWED_ORIGINS", None)
        os.environ.pop("WEBAUTHN_RP_ID", None)
        try:
            spec = importlib.util.spec_from_file_location(
                "hrt_security_test_backend", ROOT / "server.py")
            cls.backend = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.backend)

            class QuietHandler(cls.backend.HRTServerHandler):
                def log_message(self, *args):
                    pass

            cls.httpd = cls.backend.ThreadingServer(("127.0.0.1", 0), QuietHandler)
            cls.port = cls.httpd.server_address[1]
            cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
            cls.thread.start()
        except BaseException:
            cls.restore_environment()
            cls.temp.cleanup()
            raise

    @classmethod
    def restore_environment(cls):
        for name, previous in cls.old_env.items():
            if previous is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = previous

    @classmethod
    def tearDownClass(cls):
        try:
            cls.httpd.shutdown()
            cls.httpd.server_close()
            cls.thread.join(timeout=5)
        finally:
            cls.restore_environment()
            cls.temp.cleanup()

    def setUp(self):
        # Durable buckets are shared by the HTTP server, so isolate every case.
        self.sql("DELETE FROM auth_rate_limits")
        self.username = "security_" + uuid.uuid4().hex
        result = self.ok("POST", "/api/register",
                         {"username": self.username, "password": PASSWORD})
        self.token = result["token"]
        self.user_id = result["user"]["id"]

    def request(self, method, path, data=None, token=None, origin=ORIGIN, headers=None):
        headers = dict(headers or {})
        headers["Accept"] = "application/json"
        if origin is not None:
            headers["Origin"] = origin
        if token:
            headers["Authorization"] = "Bearer " + token
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            raw = response.read()
            try:
                payload = json.loads(raw) if raw else None
            except (ValueError, UnicodeError):
                payload = raw.decode("utf-8", errors="replace")
            return response.status, dict((k.lower(), v) for k, v in response.getheaders()), payload
        finally:
            conn.close()

    def ok(self, method, path, data=None, token=None, **kwargs):
        status, _, payload = self.request(method, path, data, token, **kwargs)
        self.assertIn(status, (200, 201, 204), (method, path, status, payload))
        return payload

    def denied(self, method, path, data=None, token=None, foreign=False, **kwargs):
        status, _, payload = self.request(method, path, data, token, **kwargs)
        self.assertIn(status, (400, 401, 403, 404) if foreign else (400, 401, 403),
                      (method, path, status, payload))
        return payload

    def sql(self, query, params=()):
        with closing(sqlite3.connect(self.backend.DB_PATH)) as db, db:
            cursor = db.execute(query, params)
            return cursor.fetchall()

    def login(self, password=PASSWORD, **extra):
        return self.ok("POST", "/api/login", {"username": self.username,
                       "password": password, **extra})["token"]

    def sid(self, token):
        return self.sql("SELECT sid FROM sessions WHERE token = ?", (token,))[0][0]

    def alive(self, token):
        self.ok("GET", "/api/user/me", token=token)

    def expired(self, token):
        status, headers, body = self.request("GET", "/api/user/me", token=token)
        self.assertEqual(status, 401, body)
        self.assertEqual(headers.get("x-session-invalid"), "1", headers)

    def stored_secret(self):
        return self.sql("SELECT totp_secret FROM users WHERE id = ?", (self.user_id,))[0][0]

    @contextmanager
    def server_clock(self, timestamp):
        # Replace the backend's module reference, not the process-wide time module.
        with patch.object(self.backend, "time", SimpleNamespace(time=lambda: timestamp)):
            yield

    def advance_totp(self):
        self.totp_step = max(getattr(self, "totp_step", 0), int(time.time() // 30)) + 1
        clock = self.server_clock(self.totp_step * 30 + 5)
        clock.__enter__()
        self.addCleanup(clock.__exit__, None, None, None)
        return totp(SECRET, self.totp_step)

    def enable(self, secret=SECRET):
        return self.ok("POST", "/api/user/2fa/enable",
                       {"password": PASSWORD, "secret": secret,
                        "code": totp(secret, int(time.time() // 30) - 1)}, self.token)

    def crypto(self):
        if not CRYPTO_AVAILABLE:
            self.skipTest("requires real webauthn, cryptography and cbor2 dependencies")

    def register_options(self, origin=ORIGIN, **kwargs):
        return self.ok("POST", "/api/user/passkey/register-options", {}, self.token,
                       origin=origin, **kwargs)

    def enroll(self, proof=None, origin=ORIGIN, rp_id=RP_ID):
        self.crypto()
        authenticator = Authenticator()
        options = self.register_options(origin=origin)
        data = {"password": PASSWORD,
                "credential": authenticator.registration(options, origin=origin, rp_id=rp_id),
                "challengeToken": options["challengeToken"], "deviceName": "Security test ES256"}
        if proof:
            data.update(proof)
        result = self.ok("POST", "/api/user/passkey/register", data, self.token, origin=origin)
        row = self.sql("SELECT id FROM passkeys WHERE credential_id = ?",
                       (b64(authenticator.credential_id),))
        self.assertEqual(len(row), 1, result)
        return authenticator, row[0][0]

    def auth_options(self, username=None, origin=ORIGIN, **kwargs):
        return self.ok("POST", "/api/auth/passkey-options",
                       {} if username is None else {"username": username}, origin=origin, **kwargs)

    def verify(self, authenticator, options, **kwargs):
        return {"challengeToken": options["challengeToken"],
                "credential": authenticator.assertion(options, **kwargs)}

    def login_options(self, password=PASSWORD, **kwargs):
        return self.ok("POST", "/api/auth/passkey-options",
                       {"purpose": "login", "username": self.username,
                        "password": password}, **kwargs)

    def sensitive_options(self, purpose, password=PASSWORD, token=None, **kwargs):
        return self.ok("POST", "/api/user/passkey/auth-options",
                       {"purpose": purpose, "password": password},
                       self.token if token is None else token, **kwargs)

    def factor_options(self, purpose, **kwargs):
        if purpose == "login":
            return self.login_options(**kwargs)
        return self.sensitive_options(purpose, **kwargs)

    def factor_request(self, purpose, proof=None, password=PASSWORD, token=None,
                       extra=None, **kwargs):
        if purpose == "login":
            method, path = "POST", "/api/login"
            data = {"username": self.username, "password": password}
            token = None
        elif purpose == "password":
            method, path = "POST", "/api/user/password"
            data = {"currentPassword": password, "newPassword": NEW_PASSWORD}
            token = self.token if token is None else token
        else:
            self.assertEqual(purpose, "delete")
            method, path = "DELETE", "/api/user/me"
            data = {"password": password}
            token = self.token if token is None else token
        if proof is not None:
            data["passkey"] = proof
        data.update(extra or {})
        return self.request(method, path, data, token, **kwargs)

    def factor_ok(self, purpose, **kwargs):
        status, _, payload = self.factor_request(purpose, **kwargs)
        self.assertEqual(status, 200, (purpose, status, payload))
        if purpose == "login":
            self.assertEqual(payload["user"]["id"], self.user_id)
            self.alive(payload["token"])
        elif purpose == "password":
            self.alive(self.token)
        else:
            self.assertFalse(self.sql("SELECT id FROM users WHERE id = ?", (self.user_id,)))
            self.assertFalse(self.sql("SELECT token FROM sessions WHERE user_id = ?", (self.user_id,)))
            self.assertFalse(self.sql("SELECT id FROM passkeys WHERE user_id = ?", (self.user_id,)))
            self.expired(self.token)
        return payload

    def factor_denied(self, purpose, **kwargs):
        before = self.sql("SELECT password_hash, salt FROM users WHERE id = ?", (self.user_id,))
        sessions = self.sql("SELECT token FROM sessions WHERE user_id = ? ORDER BY token", (self.user_id,))
        status, _, payload = self.factor_request(purpose, **kwargs)
        self.assertIn(status, (400, 401, 403), (purpose, status, payload))
        self.assertNotIn("token", payload)
        self.assertEqual(self.sql("SELECT password_hash, salt FROM users WHERE id = ?",
                                  (self.user_id,)), before)
        self.assertEqual(self.sql("SELECT token FROM sessions WHERE user_id = ? ORDER BY token",
                                  (self.user_id,)), sessions)
        self.alive(self.token)
        return payload

    def backup_codes(self):
        secret = self.stored_secret()
        data = {"password": PASSWORD}
        if secret:
            data["code"] = totp(secret)
        return self.ok("POST", "/api/user/2fa/backup-codes/generate", data, self.token)["codes"]

    @contextmanager
    def webauthn_environment(self, **values):
        names = ("PUBLIC_APP_ORIGIN", "WEBAUTHN_ALLOWED_ORIGINS", "WEBAUTHN_RP_ID")
        previous = {name: os.environ.get(name) for name in names}
        try:
            for name in names:
                value = values.get(name)
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
            yield
        finally:
            for name, value in previous.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

    @contextmanager
    def webauthn_config(self, origins, rp_id):
        # Requests finish synchronously before restoring these process-wide globals.
        with patch.multiple(self.backend, ALLOWED_ORIGINS=tuple(origins), RP_ID=rp_id):
            yield

    @contextmanager
    def migration_database(self, challenge_rps=(), public_origin=None, existing_rp=False):
        """Copy a valid signed-session DB, then reproduce only the pre-RP schema."""
        secret = self.stored_secret()
        authenticator, pk_id = self.enroll({"code": totp(secret)} if secret else None)
        with tempfile.TemporaryDirectory(prefix="hrt-rp-migration-") as directory:
            path = os.path.join(directory, "migration.db")
            with closing(sqlite3.connect(self.backend.DB_PATH)) as source:
                with closing(sqlite3.connect(path)) as target:
                    source.backup(target)
            with closing(sqlite3.connect(path)) as db, db:
                if not existing_rp:
                    rows = db.execute("SELECT id, user_id, credential_id, device_name, created_at, "
                                      "public_key, sign_count FROM passkeys").fetchall()
                    db.execute("DROP TABLE passkeys")
                    db.execute("CREATE TABLE passkeys (id TEXT PRIMARY KEY, user_id TEXT, "
                               "credential_id TEXT UNIQUE, device_name TEXT, created_at INTEGER, "
                               "public_key TEXT, sign_count INTEGER NOT NULL DEFAULT 0)")
                    db.executemany("INSERT INTO passkeys VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
                db.execute("DELETE FROM webauthn_challenges")
                for rp_id in challenge_rps:
                    db.execute("INSERT INTO webauthn_challenges "
                               "(token, purpose, user_id, challenge, origin, rp_id, expires_at) "
                               "VALUES (?, ?, ?, ?, ?, ?, ?)",
                               (uuid.uuid4().hex, "authenticate", self.user_id, b64(os.urandom(32)),
                                "https://" + rp_id, rp_id, int(time.time()) + 300))
            with self.webauthn_environment(PUBLIC_APP_ORIGIN=public_origin):
                with patch.multiple(self.backend, DB_PATH=path,
                                    SESSION_SIGNING_KEY=self.backend.SESSION_SIGNING_KEY):
                    with self.webauthn_config(("https://new.example",), "new.example"):
                        yield authenticator, pk_id
        self.alive(self.token)

    def credential_ids(self, options, field="credentialIds"):
        return set(options.get(field, []))

class ServerSecurityTests(SecurityHTTPCase):
    def setUp(self):
        # Legacy matrix cases deliberately make many attempts in one case. Keep
        # real SQLite enforcement, but leave production quotas to dedicated cases.
        limiter = self.backend.check_auth_rate_limit
        replacement = patch.object(
            self.backend, "check_auth_rate_limit",
            lambda scope, identity, limit, now=None: limiter(scope, identity, 10000, now))
        replacement.start()
        self.addCleanup(replacement.stop)
        super().setUp()

    def test_session_registration_and_login_are_valid(self):
        self.alive(self.token)
        self.alive(self.login())

    def test_signed_token_expired_claim_is_rejected(self):
        parts = self.token.split('.')
        claims = json.loads(unb64(parts[1]))
        claims['exp'] = int(time.time()) - 60
        parts[1] = b64(json.dumps(claims).encode())
        parts[2] = b64(hmac.new(self.backend.SESSION_SIGNING_KEY,
                               '.'.join(parts[:2]).encode(), hashlib.sha256).digest())
        expired_token = '.'.join(parts)
        self.sql('UPDATE sessions SET token = ? WHERE token = ?', (expired_token, self.token))
        self.expired(expired_token)

    def test_legacy_schema_migration_revokes_untrusted_sessions(self):
        original_path = self.backend.DB_PATH
        original_key = self.backend.SESSION_SIGNING_KEY
        try:
            with tempfile.TemporaryDirectory(prefix='hrt-legacy-') as directory:
                self.backend.DB_PATH = os.path.join(directory, 'legacy.db')
                with closing(sqlite3.connect(self.backend.DB_PATH)) as db, db:
                    db.execute('''CREATE TABLE sessions (token TEXT PRIMARY KEY, sid TEXT,
                        user_id TEXT, created_at INTEGER, last_used INTEGER)''')
                    db.execute('INSERT INTO sessions VALUES (?, ?, ?, ?, ?)',
                               ('untrusted', 'sid_old', self.user_id, int(time.time()), int(time.time())))
                self.backend.init_db()
                self.assertFalse(self.sql('SELECT token FROM sessions'))
                self.assertIn('public_key', {r[1] for r in self.sql('PRAGMA table_info(passkeys)')})
                self.assertIn('sign_count', {r[1] for r in self.sql('PRAGMA table_info(passkeys)')})
                key = self.backend.SESSION_SIGNING_KEY
                self.backend.init_db()
                self.assertEqual(key, self.backend.SESSION_SIGNING_KEY)
        finally:
            self.backend.DB_PATH = original_path
            self.backend.SESSION_SIGNING_KEY = original_key
        self.alive(self.token)

    def test_session_absolute_seven_day_expiry(self):
        self.sql("UPDATE sessions SET created_at = ? WHERE token = ?",
                 (int(time.time()) - 7 * 86400 - 60, self.token))
        self.expired(self.token)

    def test_session_three_day_idle_expiry(self):
        self.sql("UPDATE sessions SET last_used = ? WHERE token = ?",
                 (int(time.time()) - 3 * 86400 - 60, self.token))
        self.expired(self.token)

    def test_session_active_request_refreshes_idle_not_absolute_clock(self):
        created = int(time.time()) - 86400
        old_used = int(time.time()) - 3600
        self.sql("UPDATE sessions SET created_at = ?, last_used = ? WHERE token = ?",
                 (created, old_used, self.token))
        self.alive(self.token)
        row = self.sql("SELECT created_at, last_used FROM sessions WHERE token = ?", (self.token,))[0]
        self.assertEqual(row[0], created)
        self.assertGreater(row[1], old_used)

    def test_old_token_expired_claim_is_rejected_even_if_in_database(self):
        parts = self.token.split(".")
        self.assertEqual(len(parts), 3, "legacy JWT-compatible token expected")
        claims = json.loads(unb64(parts[1]))
        claims["exp"] = int(time.time()) - 60
        parts[1] = b64(json.dumps(claims).encode())
        altered = ".".join(parts)
        self.sql("UPDATE sessions SET token = ? WHERE token = ?", (altered, self.token))
        self.expired(altered)

    def test_old_token_exp_extension_cannot_bypass_absolute_expiry(self):
        parts = self.token.split(".")
        self.assertEqual(len(parts), 3, "legacy JWT-compatible token expected")
        claims = json.loads(unb64(parts[1]))
        claims["exp"] = int(time.time()) + 365 * 86400
        parts[1] = b64(json.dumps(claims).encode())
        altered = ".".join(parts)
        self.sql("UPDATE sessions SET token = ?, created_at = ? WHERE token = ?",
                 (altered, int(time.time()) - 8 * 86400, self.token))
        self.expired(altered)

    def test_session_list_all_valid_own_only(self):
        second = self.login()
        expired = self.login()
        self.sql("UPDATE sessions SET last_used = ? WHERE token = ?",
                 (int(time.time()) - 4 * 86400, expired))
        stranger = self.ok("POST", "/api/register", {"username": uuid.uuid4().hex, "password": PASSWORD})
        result = self.ok("GET", "/api/user/sessions", token=self.token)
        rows = result if isinstance(result, list) else result["sessions"]
        ids = {r.get("id", r.get("sid")) for r in rows}
        self.assertEqual(ids, {self.sid(self.token), self.sid(second)})
        self.assertNotIn(self.sid(stranger["token"]), ids)
        self.assertEqual(sum(bool(r.get("is_current", r.get("isCurrent", False))) for r in rows), 1)

    def test_logout_current_session_replay_fails(self):
        sid = self.sid(self.token)
        self.ok("DELETE", "/api/user/sessions/" + quote(sid, safe=""), token=self.token)
        self.expired(self.token)

    def test_revoke_other_session_preserves_current(self):
        other = self.login()
        self.ok("DELETE", "/api/user/sessions/" + quote(self.sid(other), safe=""), token=self.token)
        self.expired(other)
        self.alive(self.token)

    def test_revoke_all_other_sessions_preserves_current(self):
        others = [self.login(), self.login()]
        self.ok("DELETE", "/api/user/sessions", token=self.token)
        self.alive(self.token)
        for token in others:
            self.expired(token)

    def test_cannot_revoke_another_users_session(self):
        other = self.ok("POST", "/api/register", {"username": uuid.uuid4().hex, "password": PASSWORD})["token"]
        # Idempotent success or explicit denial are both safe, provided ownership holds.
        status, _, body = self.request("DELETE", "/api/user/sessions/" + quote(self.sid(other), safe=""), token=self.token)
        self.assertIn(status, (200, 204, 400, 403, 404), body)
        self.alive(other)

    def test_password_change_preserves_current_revokes_others(self):
        other = self.login()
        self.ok("POST", "/api/user/password", {"currentPassword": PASSWORD,
                "newPassword": NEW_PASSWORD}, self.token)
        self.alive(self.token)
        self.expired(other)
        self.denied("POST", "/api/login", {"username": self.username, "password": PASSWORD})
        self.alive(self.login(NEW_PASSWORD))

    def test_password_change_revokes_session_from_concurrent_old_password_login(self):
        reached = threading.Event()
        release = threading.Event()
        original = self.backend.create_session

        def paused_create_session(conn, user_id, username):
            if user_id == self.user_id:
                reached.set()
                if not release.wait(5):
                    raise TimeoutError('concurrent login not released')
            return original(conn, user_id, username)

        with patch.object(self.backend, 'create_session', paused_create_session):
            with ThreadPoolExecutor(max_workers=2) as pool:
                login_future = pool.submit(self.login)
                self.assertTrue(reached.wait(5))
                change_future = pool.submit(self.request, 'POST', '/api/user/password',
                                            {'currentPassword': PASSWORD, 'newPassword': NEW_PASSWORD}, self.token)
                release.set()
                login_token = login_future.result(timeout=10)
                status, _, body = change_future.result(timeout=10)
                self.assertEqual(status, 200, body)
        self.expired(login_token)
        self.alive(self.token)

    def test_password_change_wrong_password_does_not_revoke_sessions(self):
        other = self.login()
        self.denied("POST", "/api/user/password", {"currentPassword": "wrong", "newPassword": NEW_PASSWORD}, self.token)
        self.alive(other)
        self.alive(self.token)

    def test_2fa_enable_token_only_rejected(self):
        self.denied("POST", "/api/user/2fa/enable", {"secret": SECRET, "code": totp(SECRET)}, self.token)
        self.assertFalse(self.stored_secret())

    def test_2fa_enable_wrong_password_rejected(self):
        self.denied("POST", "/api/user/2fa/enable", {"password": "wrong", "secret": SECRET, "code": totp(SECRET)}, self.token)
        self.assertFalse(self.stored_secret())

    def test_2fa_enable_invalid_new_code_rejected(self):
        self.denied("POST", "/api/user/2fa/enable", {"password": PASSWORD, "secret": SECRET, "code": invalid_totp(SECRET)}, self.token)
        self.assertFalse(self.stored_secret())

    def test_2fa_enable_valid_and_login_requires_totp(self):
        self.enable()
        self.assertEqual(self.stored_secret(), SECRET)
        self.denied("POST", "/api/login", {"username": self.username, "password": PASSWORD})
        self.alive(self.login(totp_code=totp(SECRET)))

    def test_2fa_replacement_requires_old_code(self):
        self.enable()
        for extra in ({}, {"currentCode": invalid_totp(SECRET)}):
            with self.subTest(extra=extra):
                self.denied("POST", "/api/user/2fa/enable", {"password": PASSWORD,
                            "secret": NEW_SECRET, "code": totp(NEW_SECRET), **extra}, self.token)
                self.assertEqual(self.stored_secret(), SECRET)

    def test_2fa_replacement_valid_old_and_new_proof(self):
        self.enable()
        self.ok("POST", "/api/user/2fa/enable", {"password": PASSWORD,
                "secret": NEW_SECRET, "code": totp(NEW_SECRET), "currentCode": totp(SECRET)}, self.token)
        self.assertEqual(self.stored_secret(), NEW_SECRET)

    def test_2fa_disable_requires_password_and_current_code_both_methods(self):
        self.enable()
        for method in ("POST", "DELETE"):
            for data in ({}, {"code": totp(SECRET)}, {"password": PASSWORD},
                         {"password": "wrong", "code": totp(SECRET)},
                         {"password": PASSWORD, "code": invalid_totp(SECRET)}):
                with self.subTest(method=method, fields=sorted(data)):
                    self.denied(method, "/api/user/2fa", data, self.token)
                    self.assertEqual(self.stored_secret(), SECRET)

    def test_2fa_disable_post_valid(self):
        self.enable()
        self.ok("POST", "/api/user/2fa", {"password": PASSWORD, "code": totp(SECRET)}, self.token)
        self.assertFalse(self.stored_secret())

    def test_2fa_disable_delete_valid(self):
        self.enable()
        self.ok("DELETE", "/api/user/2fa", {"password": PASSWORD, "code": totp(SECRET)}, self.token)
        self.assertFalse(self.stored_secret())

    def test_backup_generation_without_totp_requires_password(self):
        path = "/api/user/2fa/backup-codes/generate"
        self.denied("POST", path, {}, self.token)
        self.denied("POST", path, {"password": "wrong"}, self.token)
        result = self.ok("POST", path, {"password": PASSWORD}, self.token)
        self.assertTrue(result["codes"])
        self.assertEqual(result["codes"], result["backupCodes"])

    def test_backup_generation_with_totp_requires_both_proofs(self):
        self.enable()
        path = "/api/user/2fa/backup-codes/generate"
        before = self.sql("SELECT backup_codes FROM users WHERE id = ?", (self.user_id,))[0][0]
        for data in ({}, {"password": PASSWORD}, {"password": "wrong", "code": totp(SECRET)},
                     {"password": PASSWORD, "code": invalid_totp(SECRET)}):
            with self.subTest(fields=sorted(data)):
                self.denied("POST", path, data, self.token)
                self.assertEqual(self.sql("SELECT backup_codes FROM users WHERE id = ?", (self.user_id,))[0][0], before)
        result = self.ok("POST", path, {"password": PASSWORD, "code": totp(SECRET)}, self.token)
        self.assertTrue(result["codes"])
        self.assertEqual(result["codes"], result["backupCodes"])

    def test_passkey_options_trusted_origin_and_challenge_storage(self):
        options = self.register_options()
        self.assertEqual(options["rp"]["id"], RP_ID)
        self.assertEqual(unb64(options["user"]["id"]).decode(), self.user_id)
        row = self.sql("SELECT purpose, user_id, challenge, origin, rp_id, expires_at "
                       "FROM webauthn_challenges WHERE token = ?", (options["challengeToken"],))
        self.assertEqual(len(row), 1)
        self.assertEqual(row[0][1:5], (self.user_id, options["challenge"], ORIGIN, RP_ID))
        self.assertGreater(row[0][5], time.time())

    def test_passkey_options_forged_origin_rejected(self):
        for path, token in (("/api/user/passkey/register-options", self.token),
                            ("/api/auth/passkey-options", None)):
            with self.subTest(path=path):
                status, _, body = self.request("POST", path, {}, token, origin="https://evil.example")
                self.assertEqual(status, 400, body)

    def test_passkey_discoverable_options_do_not_enumerate_credentials(self):
        authenticator, _ = self.enroll()
        options = self.auth_options()
        self.assertFalse(options.get("credentialIds", []))
        self.assertFalse(options.get("allowCredentials", []))
        self.assertNotIn(b64(authenticator.credential_id), json.dumps(options))

    def test_passkey_real_registration_stores_cose_key_and_zero_counter(self):
        authenticator, pk_id = self.enroll()
        public_key, count = self.sql("SELECT public_key, sign_count FROM passkeys WHERE id = ?", (pk_id,))[0]
        self.assertEqual(cbor2.loads(unb64(public_key)), cbor2.loads(authenticator.cose))
        self.assertEqual(count, 0)

    def test_passkey_registration_requires_password(self):
        self.crypto()
        for proof in ({}, {"password": "wrong"}):
            with self.subTest(proof=proof):
                authenticator = Authenticator()
                options = self.register_options()
                self.denied("POST", "/api/user/passkey/register", {
                    "credential": authenticator.registration(options),
                    "challengeToken": options["challengeToken"], **proof}, self.token)
                self.assertFalse(self.sql("SELECT id FROM passkeys WHERE credential_id = ?", (b64(authenticator.credential_id),)))

    def test_passkey_registration_requires_existing_totp_code(self):
        self.crypto()
        self.enable()
        for extra in ({}, {"code": invalid_totp(SECRET)}):
            with self.subTest(extra=extra):
                authenticator = Authenticator()
                options = self.register_options()
                self.denied("POST", "/api/user/passkey/register", {"password": PASSWORD,
                            "credential": authenticator.registration(options),
                            "challengeToken": options["challengeToken"], **extra}, self.token)
        self.enroll({"code": totp(SECRET)})

    def test_passkey_registration_rejects_wrong_origin_and_rp(self):
        self.crypto()
        for kwargs in ({"origin": "https://evil.example"}, {"rp_id": "evil.example"}):
            with self.subTest(kwargs=kwargs):
                authenticator = Authenticator()
                options = self.register_options()
                self.denied("POST", "/api/user/passkey/register", {"password": PASSWORD,
                            "credential": authenticator.registration(options, **kwargs),
                            "challengeToken": options["challengeToken"]}, self.token)
                self.assertFalse(self.sql("SELECT id FROM passkeys WHERE credential_id = ?", (b64(authenticator.credential_id),)))

    def test_passkey_registration_expired_challenge_rejected(self):
        self.crypto()
        authenticator = Authenticator()
        options = self.register_options()
        self.sql("UPDATE webauthn_challenges SET expires_at = ? WHERE token = ?",
                 (int(time.time()) - 60, options["challengeToken"]))
        self.denied("POST", "/api/user/passkey/register", {"password": PASSWORD,
                    "credential": authenticator.registration(options),
                    "challengeToken": options["challengeToken"]}, self.token)

    def test_passkey_registration_challenge_replay_rejected(self):
        self.crypto()
        options = self.register_options()
        first, second = Authenticator(), Authenticator()
        data = {"password": PASSWORD, "challengeToken": options["challengeToken"],
                "credential": first.registration(options)}
        self.ok("POST", "/api/user/passkey/register", data, self.token)
        data["credential"] = second.registration(options)
        self.denied("POST", "/api/user/passkey/register", data, self.token)

    def test_passkey_id_only_attack_rejected(self):
        authenticator, _ = self.enroll()
        options = self.auth_options(self.username)
        self.denied("POST", "/api/auth/passkey-verify", {
                    "challengeToken": options["challengeToken"],
                    "credential": {"id": b64(authenticator.credential_id)}})

    def test_passkey_invalid_signature_rejected(self):
        authenticator, _ = self.enroll()
        options = self.auth_options(self.username)
        self.denied("POST", "/api/auth/passkey-verify", self.verify(authenticator, options, bad_signature=True))

    def test_passkey_wrong_client_origin_rejected(self):
        authenticator, _ = self.enroll()
        options = self.auth_options(self.username)
        self.denied("POST", "/api/auth/passkey-verify", self.verify(authenticator, options, origin="https://evil.example"))

    def test_passkey_wrong_rp_hash_rejected(self):
        authenticator, _ = self.enroll()
        options = self.auth_options(self.username)
        self.denied("POST", "/api/auth/passkey-verify", self.verify(authenticator, options, rp_id="evil.example"))

    def test_passkey_zero_counter_valid_then_challenge_replay_rejected(self):
        authenticator, _ = self.enroll()
        options = self.auth_options(self.username)
        data = self.verify(authenticator, options, counter=0, user_id=self.user_id)
        result = self.ok("POST", "/api/auth/passkey-verify", data)
        self.assertEqual(result["user"]["id"], self.user_id)
        self.alive(result["token"])
        self.denied("POST", "/api/auth/passkey-verify", data)
        # Counterless authenticators remain usable with a fresh challenge.
        fresh = self.auth_options(self.username)
        self.ok("POST", "/api/auth/passkey-verify", self.verify(authenticator, fresh, counter=0))

    def test_passkey_nonzero_counter_rollback_rejected(self):
        authenticator, pk_id = self.enroll()
        options = self.auth_options(self.username)
        self.ok("POST", "/api/auth/passkey-verify", self.verify(authenticator, options, counter=5))
        self.assertEqual(self.sql("SELECT sign_count FROM passkeys WHERE id = ?", (pk_id,))[0][0], 5)
        options = self.auth_options(self.username)
        self.denied("POST", "/api/auth/passkey-verify", self.verify(authenticator, options, counter=4))

    def test_passkey_expired_auth_challenge_rejected(self):
        authenticator, _ = self.enroll()
        options = self.auth_options(self.username)
        self.sql("UPDATE webauthn_challenges SET expires_at = ? WHERE token = ?",
                 (int(time.time()) - 60, options["challengeToken"]))
        self.denied("POST", "/api/auth/passkey-verify", self.verify(authenticator, options))

    def test_passkey_username_binding_prevents_cross_account_login(self):
        authenticator, _ = self.enroll()
        stranger_name = "stranger_" + uuid.uuid4().hex
        self.ok("POST", "/api/register", {"username": stranger_name, "password": PASSWORD})
        options = self.auth_options(stranger_name)
        self.denied("POST", "/api/auth/passkey-verify", self.verify(authenticator, options))

    def test_passkey_unknown_username_cannot_fall_back_to_discoverable_login(self):
        authenticator, _ = self.enroll()
        options = self.auth_options("missing_" + uuid.uuid4().hex)
        self.denied("POST", "/api/auth/passkey-verify", self.verify(authenticator, options))

    def test_passkey_assertion_requires_matching_challenge(self):
        authenticator, _ = self.enroll()
        first, second = self.auth_options(self.username), self.auth_options(self.username)
        data = self.verify(authenticator, first)
        data["challengeToken"] = second["challengeToken"]
        self.denied("POST", "/api/auth/passkey-verify", data)

    def test_passkey_registration_challenge_cannot_authenticate(self):
        authenticator, _ = self.enroll()
        options = self.register_options()
        self.denied("POST", "/api/auth/passkey-verify", self.verify(authenticator, options))

    def test_passkey_legacy_record_without_public_key_rejected(self):
        self.crypto()
        authenticator = Authenticator()
        self.sql("INSERT INTO passkeys (id, user_id, credential_id, device_name, created_at) "
                 "VALUES (?, ?, ?, ?, ?)", ("legacy_" + uuid.uuid4().hex, self.user_id,
                 b64(authenticator.credential_id), "Old ID-only record", int(time.time())))
        options = self.auth_options(self.username)
        self.denied("POST", "/api/auth/passkey-verify", self.verify(authenticator, options))
        status = self.ok('GET', '/api/user/2fa/status', token=self.token)
        self.assertFalse(status['passkey'])
        self.assertFalse(status['enabled'])
        self.assertEqual(self.ok('GET', '/api/user/passkeys', token=self.token), [])

    def test_passkey_delete_requires_password(self):
        _, pk_id = self.enroll()
        path = "/api/user/passkeys/" + quote(pk_id, safe="")
        for data in ({}, {"password": "wrong"}):
            with self.subTest(data=data):
                self.denied("DELETE", path, data, self.token)
                self.assertTrue(self.sql("SELECT id FROM passkeys WHERE id = ?", (pk_id,)))
        self.ok("DELETE", path, {"password": PASSWORD}, self.token)
        self.assertFalse(self.sql("SELECT id FROM passkeys WHERE id = ?", (pk_id,)))

    def test_passkey_delete_requires_existing_totp_code(self):
        _, pk_id = self.enroll()
        self.enable()
        path = "/api/user/passkeys/" + quote(pk_id, safe="")
        for data in ({"password": PASSWORD}, {"password": PASSWORD, "code": invalid_totp(SECRET)}):
            with self.subTest(data=data):
                self.denied("DELETE", path, data, self.token)
                self.assertTrue(self.sql("SELECT id FROM passkeys WHERE id = ?", (pk_id,)))
        self.ok("DELETE", path, {"password": PASSWORD, "code": totp(SECRET)}, self.token)
        self.assertFalse(self.sql("SELECT id FROM passkeys WHERE id = ?", (pk_id,)))

    def test_webauthn_config_allowed_origins_override_legacy_and_deduplicate(self):
        with self.webauthn_environment(
                PUBLIC_APP_ORIGIN="not a valid legacy origin",
                WEBAUTHN_ALLOWED_ORIGINS=" https://APP.Example:443,https://app.example,https://app.example:8443 "):
            origins, rp_id = self.backend.load_webauthn_config()
        self.assertIsInstance(origins, tuple)
        self.assertEqual(origins, ("https://app.example", "https://app.example:8443"))
        self.assertEqual(rp_id, "app.example")

    def test_webauthn_config_legacy_fallback_and_default_first_origin_rp(self):
        with self.webauthn_environment(PUBLIC_APP_ORIGIN="https://OLD.Example:443"):
            self.assertEqual(self.backend.load_webauthn_config(), (("https://old.example",), "old.example"))
        with self.webauthn_environment(
                WEBAUTHN_ALLOWED_ORIGINS="https://first.example:8443,https://unrelated.example"):
            self.assertEqual(self.backend.load_webauthn_config(),
                             (("https://first.example:8443", "https://unrelated.example"), "first.example"))

    def test_webauthn_config_explicit_parent_rp_and_unrelated_legacy_origin(self):
        with self.webauthn_environment(
                WEBAUTHN_ALLOWED_ORIGINS="https://old.example,https://app.accounts.example",
                WEBAUTHN_RP_ID="Accounts.Example"):
            self.assertEqual(self.backend.load_webauthn_config(),
                             (("https://old.example", "https://app.accounts.example"), "accounts.example"))

    def test_webauthn_config_rejects_rp_not_matching_any_origin(self):
        for rp_id in ("evil.example", "example.com", "ample.com"):
            with self.subTest(rp_id=rp_id), self.webauthn_environment(
                    WEBAUTHN_ALLOWED_ORIGINS="https://notexample.com,https://example.com.evil.test",
                    WEBAUTHN_RP_ID=rp_id):
                with self.assertRaises(ValueError):
                    self.backend.load_webauthn_config()

    def test_webauthn_config_rejects_non_domain_rp(self):
        for rp_id in ("https://hrt.example", "hrt.example:443", "hrt.example/path",
                      "*.hrt.example", "user@hrt.example", "hrt.example?x=1", "-hrt.example"):
            with self.subTest(rp_id=rp_id), self.webauthn_environment(
                    WEBAUTHN_ALLOWED_ORIGINS=ORIGIN, WEBAUTHN_RP_ID=rp_id):
                with self.assertRaises(ValueError):
                    self.backend.load_webauthn_config()

    def test_webauthn_normalize_origin_canonical_ports_and_localhost(self):
        for value, expected in (("HTTPS://HRT.Example:443", ORIGIN),
                                ("https://HRT.Example:8443", "https://hrt.example:8443"),
                                ("http://LOCALHOST:80", "http://localhost"),
                                ("http://localhost:3000", "http://localhost:3000")):
            with self.subTest(value=value):
                self.assertEqual(self.backend.normalize_origin(value), expected)

    def test_webauthn_normalize_origin_rejects_untrusted_url_components(self):
        for value in ("", "null", "*", "https://*.hrt.example", "http://hrt.example",
                      "https://hrt.example/path", "https://hrt.example?x=1",
                      "https://hrt.example#fragment", "https://user@hrt.example",
                      "https://user:password@hrt.example", "https://@hrt.example",
                      "https://hrt.example:invalid", "https://hrt.example:65536",
                      "https://hrt.example\\evil", "https://hrt.example evil"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.backend.normalize_origin(value)

    def test_webauthn_config_rejects_invalid_member_not_silently_dropping_it(self):
        for configured in (ORIGIN + ",null", ORIGIN + ",https://*.example",
                           ORIGIN + ",", ORIGIN + ",http://remote.example"):
            with self.subTest(configured=configured), self.webauthn_environment(
                    WEBAUTHN_ALLOWED_ORIGINS=configured, PUBLIC_APP_ORIGIN=ORIGIN):
                with self.assertRaises(ValueError):
                    self.backend.load_webauthn_config()

    def test_webauthn_allowed_origins_global_is_tuple(self):
        self.assertIsInstance(self.backend.ALLOWED_ORIGINS, tuple)
        self.assertEqual(self.backend.ALLOWED_ORIGINS, (ORIGIN,))
        self.assertEqual(self.backend.RP_ID, RP_ID)

    def test_webauthn_multiple_origins_share_parent_rp_real_registration_and_login(self):
        origins = (ORIGIN, "https://app.hrt.example")
        with self.webauthn_config(origins, RP_ID):
            for registration_origin in origins:
                with self.subTest(registration_origin=registration_origin):
                    authenticator, pk_id = self.enroll(origin=registration_origin)
                    self.assertEqual(self.sql("SELECT rp_id FROM passkeys WHERE id = ?", (pk_id,)), [(RP_ID,)])
                    for origin in origins:
                        options = self.auth_options(self.username, origin=origin)
                        self.assertEqual(options["rpId"], RP_ID)
                        self.assertIn(b64(authenticator.credential_id), self.credential_ids(options))
                        result = self.ok("POST", "/api/auth/passkey-verify",
                                         self.verify(authenticator, options, origin=origin), origin=origin)
                        self.assertEqual(result["user"]["id"], self.user_id)
                        self.alive(result["token"])

    def test_webauthn_subdomain_rp_with_sibling_origins_real_crypto(self):
        rp_id = "accounts.hrt.example"
        origins = ("https://one.accounts.hrt.example", "https://two.accounts.hrt.example:8443")
        with self.webauthn_config(origins, rp_id):
            authenticator, pk_id = self.enroll(origin=origins[0], rp_id=rp_id)
            self.assertEqual(self.sql("SELECT rp_id FROM passkeys WHERE id = ?", (pk_id,)), [(rp_id,)])
            options = self.auth_options(self.username, origin=origins[1])
            result = self.ok("POST", "/api/auth/passkey-verify",
                             self.verify(authenticator, options, origin=origins[1], rp_id=rp_id), origin=origins[1])
            self.alive(result["token"])

    def test_webauthn_nondefault_port_is_part_of_trusted_origin(self):
        for origin in (ORIGIN + ":8443", "https://hrt.example:80"):
            with self.subTest(origin=origin):
                self.denied("POST", "/api/user/passkey/register-options", {}, self.token, origin=origin)
                self.denied("POST", "/api/auth/passkey-options", {}, origin=origin)
        with self.webauthn_config((ORIGIN + ":8443",), RP_ID):
            self.denied("POST", "/api/auth/passkey-options", {}, origin=ORIGIN)
            self.auth_options(origin=ORIGIN + ":8443")

    def test_webauthn_default_port_request_normalizes_to_challenge_origin(self):
        options = self.register_options(origin="https://HRT.Example:443")
        self.assertEqual(self.sql("SELECT origin, rp_id FROM webauthn_challenges WHERE token = ?",
                                  (options["challengeToken"],)), [(ORIGIN, RP_ID)])

    def test_webauthn_missing_and_null_origin_rejected_all_ceremony_routes(self):
        routes = (("POST", "/api/user/passkey/register-options", self.token),
                  ("POST", "/api/user/passkey/register", self.token),
                  ("POST", "/api/auth/passkey-options", None),
                  ("GET", "/api/auth/passkey-options?username=" + quote(self.username), None),
                  ("POST", "/api/auth/passkey-verify", None))
        for origin in (None, "null"):
            for method, path, token in routes:
                with self.subTest(origin=origin, path=path):
                    self.denied(method, path, {} if method == "POST" else None, token, origin=origin)

    def test_webauthn_host_and_forwarded_headers_cannot_supply_trusted_origin(self):
        forged_headers = {"Host": RP_ID, "X-Forwarded-Host": RP_ID,
                          "X-Forwarded-Proto": "https", "X-Forwarded-Port": "443",
                          "Forwarded": "host=hrt.example;proto=https"}
        for origin in (None, "null", "https://evil.example"):
            with self.subTest(origin=origin):
                self.denied("POST", "/api/user/passkey/register-options", {}, self.token,
                            origin=origin, headers=forged_headers)
                self.denied("POST", "/api/auth/passkey-options", {}, origin=origin, headers=forged_headers)

    def test_webauthn_untrusted_host_headers_do_not_override_valid_origin_or_rp(self):
        headers = {"Host": "evil.example:8443", "X-Forwarded-Host": "evil.example",
                   "X-Forwarded-Proto": "http", "Forwarded": "host=evil.example;proto=http"}
        options = self.register_options(headers=headers)
        self.assertEqual(options["rp"]["id"], RP_ID)
        self.assertEqual(self.sql("SELECT origin, rp_id FROM webauthn_challenges WHERE token = ?",
                                  (options["challengeToken"],)), [(ORIGIN, RP_ID)])
        self.assertEqual(self.auth_options(headers=headers)["rpId"], RP_ID)

    def test_webauthn_challenges_capture_each_request_origin_and_current_rp(self):
        origins = (ORIGIN, "https://app.hrt.example")
        with self.webauthn_config(origins, RP_ID):
            for origin in origins:
                for options in (self.register_options(origin=origin), self.auth_options(origin=origin)):
                    self.assertEqual(self.sql("SELECT origin, rp_id FROM webauthn_challenges WHERE token = ?",
                                              (options["challengeToken"],)), [(origin, RP_ID)])

    def test_webauthn_registration_challenge_cannot_move_between_allowed_origins(self):
        self.crypto()
        second = "https://app.hrt.example"
        with self.webauthn_config((ORIGIN, second), RP_ID):
            for request_origin, client_origin in ((second, ORIGIN), (second, second), (ORIGIN, second)):
                with self.subTest(request_origin=request_origin, client_origin=client_origin):
                    authenticator = Authenticator()
                    options = self.register_options()
                    data = {"password": PASSWORD, "challengeToken": options["challengeToken"],
                            "credential": authenticator.registration(options, origin=client_origin)}
                    self.denied("POST", "/api/user/passkey/register", data, self.token, origin=request_origin)
                    self.assertFalse(self.sql("SELECT id FROM passkeys WHERE credential_id = ?",
                                              (b64(authenticator.credential_id),)))

    def test_webauthn_auth_challenge_cannot_move_between_allowed_origins(self):
        authenticator, _ = self.enroll()
        second = "https://app.hrt.example"
        with self.webauthn_config((ORIGIN, second), RP_ID):
            for request_origin, client_origin in ((second, ORIGIN), (second, second), (ORIGIN, second)):
                with self.subTest(request_origin=request_origin, client_origin=client_origin):
                    options = self.auth_options(self.username)
                    self.denied("POST", "/api/auth/passkey-verify",
                                self.verify(authenticator, options, origin=client_origin), origin=request_origin)

    def test_webauthn_registration_challenge_rejected_after_rp_change(self):
        self.crypto()
        origin = "https://app.hrt.example"
        for signed_rp in (RP_ID, "app.hrt.example"):
            with self.subTest(signed_rp=signed_rp):
                with self.webauthn_config((origin,), RP_ID):
                    options = self.register_options(origin=origin)
                authenticator = Authenticator()
                data = {"password": PASSWORD, "challengeToken": options["challengeToken"],
                        "credential": authenticator.registration(options, origin=origin, rp_id=signed_rp)}
                with self.webauthn_config((origin,), "app.hrt.example"):
                    self.denied("POST", "/api/user/passkey/register", data, self.token, origin=origin)
                self.assertFalse(self.sql("SELECT id FROM passkeys WHERE credential_id = ?",
                                          (b64(authenticator.credential_id),)))

    def test_webauthn_auth_challenge_rejected_after_rp_change(self):
        authenticator, pk_id = self.enroll()
        origin = "https://app.hrt.example"
        for key_rp in (RP_ID, "app.hrt.example"):
            with self.subTest(key_rp=key_rp):
                with self.webauthn_config((origin,), RP_ID):
                    options = self.auth_options(self.username, origin=origin)
                # Also test a key belonging to the new RP: stale challenge alone must fail.
                self.sql("UPDATE passkeys SET rp_id = ? WHERE id = ?", (key_rp, pk_id))
                with self.webauthn_config((origin,), "app.hrt.example"):
                    self.denied("POST", "/api/auth/passkey-verify",
                                self.verify(authenticator, options, origin=origin, rp_id=key_rp), origin=origin)

    def test_webauthn_challenge_rejected_after_origin_removed_from_config(self):
        authenticator, _ = self.enroll()
        options = self.auth_options(self.username)
        with self.webauthn_config(("https://app.hrt.example",), RP_ID):
            self.denied("POST", "/api/auth/passkey-verify", self.verify(authenticator, options))

    def test_webauthn_unrelated_allowed_old_origin_rejected_only_for_ceremonies(self):
        with self.webauthn_config((ORIGIN, "https://new.example"), "new.example"):
            for method, path, token in (("POST", "/api/user/passkey/register-options", self.token),
                                        ("POST", "/api/user/passkey/register", self.token),
                                        ("POST", "/api/auth/passkey-options", None),
                                        ("GET", "/api/auth/passkey-options", None),
                                        ("POST", "/api/auth/passkey-verify", None)):
                with self.subTest(path=path):
                    self.denied(method, path, {} if method == "POST" else None, token)
            self.alive(self.login())
            self.alive(self.token)
            self.ok("GET", "/api/user/passkeys", token=self.token)
            self.register_options(origin="https://new.example")

    def test_webauthn_unrelated_origin_never_reports_current_rp_as_usable(self):
        self.enroll()
        with self.webauthn_config((ORIGIN, 'https://new.example'), RP_ID):
            for origin, headers in (('https://new.example', {}),
                                    (None, {'Referer': 'https://new.example/account'}),
                                    ('null', {})):
                with self.subTest(origin=origin, headers=headers):
                    status = self.ok('GET', '/api/user/2fa/status', token=self.token,
                                     origin=origin, headers=headers)
                    self.assertFalse(status['passkey'])
                    self.assertFalse(status['enabled'])
                    rows = self.ok('GET', '/api/user/passkeys', token=self.token,
                                   origin=origin, headers=headers)
                    self.assertFalse(rows[0]['is_current_rp'])

    def test_webauthn_same_origin_get_uses_referer_for_parent_rp_status(self):
        self.enroll()
        with self.webauthn_config((ORIGIN, 'https://app.hrt.example'), RP_ID):
            headers = {'Referer': 'https://app.hrt.example/account'}
            status = self.ok('GET', '/api/user/2fa/status', token=self.token,
                             origin=None, headers=headers)
            self.assertTrue(status['passkey'])
            rows = self.ok('GET', '/api/user/passkeys', token=self.token,
                           origin=None, headers=headers)
            self.assertTrue(rows[0]['is_current_rp'])

    def test_webauthn_old_rp_key_hidden_from_allow_and_exclude_lists(self):
        old, _ = self.enroll()
        new_origin, new_rp = "https://new.example", "new.example"
        with self.webauthn_config((ORIGIN, new_origin), new_rp):
            options = self.auth_options(self.username, origin=new_origin)
            self.assertNotIn(b64(old.credential_id), self.credential_ids(options))
            self.assertNotIn(b64(old.credential_id), self.credential_ids(
                self.register_options(origin=new_origin), "excludeCredentialIds"))
            current, _ = self.enroll(origin=new_origin, rp_id=new_rp)
            self.assertEqual(self.credential_ids(self.auth_options(self.username, origin=new_origin)),
                             {b64(current.credential_id)})
            self.assertEqual(self.credential_ids(self.register_options(origin=new_origin), "excludeCredentialIds"),
                             {b64(current.credential_id)})

    def test_webauthn_old_rp_key_cannot_authenticate_even_with_valid_current_rp_signature(self):
        old, _ = self.enroll()
        new_origin, new_rp = "https://new.example", "new.example"
        with self.webauthn_config((new_origin,), new_rp):
            for username in (None, self.username):
                for signed_rp in (RP_ID, new_rp):
                    with self.subTest(username=username, signed_rp=signed_rp):
                        options = self.auth_options(username, origin=new_origin)
                        self.denied("POST", "/api/auth/passkey-verify",
                                    self.verify(old, options, origin=new_origin, rp_id=signed_rp), origin=new_origin)

    def test_webauthn_rp_change_status_excludes_old_key_and_enrollment_restores_it(self):
        self.enroll()
        with self.webauthn_config(("https://new.example",), "new.example"):
            status = self.ok("GET", "/api/user/2fa/status", token=self.token, origin="https://new.example")
            self.assertFalse(status["passkey"])
            self.assertFalse(status["enabled"])
            self.enroll(origin="https://new.example", rp_id="new.example")
            status = self.ok("GET", "/api/user/2fa/status", token=self.token, origin="https://new.example")
            self.assertTrue(status["passkey"])
            self.assertTrue(status["enabled"])

    def test_webauthn_migration_password_totp_backup_login_and_new_enrollment(self):
        self.enroll()
        self.enable()
        codes = self.ok("POST", "/api/user/2fa/backup-codes/generate",
                        {"password": PASSWORD, "code": totp(SECRET)}, self.token)["codes"]
        new_origin, new_rp = "https://new.example", "new.example"
        with self.webauthn_config((ORIGIN, new_origin), new_rp):
            self.denied("POST", "/api/login", {"username": self.username, "password": PASSWORD}, origin=new_origin)
            for login_origin in (ORIGIN, new_origin):
                result = self.ok("POST", "/api/login", {"username": self.username,
                                 "password": PASSWORD, "totp_code": self.advance_totp()}, origin=login_origin)
                self.alive(result["token"])
            result = self.ok("POST", "/api/login", {"username": self.username,
                             "password": PASSWORD, "backup_code": codes[0]}, origin=new_origin)
            self.alive(result["token"])
            self.denied("POST", "/api/login", {"username": self.username,
                        "password": PASSWORD, "backup_code": codes[0]}, origin=new_origin)
            status = self.ok("GET", "/api/user/2fa/status", token=self.token, origin=new_origin)
            self.assertTrue(status["totp"])
            self.assertTrue(status["enabled"])
            self.assertFalse(status["passkey"])
            current, _ = self.enroll({"code": self.advance_totp()}, origin=new_origin, rp_id=new_rp)
            options = self.auth_options(self.username, origin=new_origin)
            result = self.ok("POST", "/api/auth/passkey-verify",
                             self.verify(current, options, origin=new_origin, rp_id=new_rp), origin=new_origin)
            self.alive(result["token"])
            self.alive(self.token)

    def test_webauthn_passkey_list_retains_old_rp_metadata_and_boolean_current_flag(self):
        _, old_id = self.enroll()
        with self.webauthn_config(("https://new.example",), "new.example"):
            _, current_id = self.enroll(origin="https://new.example", rp_id="new.example")
            rows = self.ok("GET", "/api/user/passkeys", token=self.token, origin="https://new.example")
            by_id = {row["id"]: row for row in rows}
            self.assertEqual(set(by_id), {old_id, current_id})
            self.assertEqual(by_id[old_id]["rp_id"], RP_ID)
            self.assertIs(by_id[old_id]["is_current_rp"], False)
            self.assertEqual(by_id[current_id]["rp_id"], "new.example")
            self.assertIs(by_id[current_id]["is_current_rp"], True)

    def test_webauthn_old_rp_passkey_remains_manageable_with_password_and_totp(self):
        _, pk_id = self.enroll()
        self.enable()
        with self.webauthn_config(("https://new.example",), "new.example"):
            path = "/api/user/passkeys/" + quote(pk_id, safe="")
            self.denied("DELETE", path, {"password": PASSWORD}, self.token, origin="https://new.example")
            self.ok("DELETE", path, {"password": PASSWORD, "code": totp(SECRET)}, self.token,
                    origin="https://new.example")
            self.assertFalse(self.sql("SELECT id FROM passkeys WHERE id = ?", (pk_id,)))
            self.alive(self.token)

    def test_webauthn_null_rp_public_key_visible_but_never_current_or_usable(self):
        authenticator, pk_id = self.enroll()
        self.sql("UPDATE passkeys SET rp_id = NULL WHERE id = ?", (pk_id,))
        status = self.ok("GET", "/api/user/2fa/status", token=self.token)
        self.assertFalse(status["passkey"])
        self.assertFalse(status["enabled"])
        rows = self.ok("GET", "/api/user/passkeys", token=self.token)
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["rp_id"])
        self.assertIs(rows[0]["is_current_rp"], False)
        self.assertFalse(self.credential_ids(self.register_options(), "excludeCredentialIds"))
        options = self.auth_options(self.username)
        self.assertFalse(self.credential_ids(options))
        self.denied("POST", "/api/auth/passkey-verify", self.verify(authenticator, options))

    def test_webauthn_schema_migration_prefers_public_origin_over_challenge_rp(self):
        with self.migration_database(challenge_rps=("challenge.example",),
                                     public_origin="https://OLD.Example:443") as (_, pk_id):
            self.backend.init_db()
            self.assertEqual(self.sql("SELECT rp_id FROM passkeys WHERE id = ?", (pk_id,)), [("old.example",)])

    def test_webauthn_schema_migration_does_not_infer_keys_from_temporary_challenges(self):
        with self.migration_database(challenge_rps=(RP_ID, RP_ID)) as (_, pk_id):
            self.backend.init_db()
            self.assertEqual(self.sql("SELECT rp_id FROM passkeys WHERE id = ?", (pk_id,)), [(None,)])

    def test_webauthn_schema_migration_unknown_rp_stays_null_after_config_change(self):
        with self.migration_database() as (_, pk_id):
            self.backend.init_db()
            self.assertEqual(self.sql("SELECT rp_id FROM passkeys WHERE id = ?", (pk_id,)), [(None,)])
            with self.webauthn_environment(PUBLIC_APP_ORIGIN=ORIGIN):
                self.backend.init_db()
            self.assertEqual(self.sql("SELECT rp_id FROM passkeys WHERE id = ?", (pk_id,)), [(None,)])

    def test_webauthn_schema_migration_ambiguous_challenge_rps_remain_null(self):
        with self.migration_database(challenge_rps=(RP_ID, "other.example")) as (_, pk_id):
            self.backend.init_db()
            self.assertEqual(self.sql("SELECT rp_id FROM passkeys WHERE id = ?", (pk_id,)), [(None,)])

    def test_webauthn_schema_migration_existing_rp_and_null_are_never_rewritten(self):
        for rp_id in (RP_ID, None):
            with self.subTest(rp_id=rp_id):
                with self.migration_database(public_origin="https://new.example", existing_rp=True) as (_, pk_id):
                    self.sql("UPDATE passkeys SET rp_id = ? WHERE id = ?", (rp_id, pk_id))
                    self.backend.init_db()
                    self.backend.init_db()
                    self.assertEqual(self.sql("SELECT rp_id FROM passkeys WHERE id = ?", (pk_id,)), [(rp_id,)])

    def test_webauthn_schema_migration_once_preserves_sessions_signkey_and_security_data(self):
        self.enable()
        with self.migration_database(public_origin=ORIGIN) as (_, pk_id):
            key = self.backend.SESSION_SIGNING_KEY
            queries = ("SELECT * FROM users ORDER BY id", "SELECT * FROM sessions ORDER BY token",
                       "SELECT * FROM server_settings ORDER BY key", "SELECT * FROM backups ORDER BY id",
                       "SELECT * FROM webauthn_challenges ORDER BY token",
                       "SELECT id, user_id, credential_id, device_name, created_at, public_key, sign_count "
                       "FROM passkeys ORDER BY id")
            before = [self.sql(query) for query in queries]
            self.backend.init_db()
            self.assertEqual(self.backend.SESSION_SIGNING_KEY, key)
            self.assertEqual([self.sql(query) for query in queries], before)
            self.assertEqual(self.sql("SELECT rp_id FROM passkeys WHERE id = ?", (pk_id,)), [(RP_ID,)])
            with self.webauthn_environment(PUBLIC_APP_ORIGIN="https://new.example"):
                self.backend.init_db()
            self.assertEqual(self.backend.SESSION_SIGNING_KEY, key)
            self.assertEqual([self.sql(query) for query in queries], before)
            self.assertEqual(self.sql("SELECT rp_id FROM passkeys WHERE id = ?", (pk_id,)), [(RP_ID,)])
            self.alive(self.token)
            self.assertEqual(self.stored_secret(), SECRET)
            self.alive(self.login(totp_code=self.advance_totp()))

    def test_direct_passkey_options_require_user_verification(self):
        self.enroll()
        for username in (None, self.username):
            with self.subTest(username=username):
                options = self.auth_options(username)
                self.assertEqual(options["userVerification"], "required")
                self.assertEqual(self.sql("SELECT purpose FROM webauthn_challenges WHERE token = ?",
                                          (options["challengeToken"],)), [("authenticate",)])

    def test_direct_passkey_rejects_real_up_only_signature(self):
        authenticator, _ = self.enroll()
        for username in (None, self.username):
            with self.subTest(username=username):
                options = self.auth_options(username)
                proof = self.verify(authenticator, options, user_verified=False)
                self.assertEqual(unb64(proof["credential"]["response"]["authenticatorData"])[32], 1)
                self.denied("POST", "/api/auth/passkey-verify", proof)

    def test_direct_passkey_client_preference_tampering_cannot_disable_uv(self):
        authenticator, _ = self.enroll()
        for preference in ("preferred", "discouraged"):
            with self.subTest(preference=preference):
                options = self.auth_options(self.username)
                options["userVerification"] = preference
                proof = self.verify(authenticator, options, user_verified=False)
                proof.update({"userVerification": preference, "requireUV": False,
                              "require_user_verification": False})
                self.denied("POST", "/api/auth/passkey-verify", proof)

    def test_passkey_only_password_login_reports_actual_methods(self):
        self.enroll()
        self.assertFalse(self.stored_secret())
        payload = self.factor_denied("login")
        self.assertTrue(payload["needs2FA"])
        self.assertEqual(payload["methods"], ["passkey"])

    def test_totp_only_password_login_reports_actual_methods(self):
        self.enable()
        payload = self.factor_denied("login")
        self.assertTrue(payload["needs2FA"])
        self.assertEqual(payload["methods"], ["totp"])
        self.factor_ok("login", extra={"totp_code": totp(SECRET)})

    def test_both_factors_password_login_reports_both_methods(self):
        authenticator, _ = self.enroll()
        self.enable()
        payload = self.factor_denied("login")
        self.assertTrue(payload["needs2FA"])
        self.assertEqual(payload["methods"], ["totp", "passkey"])
        self.factor_ok("login", extra={"totp_code": totp(SECRET)})
        self.factor_ok("login", proof=self.verify(authenticator, self.login_options(), user_verified=False))

    def test_login_passkey_options_require_correct_first_factor(self):
        self.enroll()
        for data in ({"purpose": "login", "username": self.username},
                     {"purpose": "login", "username": self.username, "password": "wrong"},
                     {"purpose": "login", "username": "missing_" + uuid.uuid4().hex, "password": PASSWORD},
                     {"purpose": "login", "password": PASSWORD}):
            with self.subTest(fields=data):
                before = self.sql("SELECT token FROM webauthn_challenges ORDER BY token")
                payload = self.denied("POST", "/api/auth/passkey-options", data, self.token)
                self.assertNotIn("challengeToken", payload)
                self.assertEqual(self.sql("SELECT token FROM webauthn_challenges ORDER BY token"), before)

    def test_login_passkey_options_are_account_bound_and_preferred(self):
        authenticator, _ = self.enroll()
        options = self.login_options()
        self.assertEqual(options["userVerification"], "preferred")
        self.assertEqual(self.credential_ids(options), {b64(authenticator.credential_id)})
        row = self.sql("SELECT purpose, user_id, session_id, origin, rp_id FROM webauthn_challenges "
                       "WHERE token = ?", (options["challengeToken"],))
        self.assertEqual(row, [("login", self.user_id, None, ORIGIN, RP_ID)])

    def test_password_plus_passkey_accepts_real_up_only_signature(self):
        authenticator, _ = self.enroll()
        proof = self.verify(authenticator, self.login_options(), user_verified=False)
        self.factor_ok("login", proof=proof)
        self.assertFalse(self.sql("SELECT token FROM webauthn_challenges WHERE token = ?",
                                  (proof["challengeToken"],)))

    def test_password_plus_passkey_login_challenge_is_one_use(self):
        authenticator, _ = self.enroll()
        proof = self.verify(authenticator, self.login_options(), user_verified=False)
        self.factor_ok("login", proof=proof)
        self.factor_denied("login", proof=proof)

    def test_login_challenge_cannot_use_direct_verify_even_with_uv(self):
        authenticator, _ = self.enroll()
        for user_verified in (False, True):
            with self.subTest(user_verified=user_verified):
                proof = self.verify(authenticator, self.login_options(), user_verified=user_verified)
                self.denied("POST", "/api/auth/passkey-verify", proof)

    def test_direct_challenge_cannot_replace_login_second_factor(self):
        authenticator, _ = self.enroll()
        proof = self.verify(authenticator, self.auth_options(self.username))
        self.factor_denied("login", proof=proof)

    def test_direct_login_session_token_cannot_replace_raw_factor_proof(self):
        authenticator, _ = self.enroll()
        result = self.ok("POST", "/api/auth/passkey-verify",
                         self.verify(authenticator, self.auth_options(self.username)))
        for purpose in ("login", "password", "delete"):
            for proof in (result["token"], {"token": result["token"]},
                          {"proofToken": result["token"]}):
                with self.subTest(purpose=purpose, shape=type(proof).__name__):
                    self.factor_denied(purpose, proof=proof)

    def test_sensitive_options_require_session_password_and_valid_purpose(self):
        self.enroll()
        for purpose in ("password", "delete"):
            for token, data in ((None, {"purpose": purpose, "password": PASSWORD}),
                                (self.token, {"purpose": purpose}),
                                (self.token, {"purpose": purpose, "password": "wrong"})):
                with self.subTest(purpose=purpose, authenticated=bool(token), fields=data):
                    payload = self.denied("POST", "/api/user/passkey/auth-options", data, token)
                    self.assertNotIn("challengeToken", payload)
        for purpose in (None, "login", "authenticate", "register", "invalid"):
            with self.subTest(purpose=purpose):
                self.denied("POST", "/api/user/passkey/auth-options",
                            {"purpose": purpose, "password": PASSWORD}, self.token)
        for purpose in ("password", "delete", "register", "invalid"):
            with self.subTest(public_purpose=purpose):
                self.denied("POST", "/api/auth/passkey-options",
                            {"purpose": purpose, "username": self.username, "password": PASSWORD})

    def test_sensitive_options_bind_user_session_purpose_and_prefer_uv(self):
        authenticator, _ = self.enroll()
        for purpose in ("password", "delete"):
            with self.subTest(purpose=purpose):
                options = self.sensitive_options(purpose)
                self.assertEqual(options["userVerification"], "preferred")
                self.assertEqual(self.credential_ids(options), {b64(authenticator.credential_id)})
                self.assertEqual(self.sql("SELECT purpose, user_id, session_id, origin, rp_id "
                                          "FROM webauthn_challenges WHERE token = ?",
                                          (options["challengeToken"],)),
                                 [(purpose, self.user_id, self.sid(self.token), ORIGIN, RP_ID)])

    def test_passkey_only_sensitive_operations_require_factor(self):
        self.enroll()
        for purpose in ("password", "delete"):
            with self.subTest(purpose=purpose):
                payload = self.factor_denied(purpose)
                self.assertTrue(payload["needs2FA"])
                self.assertEqual(payload["methods"], ["passkey"])

    def test_sensitive_password_change_accepts_up_only_and_revokes_other_sessions(self):
        other = self.login()
        authenticator, _ = self.enroll()
        proof = self.verify(authenticator, self.sensitive_options("password"), user_verified=False)
        self.factor_ok("password", proof=proof)
        self.expired(other)
        self.factor_denied("login", password=PASSWORD)
        self.factor_ok("login", password=NEW_PASSWORD,
                       proof=self.verify(authenticator, self.login_options(password=NEW_PASSWORD), user_verified=False))

    def test_sensitive_password_change_challenge_replay_rejected(self):
        authenticator, _ = self.enroll()
        proof = self.verify(authenticator, self.sensitive_options("password"), user_verified=False)
        self.factor_ok("password", proof=proof)
        self.assertFalse(self.sql("SELECT token FROM webauthn_challenges WHERE token = ?",
                                  (proof["challengeToken"],)))
        self.factor_denied("password", password=NEW_PASSWORD, proof=proof)

    def test_sensitive_delete_accepts_up_only_and_revokes_all_sessions(self):
        other = self.login()
        authenticator, _ = self.enroll()
        proof = self.verify(authenticator, self.sensitive_options("delete"), user_verified=False)
        self.factor_ok("delete", proof=proof)
        self.expired(other)
        self.denied("DELETE", "/api/user/me", {"password": PASSWORD, "passkey": proof}, self.token)

    def test_sensitive_final_request_still_requires_current_password(self):
        authenticator, _ = self.enroll()
        for purpose in ("login", "password", "delete"):
            for password in ("", "wrong"):
                with self.subTest(purpose=purpose, password=password):
                    proof = self.verify(authenticator, self.factor_options(purpose), user_verified=False)
                    self.factor_denied(purpose, proof=proof, password=password)

    def test_factor_challenges_cannot_cross_purposes(self):
        authenticator, _ = self.enroll()
        for source in ("login", "password", "delete"):
            for target in ("login", "password", "delete"):
                if source == target:
                    continue
                with self.subTest(source=source, target=target):
                    proof = self.verify(authenticator, self.factor_options(source))
                    self.factor_denied(target, proof=proof)
        for purpose in ("password", "delete"):
            for options in (self.auth_options(self.username), self.register_options()):
                with self.subTest(target=purpose, token=options["challengeToken"]):
                    self.factor_denied(purpose, proof=self.verify(authenticator, options))

    def test_sensitive_challenges_cannot_use_direct_verify(self):
        authenticator, _ = self.enroll()
        for purpose in ("password", "delete"):
            with self.subTest(purpose=purpose):
                self.denied("POST", "/api/auth/passkey-verify",
                            self.verify(authenticator, self.sensitive_options(purpose)))

    def test_sensitive_challenges_reject_other_session_of_same_user(self):
        other = self.login()
        authenticator, _ = self.enroll()
        for purpose in ("password", "delete"):
            with self.subTest(purpose=purpose):
                proof = self.verify(authenticator, self.sensitive_options(purpose), user_verified=False)
                self.factor_denied(purpose, proof=proof, token=other)
                self.alive(other)

    def test_factor_challenges_reject_foreign_credential(self):
        self.enroll()
        stranger = self.ok("POST", "/api/register",
                           {"username": uuid.uuid4().hex, "password": PASSWORD})
        authenticator = Authenticator()
        options = self.ok("POST", "/api/user/passkey/register-options", {}, stranger["token"])
        self.ok("POST", "/api/user/passkey/register",
                {"password": PASSWORD, "challengeToken": options["challengeToken"],
                 "credential": authenticator.registration(options)}, stranger["token"])
        for purpose in ("login", "password", "delete"):
            with self.subTest(purpose=purpose):
                self.factor_denied(purpose, proof=self.verify(authenticator, self.factor_options(purpose)))

    def test_factor_challenges_reject_other_account_binding(self):
        authenticator, _ = self.enroll()
        stranger_name = uuid.uuid4().hex
        stranger = self.ok("POST", "/api/register", {"username": stranger_name, "password": PASSWORD})
        for purpose in ("login", "password", "delete"):
            with self.subTest(purpose=purpose):
                if purpose == "login":
                    options = self.ok("POST", "/api/auth/passkey-options",
                                      {"purpose": purpose, "username": stranger_name, "password": PASSWORD})
                else:
                    options = self.sensitive_options(purpose, token=stranger["token"])
                self.factor_denied(purpose, proof=self.verify(authenticator, options))

    def test_factor_challenges_reject_expiration(self):
        authenticator, _ = self.enroll()
        for purpose in ("login", "password", "delete"):
            with self.subTest(purpose=purpose):
                options = self.factor_options(purpose)
                self.sql("UPDATE webauthn_challenges SET expires_at = ? WHERE token = ?",
                         (int(time.time()) - 60, options["challengeToken"]))
                self.factor_denied(purpose, proof=self.verify(authenticator, options))

    def test_factor_challenges_reject_invalid_crypto(self):
        authenticator, _ = self.enroll()
        for purpose in ("login", "password", "delete"):
            for kwargs in ({"bad_signature": True}, {"rp_id": "evil.example"},
                           {"origin": "https://evil.example"}):
                with self.subTest(purpose=purpose, kwargs=kwargs):
                    self.factor_denied(purpose, proof=self.verify(authenticator, self.factor_options(purpose),
                                                                  user_verified=False, **kwargs))

    def test_factor_challenges_reject_assertion_for_different_challenge(self):
        authenticator, _ = self.enroll()
        for purpose in ("login", "password", "delete"):
            with self.subTest(purpose=purpose):
                proof = self.verify(authenticator, self.factor_options(purpose))
                proof["challengeToken"] = self.factor_options(purpose)["challengeToken"]
                self.factor_denied(purpose, proof=proof)

    def test_factor_challenges_cannot_move_between_allowed_origins(self):
        authenticator, _ = self.enroll()
        second = "https://app.hrt.example"
        with self.webauthn_config((ORIGIN, second), RP_ID):
            for purpose in ("login", "password", "delete"):
                for request_origin, client_origin in ((second, ORIGIN), (second, second), (ORIGIN, second)):
                    with self.subTest(purpose=purpose, request_origin=request_origin, client_origin=client_origin):
                        proof = self.verify(authenticator, self.factor_options(purpose), origin=client_origin)
                        self.factor_denied(purpose, proof=proof, origin=request_origin)

    def test_factor_challenges_reject_changed_rp_even_for_rebound_key(self):
        authenticator, pk_id = self.enroll()
        origin = "https://app.hrt.example"
        for purpose in ("login", "password", "delete"):
            with self.subTest(purpose=purpose):
                self.sql("UPDATE passkeys SET rp_id = ? WHERE id = ?", (RP_ID, pk_id))
                with self.webauthn_config((origin,), RP_ID):
                    options = self.factor_options(purpose, origin=origin)
                self.sql("UPDATE passkeys SET rp_id = ? WHERE id = ?", ("app.hrt.example", pk_id))
                with self.webauthn_config((origin,), "app.hrt.example"):
                    proof = self.verify(authenticator, options, origin=origin, rp_id="app.hrt.example")
                    self.factor_denied(purpose, proof=proof, origin=origin)

    def test_factor_proof_requires_credential_not_just_identifier_or_token(self):
        authenticator, _ = self.enroll()
        for purpose in ("login", "password", "delete"):
            for shape in ("token", "id", "missing-token"):
                with self.subTest(purpose=purpose, shape=shape):
                    options = self.factor_options(purpose)
                    proof = self.verify(authenticator, options)
                    if shape == "token":
                        proof.pop("credential")
                    elif shape == "id":
                        proof["credential"] = {"id": b64(authenticator.credential_id)}
                    else:
                        proof.pop("challengeToken")
                    self.factor_denied(purpose, proof=proof)

    def test_passkey_factor_invalid_attempt_consumes_challenge(self):
        authenticator, _ = self.enroll()
        for purpose in ("login", "password", "delete"):
            with self.subTest(purpose=purpose):
                options = self.factor_options(purpose)
                self.factor_denied(purpose, proof=self.verify(authenticator, options, bad_signature=True))
                self.factor_denied(purpose, proof=self.verify(authenticator, options))

    def test_old_sensitive_challenges_cannot_survive_password_change(self):
        authenticator, _ = self.enroll()
        stale = {purpose: self.verify(authenticator, self.sensitive_options(purpose), user_verified=False)
                 for purpose in ("password", "delete")}
        fresh = self.verify(authenticator, self.sensitive_options("password"), user_verified=False)
        self.factor_ok("password", proof=fresh)
        for purpose, proof in stale.items():
            with self.subTest(purpose=purpose):
                self.factor_denied(purpose, proof=proof, password=NEW_PASSWORD)

    def test_totp_can_replace_passkey_for_sensitive_password_change(self):
        self.enroll()
        self.enable()
        self.factor_ok("password", extra={"code": totp(SECRET)})
        self.factor_ok("login", password=NEW_PASSWORD, extra={"totp_code": self.advance_totp()})

    def test_totp_can_replace_passkey_for_sensitive_delete(self):
        self.enroll()
        self.enable()
        self.factor_ok("delete", extra={"code": totp(SECRET)})

    def test_passkey_can_replace_totp_for_sensitive_password_change(self):
        authenticator, _ = self.enroll()
        self.enable()
        self.factor_ok("password", proof=self.verify(authenticator, self.sensitive_options("password"),
                                                     user_verified=False))

    def test_passkey_can_replace_totp_for_sensitive_delete(self):
        authenticator, _ = self.enroll()
        self.enable()
        self.factor_ok("delete", proof=self.verify(authenticator, self.sensitive_options("delete"),
                                                   user_verified=False))

    def test_backup_code_can_replace_passkey_for_login_and_is_one_use(self):
        self.enroll()
        code = self.backup_codes()[0]
        self.factor_ok("login", extra={"backup_code": code})
        self.factor_denied("login", extra={"backup_code": code})

    def test_backup_code_can_replace_passkey_for_password_change_and_is_one_use(self):
        self.enroll()
        code = self.backup_codes()[0]
        self.factor_ok("password", extra={"backup_code": code})
        self.factor_denied("password", password=NEW_PASSWORD, extra={"backup_code": code})

    def test_backup_code_can_replace_passkey_for_account_delete(self):
        self.enroll()
        self.factor_ok("delete", extra={"backup_code": self.backup_codes()[0]})

    def test_invalid_totp_and_backup_codes_cannot_bypass_passkey_only_factor(self):
        self.enroll()
        for purpose in ("login", "password", "delete"):
            for extra in ({"code": totp(SECRET)}, {"totp_code": totp(SECRET)},
                          {"backup_code": "NOT-A-VALID-RECOVERY-CODE"}):
                with self.subTest(purpose=purpose, extra=extra):
                    self.factor_denied(purpose, extra=extra)

    def test_first_passkey_enrollment_issues_recovery_codes_without_overwriting_existing_codes(self):
        self.enroll()
        codes = self.sql('SELECT backup_codes FROM users WHERE id = ?', (self.user_id,))[0][0]
        self.assertEqual(len(json.loads(codes)), 8)
        self.enroll()
        self.assertEqual(self.sql('SELECT backup_codes FROM users WHERE id = ?', (self.user_id,))[0][0], codes)

    def test_no_factor_account_password_change_still_works(self):
        self.factor_ok("password")
        self.alive(self.login(NEW_PASSWORD))

    def test_no_factor_account_delete_still_works(self):
        self.factor_ok("delete")


class AuthProtectionTests(SecurityHTTPCase):
    def test_login_and_passkey_options_share_normalized_account_budget(self):
        for index in range(10):
            path = '/api/login' if index % 2 == 0 else '/api/auth/passkey-options'
            status, _, _ = self.request('POST', path, {
                'username': self.username.upper(), 'password': 'incorrect', 'purpose': 'login'})
            self.assertEqual(status, 401)
        status, headers, body = self.request('POST', '/api/login', {
            'username': self.username, 'password': PASSWORD})
        self.assertEqual(status, 429, body)
        self.assertTrue(1 <= int(headers['retry-after']) <= 60)
        self.assertEqual(body['code'], 'RATE_LIMITED')
        with self.server_clock(time.time() + 61):
            self.alive(self.login())

    def test_ip_budget_ignores_untrusted_forwarding_headers(self):
        for index in range(59):
            status, _, _ = self.request('POST', '/api/auth/passkey-verify', {},
                headers={'X-Forwarded-For': f'192.0.2.{index + 1}', 'X-Real-IP': f'192.0.2.{index + 1}'})
            self.assertEqual(status, 401)
        status, headers, _ = self.request('POST', '/api/register', {})
        self.assertEqual(status, 429)
        self.assertIn('retry-after', headers)

    def test_authenticated_operations_share_user_budget_across_sessions(self):
        other_token = self.login()
        paths = ['/api/user/2fa/setup', '/api/user/passkey/register-options']
        for index in range(10):
            self.ok('POST', paths[index % 2], {}, self.token if index % 2 else other_token)
        status, _, _ = self.request('POST', '/api/user/password', {
            'currentPassword': PASSWORD, 'newPassword': NEW_PASSWORD}, self.token)
        self.assertEqual(status, 429)
        self.alive(self.token)

    def test_durable_bucket_is_atomic_and_expires(self):
        def attempt(_):
            return self.backend.check_auth_rate_limit('test', self.user_id, 10, now=100)
        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(attempt, range(24)))
        self.assertEqual(results.count(0), 10)
        self.assertEqual(results.count(60), 14)
        self.assertEqual(self.backend.check_auth_rate_limit('test', self.user_id, 10, now=160), 0)

    def test_proxy_trust_strips_only_trusted_rightmost_hops(self):
        with patch.object(self.backend, 'TRUSTED_PROXY_CIDRS',
                          (ipaddress.ip_network('10.0.0.0/8'),)):
            ip = self.backend.auth_client_ip
            self.assertEqual(ip('192.0.2.1', '198.51.100.1'), '192.0.2.1')
            self.assertEqual(ip('10.0.0.1', '198.51.100.1, 192.0.2.1, 10.0.0.2'), '192.0.2.1')
            self.assertEqual(ip('10.0.0.1', 'invalid, 192.0.2.1'), '10.0.0.1')
            self.assertEqual(ip('10.0.0.1', '198.51.100.1'), '198.51.100.1')

    def test_enrollment_consumes_setup_step_and_replacement_resets_high_water(self):
        step = int(time.time() // 30)
        with self.server_clock(step * 30 + 5):
            self.ok('POST', '/api/user/2fa/enable', {
                'password': PASSWORD, 'secret': SECRET, 'code': totp(SECRET, step)}, self.token)
            self.denied('POST', '/api/login', {
                'username': self.username, 'password': PASSWORD, 'code': totp(SECRET, step)})
            self.ok('POST', '/api/user/2fa/enable', {
                'password': PASSWORD, 'currentCode': totp(SECRET, step + 1),
                'secret': NEW_SECRET, 'code': totp(NEW_SECRET, step - 1)}, self.token)
            self.assertEqual(self.sql('SELECT totp_last_step FROM users WHERE id = ?',
                                     (self.user_id,))[0][0], step - 1)
            self.alive(self.login(code=totp(NEW_SECRET, step)))

    def test_concurrent_totp_login_has_one_winner(self):
        self.enable()
        code = totp(SECRET)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.request('POST', '/api/login', {
                'username': self.username, 'password': PASSWORD, 'code': code})[0], range(2)))
        self.assertEqual(sorted(results), [200, 401])

    def test_totp_requires_six_ascii_digits_in_a_string(self):
        for code in ['１２３４５６', '123456\n', 123456, '12345', '1234567']:
            with self.subTest(code=code):
                self.assertIsNone(self.backend.match_totp_step(SECRET, code))


if __name__ == "__main__":
    unittest.main()
