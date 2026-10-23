#!/usr/bin/env python3
"""HTTP regressions using a temporary database and real WebAuthn signatures."""

import base64
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from contextlib import closing
import hashlib
import hmac
import http.client
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import struct
import sys
import tempfile
import threading
import time
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
                  bad_signature=False, user_id=None):
        client = self.client_data("webauthn.get", options["challenge"], origin)
        auth = (hashlib.sha256(rp_id.encode()).digest() + b"\x05" +
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


class ServerSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="hrt-security-")
        cls.old_env = {name: os.environ.get(name)
                       for name in ("PERSIST_DIR", "PUBLIC_APP_ORIGIN")}
        os.environ["PERSIST_DIR"] = cls.temp.name
        os.environ["PUBLIC_APP_ORIGIN"] = ORIGIN
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
        # Each test gets its own account; no shared state or execution-order dependency.
        self.username = "security_" + uuid.uuid4().hex
        result = self.ok("POST", "/api/register",
                         {"username": self.username, "password": PASSWORD})
        self.token = result["token"]
        self.user_id = result["user"]["id"]

    def request(self, method, path, data=None, token=None, origin=ORIGIN):
        headers = {"Origin": origin, "Accept": "application/json"}
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

    def enable(self, secret=SECRET):
        return self.ok("POST", "/api/user/2fa/enable",
                       {"password": PASSWORD, "secret": secret, "code": totp(secret)}, self.token)

    def crypto(self):
        if not CRYPTO_AVAILABLE:
            self.skipTest("requires real webauthn, cryptography and cbor2 dependencies")

    def register_options(self):
        return self.ok("POST", "/api/user/passkey/register-options", {}, self.token)

    def enroll(self, proof=None):
        self.crypto()
        authenticator = Authenticator()
        options = self.register_options()
        data = {"password": PASSWORD, "credential": authenticator.registration(options),
                "challengeToken": options["challengeToken"], "deviceName": "Security test ES256"}
        if proof:
            data.update(proof)
        result = self.ok("POST", "/api/user/passkey/register", data, self.token)
        row = self.sql("SELECT id FROM passkeys WHERE credential_id = ?",
                       (b64(authenticator.credential_id),))
        self.assertEqual(len(row), 1, result)
        return authenticator, row[0][0]

    def auth_options(self, username=None):
        return self.ok("POST", "/api/auth/passkey-options",
                       {} if username is None else {"username": username})

    def verify(self, authenticator, options, **kwargs):
        return {"challengeToken": options["challengeToken"],
                "credential": authenticator.assertion(options, **kwargs)}

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


if __name__ == "__main__":
    unittest.main()
