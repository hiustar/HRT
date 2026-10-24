-- Short-lived, single-use WebAuthn authentication challenges. No runtime DDL.
CREATE TABLE IF NOT EXISTS auth_challenges (
    token_hash TEXT PRIMARY KEY,
    payload_json TEXT NOT NULL,
    user_id TEXT,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_challenges_expiry ON auth_challenges(expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_challenges_user ON auth_challenges(user_id);

-- Password changes (including administrator resets) invalidate pending proofs.
CREATE TRIGGER IF NOT EXISTS invalidate_auth_challenges_on_password_change
AFTER UPDATE OF password_hash ON users
WHEN OLD.password_hash IS NOT NEW.password_hash
BEGIN
    DELETE FROM auth_challenges WHERE user_id = NEW.id;
END;
CREATE TRIGGER IF NOT EXISTS delete_user_auth_challenges
AFTER DELETE ON users
BEGIN
    DELETE FROM auth_challenges WHERE user_id = OLD.id;
END;

CREATE TRIGGER IF NOT EXISTS delete_user_auth_data
BEFORE DELETE ON users
BEGIN
    DELETE FROM dosage_shares WHERE user_id = OLD.id;
    DELETE FROM content WHERE user_id = OLD.id;
    DELETE FROM sessions WHERE user_id = OLD.id;
    DELETE FROM passkeys WHERE user_id = OLD.id;
    DELETE FROM backup_codes WHERE user_id = OLD.id;
END;
