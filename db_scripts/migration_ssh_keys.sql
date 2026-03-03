-- Migration: Add ssh_keys table for dynamic key management
-- This enables multiple keys per user with TTL support

-- Create ssh_keys table
CREATE TABLE IF NOT EXISTS ssh_keys (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP,  -- NULL = permanent, otherwise auto-expire
    revoked_at TIMESTAMP,  -- Manual revocation timestamp
    last_used_at TIMESTAMP, -- Track usage for audit
    comment TEXT,          -- Optional description (e.g., "Work laptop", "Home desktop")
    CONSTRAINT valid_dates CHECK (
        (expires_at IS NULL OR expires_at > created_at) AND
        (revoked_at IS NULL OR revoked_at > created_at)
    )
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_ssh_keys_user_active 
    ON ssh_keys(user_id) 
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_ssh_keys_fingerprint 
    ON ssh_keys(fingerprint);

CREATE INDEX IF NOT EXISTS idx_ssh_keys_expires 
    ON ssh_keys(expires_at) 
    WHERE expires_at IS NOT NULL;

-- Migrate existing keys from users table to ssh_keys table
INSERT INTO ssh_keys (user_id, public_key, fingerprint, comment)
SELECT 
    id,
    ssh_public_key,
    ssh_key_fingerprint,
    'Migrated from users table on ' || NOW()::DATE
FROM users
WHERE ssh_public_key IS NOT NULL
ON CONFLICT (fingerprint) DO NOTHING;

-- Create a view for active keys (commonly used query)
CREATE OR REPLACE VIEW active_ssh_keys AS
SELECT 
    k.id,
    k.user_id,
    u.username,
    k.public_key,
    k.fingerprint,
    k.created_at,
    k.expires_at,
    k.last_used_at,
    k.comment,
    CASE 
        WHEN k.revoked_at IS NOT NULL THEN 'revoked'
        WHEN k.expires_at IS NOT NULL AND k.expires_at < NOW() THEN 'expired'
        ELSE 'active'
    END as status
FROM ssh_keys k
JOIN users u ON u.id = k.user_id
WHERE k.revoked_at IS NULL
  AND (k.expires_at IS NULL OR k.expires_at > NOW());

-- Optional: Keep old columns for backwards compatibility or remove them
-- Uncomment the lines below if you want to remove old columns:
-- ALTER TABLE users DROP COLUMN IF EXISTS ssh_public_key;
-- ALTER TABLE users DROP COLUMN IF EXISTS ssh_key_fingerprint;

-- Grant permissions (if needed)
-- GRANT SELECT ON ssh_keys TO your_api_user;
-- GRANT SELECT ON active_ssh_keys TO your_api_user;

-- Display migration results
SELECT 
    'Migration complete!' as status,
    COUNT(*) as keys_migrated 
FROM ssh_keys;

-- Show sample of migrated keys
SELECT 
    u.username,
    SUBSTRING(k.fingerprint, 1, 30) as fingerprint_preview,
    k.created_at
FROM ssh_keys k
JOIN users u ON u.id = k.user_id
ORDER BY k.created_at DESC
LIMIT 10;
