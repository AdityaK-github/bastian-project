-- Enhanced user tracking with SSH keys and IP addresses

-- Add SSH key tracking to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS ssh_public_key TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS ssh_key_fingerprint TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen_ip INET;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMPTZ;

-- Add connection tracking to sessions table
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS client_ip INET;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ssh_key_fingerprint TEXT;

-- Create index for faster key lookups
CREATE INDEX IF NOT EXISTS idx_users_ssh_key_fingerprint ON users(ssh_key_fingerprint);
CREATE INDEX IF NOT EXISTS idx_sessions_client_ip ON sessions(client_ip);

-- Add sample SSH keys for test users
-- Alice's key (already in authorized_keys)
UPDATE users 
SET ssh_public_key = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII3ToWo67OCIBS7fT1X9XtCaqprewABb5tMYYbHdC0dp adibabakarwa10@gmail.com',
    ssh_key_fingerprint = 'SHA256:...' -- Will be computed dynamically
WHERE username = 'alice';

-- View for session tracking with user identification
CREATE OR REPLACE VIEW session_tracking AS
SELECT 
    s.id as session_id,
    u.username,
    u.ssh_key_fingerprint as user_key,
    s.client_ip,
    srv.name as server_name,
    srv.address as server_address,
    s.start_time,
    s.end_time,
    s.status,
    s.log_file_path,
    EXTRACT(EPOCH FROM (s.end_time - s.start_time)) as duration_seconds
FROM sessions s
JOIN users u ON u.id = s.user_id
JOIN servers srv ON srv.id = s.server_id
ORDER BY s.start_time DESC;

-- Function to identify user by SSH key
CREATE OR REPLACE FUNCTION get_user_by_ssh_key(key_fingerprint TEXT)
RETURNS TABLE(username TEXT, user_id INTEGER) AS $$
BEGIN
    RETURN QUERY
    SELECT u.username, u.id
    FROM users u
    WHERE u.ssh_key_fingerprint = key_fingerprint
    LIMIT 1;
END;
$$ LANGUAGE plpgsql;

COMMENT ON COLUMN users.ssh_public_key IS 'Full SSH public key for the user';
COMMENT ON COLUMN users.ssh_key_fingerprint IS 'SHA256 fingerprint of SSH key for identification';
COMMENT ON COLUMN users.last_seen_ip IS 'Last IP address user connected from';
COMMENT ON COLUMN sessions.client_ip IS 'IP address of the client connecting to bastion';
COMMENT ON COLUMN sessions.ssh_key_fingerprint IS 'SSH key fingerprint used for this session';

SELECT 'User tracking schema updated successfully!' as status;
