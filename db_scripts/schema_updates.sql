-- Schema updates for admin approval workflow

-- Add is_admin flag to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE;

-- Create access_requests table for approval workflow
CREATE TABLE IF NOT EXISTS access_requests (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) NOT NULL,
    server_id INTEGER REFERENCES servers(id) NOT NULL,
    requested_at TIMESTAMPTZ DEFAULT NOW(),
    status VARCHAR(50) DEFAULT 'pending', -- pending, approved, denied
    approved_by INTEGER REFERENCES users(id),
    approved_at TIMESTAMPTZ,
    denial_reason TEXT,
    duration_hours INTEGER DEFAULT 1, -- How long access should be granted
    expires_at TIMESTAMPTZ, -- When the approved access will expire
    notes TEXT
);

-- Create index for faster queries
CREATE INDEX IF NOT EXISTS idx_access_requests_status ON access_requests(status);
CREATE INDEX IF NOT EXISTS idx_access_requests_user_id ON access_requests(user_id);

-- Make some test users admins
UPDATE users SET is_admin = TRUE WHERE username IN ('alice');

-- Add some sample data
COMMENT ON TABLE access_requests IS 'Tracks access requests that need admin approval';
COMMENT ON COLUMN access_requests.status IS 'pending, approved, denied';
COMMENT ON COLUMN access_requests.duration_hours IS 'How many hours of access to grant when approved';

-- View to see pending requests with details
CREATE OR REPLACE VIEW pending_requests AS
SELECT 
    ar.id,
    u.username as requester,
    s.name as server_name,
    s.address as server_address,
    ar.requested_at,
    ar.duration_hours,
    ar.notes,
    EXTRACT(EPOCH FROM (NOW() - ar.requested_at))/3600 as hours_waiting
FROM access_requests ar
JOIN users u ON u.id = ar.user_id
JOIN servers s ON s.id = ar.server_id
WHERE ar.status = 'pending'
ORDER BY ar.requested_at ASC;

-- View to see all requests with status
CREATE OR REPLACE VIEW all_requests AS
SELECT 
    ar.id,
    u.username as requester,
    s.name as server_name,
    ar.requested_at,
    ar.status,
    admin.username as approved_by,
    ar.approved_at,
    ar.duration_hours,
    ar.expires_at,
    ar.denial_reason
FROM access_requests ar
JOIN users u ON u.id = ar.user_id
JOIN servers s ON s.id = ar.server_id
LEFT JOIN users admin ON admin.id = ar.approved_by
ORDER BY ar.requested_at DESC;

SELECT 'Schema updated successfully!' as status;
