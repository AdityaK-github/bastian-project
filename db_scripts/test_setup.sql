-- Test Setup SQL
-- This creates test data with valid permissions for testing

-- Add test users (teammates)
INSERT INTO users (username) VALUES ('alice') ON CONFLICT (username) DO NOTHING;
INSERT INTO users (username) VALUES ('bob') ON CONFLICT (username) DO NOTHING;
INSERT INTO users (username) VALUES ('charlie') ON CONFLICT (username) DO NOTHING;

-- Add test servers
INSERT INTO servers (name, address) VALUES 
    ('prod-db', 'root@prod-db-server'),
    ('prod-api', 'ubuntu@prod-api-server'),
    ('staging', 'dev@staging-server')
ON CONFLICT (name) DO NOTHING;

-- Grant permissions (valid for 24 hours)
INSERT INTO permissions (user_id, server_id, expires_at)
VALUES 
    ((SELECT id FROM users WHERE username = 'alice'), 
     (SELECT id FROM servers WHERE name = 'prod-server-1'), 
     NOW() + INTERVAL '24 hours'),
    
    ((SELECT id FROM users WHERE username = 'bob'), 
     (SELECT id FROM servers WHERE name = 'prod-db'), 
     NOW() + INTERVAL '24 hours'),
    
    ((SELECT id FROM users WHERE username = 'alice'), 
     (SELECT id FROM servers WHERE name = 'staging'), 
     NOW() + INTERVAL '1 hour')
ON CONFLICT (user_id, server_id) DO UPDATE 
    SET expires_at = EXCLUDED.expires_at;

-- View current permissions
SELECT 
    u.username,
    s.name as server_name,
    s.address,
    p.expires_at,
    CASE 
        WHEN p.expires_at > NOW() THEN 'ACTIVE'
        ELSE 'EXPIRED'
    END as status
FROM permissions p
JOIN users u ON u.id = p.user_id
JOIN servers s ON s.id = p.server_id
ORDER BY p.expires_at DESC;
