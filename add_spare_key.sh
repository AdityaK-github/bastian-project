#!/bin/bash
# Helper script to add a spare laptop key cleanly

if [ -z "$1" ]; then
    echo "Usage: ./add_spare_key.sh \"ssh-ed25519 AAAA...\""
    exit 1
fi

RAW_KEY="$1"
# Extract just the key type and the base64 part (ignore comments)
CLEAN_KEY=$(echo "$RAW_KEY" | awk '{print $1 " " $2}')
# Generate a clean fingerprint
FINGERPRINT=$(echo "$CLEAN_KEY" | ssh-keygen -lf - | awk '{print $2}')

echo "Adding Key:"
echo "  Type/Body: $CLEAN_KEY"
echo "  Fingerprint: $FINGERPRINT"

docker exec -i bastianproject-db-1 psql -U postgres -d postgres -c "
INSERT INTO ssh_keys (user_id, public_key, fingerprint, comment)
VALUES (
    (SELECT id FROM users WHERE username = 'dev'),
    '$CLEAN_KEY',
    '$FINGERPRINT',
    'Spare Laptop Key (Clean)'
)
ON CONFLICT (fingerprint) DO UPDATE 
SET public_key = EXCLUDED.public_key;
"

echo "Key added! Try connecting now."
