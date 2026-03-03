#!/bin/bash
# SSH Wrapper Script for Bastion Server
# This script is called via SSH ForceCommand to intercept SSH sessions
# and route them through the bastion CLI with proper logging

# Set up environment
export DATABASE_URL="${DATABASE_URL:-postgresql://postgres:mysecretpassword@db:5432/postgres}"

# Get the connecting user (from SSH)
BASTION_USER="${USER:-unknown}"

# Log the original SSH command for debugging
# touch /var/log/bastion/ssh_commands.log
# chmod 666 /var/log/bastion/ssh_commands.log
echo "$(date) - User: $BASTION_USER - Command: ${SSH_ORIGINAL_COMMAND:-interactive}" >> /var/log/bastion/ssh_commands.log

# Check if user is trying to run a specific command
if [ -z "$SSH_ORIGINAL_COMMAND" ]; then
    # Interactive session - show menu
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║           Welcome to the Bastion Jump Server              ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Connected as: $BASTION_USER"
    echo ""
    echo "Available servers you can connect to:"
    echo ""
    
    # Use bastion_cli to list servers (it handles user identification securely)
    /usr/local/bin/bastion_cli list
    
    echo ""
    echo "Usage: bastion_cli connect <server-name>"
    echo ""
    echo "Example:"
    echo "  bastion_cli connect prod-server-1"
    echo ""
    echo "Or simply SSH with the server name:"
    echo "  ssh bastion prod-server-1"
    echo ""
    
    # Give them a shell to work with
    exec /bin/bash
else
    # Parse the SSH command
    CMD_TYPE=$(echo "$SSH_ORIGINAL_COMMAND" | awk '{print $1}')
    
    case "$CMD_TYPE" in
        connect|request|pending|approve|deny|ping|list-access|my-requests)
            # Pass through to bastion_cli using --raw to avoid shell expansion
            exec /usr/local/bin/bastion_cli --raw "$SSH_ORIGINAL_COMMAND"
            ;;
        bastion_cli)
            # Pass through raw bastion_cli command (strip the binary name)
            CMD_WITHOUT_PREFIX=$(echo "$SSH_ORIGINAL_COMMAND" | sed 's/^[^ ]* //')
            exec /usr/local/bin/bastion_cli --raw "$CMD_WITHOUT_PREFIX"
            ;;
        *)
            # Assume it's a server name shortcut (e.g. "ssh bastion prod-server-1")
            exec /usr/local/bin/bastion_cli --raw "connect $SSH_ORIGINAL_COMMAND"
            ;;
    esac
fi
fi
