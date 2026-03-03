// CLI command definitions and argument parsing

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "bastion_cli")]
#[command(about = "Bastion CLI for secure SSH access", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Test database connectivity
    Ping,

    /// Connect to a server
    Connect {
        /// Name of the server to connect to
        server_name: String,
    },

    /// List available servers
    List,

    /// Request access to a server (requires admin approval)
    Request {
        /// Name of the server to request access to
        server_name: String,
        /// Duration in hours (default: 1)
        #[arg(short, long, default_value = "1")]
        hours: i32,
        /// Optional note/reason for the request
        #[arg(short, long)]
        note: Option<String>,
    },

    /// List pending access requests (admin only)
    Pending,

    /// Approve an access request (admin only)
    Approve {
        /// Request ID to approve (optional, interactive if not provided)
        request_id: Option<i32>,
        /// Override duration in hours (optional)
        #[arg(short, long)]
        hours: Option<i32>,
    },

    /// Deny an access request (admin only)
    Deny {
        /// Request ID to deny
        request_id: i32,
        /// Reason for denial
        #[arg(short, long)]
        reason: String,
    },

    /// List your access requests and their status
    MyRequests,

    /// List all active permissions
    ListAccess,

    /// Grant direct access to a user (admin only, bypasses approval)
    Grant {
        /// Username to grant access to
        username: String,
        /// Server name to grant access to
        server_name: String,
        /// Duration in hours
        #[arg(short, long, default_value = "1")]
        hours: i32,
    },

    /// Add a new SSH key (with optional TTL)
    AddKey {
        /// Path to public key file
        #[arg(short = 'f', long, conflicts_with = "key_data")]
        file: Option<String>,

        /// Public key data directly (as string)
        #[arg(short = 'd', long, conflicts_with = "file")]
        key_data: Option<String>,

        /// Time-to-live (e.g., "10m", "2h", "7d") - leave empty for permanent
        #[arg(short, long)]
        ttl: Option<String>,

        /// Optional comment/description
        #[arg(short, long)]
        comment: Option<String>,
    },

    /// List all your SSH keys
    ListKeys,

    /// Revoke an SSH key
    RevokeKey {
        /// Key ID or fingerprint
        key_id: String,
    },

    /// Show detailed key information
    KeyInfo {
        /// Key ID or fingerprint
        key_id: String,
    },

    /// Promote a user to admin (admin only)
    MakeAdmin {
        /// Username to promote to admin
        username: String,
    },

    /// Revoke admin privileges from a user (admin only)
    RevokeAdmin {
        /// Username to demote from admin
        username: String,
    },

    /// List all users and their roles
    ListUsers,
}
