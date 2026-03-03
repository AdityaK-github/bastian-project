// Command handlers - UI and business logic for each CLI command

use crate::identity;
use crate::keys;
use crate::permissions;
use crate::requests;
use crate::session;
use sqlx::PgPool;

/// Handle the connect command
pub async fn handle_connect(
    pool: &PgPool,
    username: &str,
    server_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Get connection information for tracking
    let conn_info = identity::get_connection_info();
    conn_info.display();

    println!(
        "--> Received connection request from '{}' for server '{}'",
        username, server_name
    );

    // Update user's last seen info
    identity::update_user_last_seen(pool, username, conn_info.client_ip.as_deref()).await?;

    let client_ip = conn_info.client_ip.as_deref();
    let ssh_key = conn_info.ssh_key_fingerprint.as_deref();

    // Check if user is admin (admins have automatic access)
    if permissions::is_admin(pool, username).await? {
        println!("-->   Admin access - no permission check needed");

        let server_address = permissions::get_server_address(pool, server_name).await?;
        if let Some(addr) = server_address {
            session::connect_to_server(pool, username, &addr, server_name, 0, client_ip, ssh_key)
                .await?;
        } else {
            eprintln!("-->  Server '{}' not found", server_name);
        }
    } else {
        // Regular users need valid permission
        let permission = permissions::check_permission(pool, username, server_name).await?;

        if let Some((server_address, permission_id)) = permission {
            println!("-->   Access granted. Permission ID: {}", permission_id);
            session::connect_to_server(
                pool,
                username,
                &server_address,
                server_name,
                permission_id,
                client_ip,
                ssh_key,
            )
            .await?;
        } else {
            eprintln!(
                "-->  Access denied for user '{}' to server '{}'.",
                username, server_name
            );
            eprintln!(
                "--> You need to request access first: bastion_cli request {}",
                server_name
            );
        }
    }

    Ok(())
}

/// Handle the request command
pub async fn handle_request(
    pool: &PgPool,
    username: &str,
    server_name: &str,
    hours: i32,
    note: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    if permissions::is_admin(pool, username).await? {
        println!("--> Note: You're an admin. You have automatic access to all servers.");
        println!(
            "--> Use 'bastion_cli connect {}' to connect directly.",
            server_name
        );
        return Ok(());
    }

    let request_id = requests::create_request(pool, username, server_name, hours, note).await?;

    println!("-->   Access request submitted! Request ID: {}", request_id);
    println!(
        "--> Requesting access to '{}' for {} hour(s)",
        server_name, hours
    );
    if let Some(n) = note {
        println!("--> Note: {}", n);
    }
    println!("--> Waiting for admin approval...");
    println!("--> Check status with: bastion_cli my-requests");

    Ok(())
}

/// Handle the pending command
pub async fn handle_pending(pool: &PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let request_list = requests::get_pending_requests(pool).await?;

    if request_list.is_empty() {
        println!("--> No pending requests");
        return Ok(());
    }

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║                    PENDING ACCESS REQUESTS                   ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    for (id, user, server, requested_at, hours, notes) in request_list {
        println!("Request ID: {}", id);
        println!("   User: {}", user);
        println!("   Server: {}", server);
        println!("   Requested: {}", requested_at);
        println!("   Duration: {} hour(s)", hours);
        if let Some(note) = notes {
            println!("   Note: {}", note);
        }
        println!("   ─────────────────────────────────────────────");
    }

    println!("\nTo approve: bastion_cli approve <request_id>");
    println!("To deny: bastion_cli deny <request_id> --reason \"<reason>\"\n");

    Ok(())
}

/// Handle the approve command
pub async fn handle_approve(
    pool: &PgPool,
    request_id: Option<i32>,
    admin_username: &str,
    override_hours: Option<i32>,
) -> Result<(), Box<dyn std::error::Error>> {
    let id = match request_id {
        Some(id) => id,
        None => {
            // Interactive mode
            let requests = requests::get_pending_requests(pool).await?;
            if requests.is_empty() {
                println!("--> No pending requests to approve.");
                return Ok(());
            }

            println!("Select a request to approve:");
            for (idx, (r_id, user, server, time, hours, note)) in requests.iter().enumerate() {
                let note_str = note.as_deref().unwrap_or("-");
                println!(
                    "{}. {} -> {} ({}h) [Time: {}] - Note: {}",
                    idx + 1,
                    user,
                    server,
                    hours,
                    time,
                    note_str
                );
            }

            use std::io::{self, Write};
            print!("Enter selection number (1-{}): ", requests.len());
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let selection: usize = input.trim().parse().map_err(|_| "Invalid number")?;

            if selection < 1 || selection > requests.len() {
                return Err("Invalid selection range".into());
            }

            requests[selection - 1].0
        }
    };

    let request_details = requests::get_request_details(pool, id).await?;

    let (user_id, server_id, default_hours, username, server_name) = match request_details {
        Some(r) => r,
        None => {
            eprintln!("-->  Request {} not found or already processed", id);
            return Ok(());
        }
    };

    let duration_hours = override_hours.unwrap_or(default_hours);

    requests::approve_request(pool, id, user_id, server_id, admin_username, duration_hours).await?;

    println!("-->   Request {} approved!", id);
    println!(
        "--> User '{}' granted access to '{}' for {} hour(s)",
        username, server_name, duration_hours
    );

    Ok(())
}

/// Handle the deny command
pub async fn handle_deny(
    pool: &PgPool,
    request_id: i32,
    admin_username: &str,
    reason: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let rows_affected = requests::deny_request(pool, request_id, admin_username, reason).await?;

    if rows_affected == 0 {
        eprintln!("-->  Request {} not found or already processed", request_id);
    } else {
        println!("--> Request {} denied", request_id);
        println!("--> Reason: {}", reason);
    }

    Ok(())
}

/// Handle the my-requests command
pub async fn handle_my_requests(
    pool: &PgPool,
    username: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let request_list = requests::get_user_requests(pool, username).await?;

    if request_list.is_empty() {
        println!("--> No access requests found");
        return Ok(());
    }

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║                    YOUR ACCESS REQUESTS                      ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    for (id, server, status, requested_at, hours, expires_at, denial_reason) in request_list {
        let status_icon = match status.as_str() {
            "pending" => "[PENDING]",
            "approved" => "[APPROVED]",
            "denied" => "[DENIED]",
            _ => "[UNKNOWN]",
        };

        println!(
            "{} Request ID: {} - {}",
            status_icon,
            id,
            status.to_uppercase()
        );
        println!("   Server: {}", server);
        println!("   Requested: {}", requested_at);
        println!("   Duration: {} hour(s)", hours);

        if status == "approved" {
            if let Some(exp) = expires_at {
                println!("   Expires: {}", exp);
            }
        }

        if status == "denied" {
            if let Some(reason) = denial_reason {
                println!("    Denial reason: {}", reason);
            }
        }

        println!("   ─────────────────────────────────────────────");
    }
    println!();

    Ok(())
}

/// Handle the list-access command
pub async fn handle_list_access(
    pool: &PgPool,
    username: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let is_admin_user = permissions::is_admin(pool, username).await?;

    let permission_list = if is_admin_user {
        permissions::list_permissions(pool, None).await?
    } else {
        permissions::list_permissions(pool, Some(username)).await?
    };

    if permission_list.is_empty() {
        if is_admin_user {
            println!("--> No active permissions");
        } else {
            println!("--> You have no active permissions");
            println!("--> Request access with: bastion_cli request <server_name>");
        }
        return Ok(());
    }

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║                    ACTIVE PERMISSIONS                        ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    for (user, server, address, expires_at) in permission_list {
        println!("  {} → {}", user, server);
        println!("   Address: {}", address);
        println!("   Expires: {}", expires_at);
        println!("   ─────────────────────────────────────────────");
    }
    println!();

    Ok(())
}

/// Handle the grant command
pub async fn handle_grant(
    pool: &PgPool,
    username: &str,
    server_name: &str,
    hours: i32,
    admin_username: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Check if user exists
    if !permissions::user_exists(pool, username).await? {
        eprintln!("-->  User '{}' not found", username);
        return Ok(());
    }

    // Check if server exists
    if !permissions::server_exists(pool, server_name).await? {
        eprintln!("-->  Server '{}' not found", server_name);
        return Ok(());
    }

    permissions::grant_permission(pool, username, server_name, hours).await?;

    println!("-->   Direct access granted!");
    println!(
        "--> User '{}' can now access '{}' for {} hour(s)",
        username, server_name, hours
    );
    println!("--> Granted by: {}", admin_username);

    Ok(())
}

/// Handle add-key command
pub async fn handle_add_key(
    pool: &PgPool,
    username: &str,
    file: Option<String>,
    key_data: Option<String>,
    ttl: Option<String>,
    comment: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Read key from file or direct input
    let public_key = if let Some(path) = file {
        std::fs::read_to_string(path)?
    } else if let Some(data) = key_data {
        data
    } else {
        return Err("Must provide either --file or --key-data".into());
    };

    println!("--> Adding SSH key for user '{}'...", username);

    let (key_id, fingerprint) =
        keys::add_key(pool, username, public_key, ttl.clone(), comment).await?;

    println!("-->   SSH key added successfully!");
    println!("   Key ID: {}", key_id);
    println!("   Fingerprint: {}", fingerprint);

    if let Some(ttl_str) = ttl {
        println!("   Expires: {} from now", ttl_str);
        println!("   Key will automatically become inactive after expiration");
    } else {
        println!("   Permanent (never expires)");
    }

    println!("\n--> You can now SSH using this key immediately!");

    Ok(())
}

/// Handle list-keys command
pub async fn handle_list_keys(
    pool: &PgPool,
    username: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let keys_list = keys::list_keys(pool, username).await?;

    if keys_list.is_empty() {
        println!("--> You have no SSH keys registered.");
        println!("--> Use 'bastion_cli add-key' to add a key.");
        return Ok(());
    }

    println!("--> Your SSH Keys:\n");

    for key in keys_list {
        let status = keys::get_key_status(&key);
        println!("  Key ID: {} | {}", key.id, status);
        println!("     Fingerprint: {}", key.fingerprint);
        println!(
            "     Created: {}",
            key.created_at.format("%Y-%m-%d %H:%M:%S UTC")
        );

        if let Some(exp) = key.expires_at {
            let now = chrono::Utc::now().naive_utc();
            if exp > now {
                let remaining = exp - now;
                println!(
                    "     Expires: {} ({} remaining)",
                    exp.format("%Y-%m-%d %H:%M:%S UTC"),
                    format_duration(remaining)
                );
            } else {
                println!("     Expired: {}", exp.format("%Y-%m-%d %H:%M:%S UTC"));
            }
        } else {
            println!("     Expires: Never");
        }

        if let Some(revoked) = key.revoked_at {
            println!("     Revoked: {}", revoked.format("%Y-%m-%d %H:%M:%S UTC"));
        }

        if let Some(last_used) = key.last_used_at {
            println!(
                "     Last used: {}",
                last_used.format("%Y-%m-%d %H:%M:%S UTC")
            );
        }

        if let Some(comment) = &key.comment {
            println!("     Comment: {}", comment);
        }

        println!();
    }

    Ok(())
}

/// Handle key-info command
pub async fn handle_key_info(
    pool: &PgPool,
    username: &str,
    key_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let key = keys::get_key_info(pool, username, key_id).await?;

    match key {
        Some(k) => {
            let status = keys::get_key_status(&k);
            println!("--> SSH Key Details:\n");
            println!("  Key ID: {}", k.id);
            println!("  Status: {}", status);
            println!("  Fingerprint: {}", k.fingerprint);
            println!(
                "  Created: {}",
                k.created_at.format("%Y-%m-%d %H:%M:%S UTC")
            );

            if let Some(exp) = k.expires_at {
                let now = chrono::Utc::now().naive_utc();
                if exp > now {
                    let remaining = exp - now;
                    println!(
                        "  Expires: {} ({} remaining)",
                        exp.format("%Y-%m-%d %H:%M:%S UTC"),
                        format_duration(remaining)
                    );
                } else {
                    println!("  Expired: {}", exp.format("%Y-%m-%d %H:%M:%S UTC"));
                }
            } else {
                println!("  Expires: Never");
            }

            if let Some(revoked) = k.revoked_at {
                println!("  Revoked: {}", revoked.format("%Y-%m-%d %H:%M:%S UTC"));
            }

            if let Some(last_used) = k.last_used_at {
                println!("  Last used: {}", last_used.format("%Y-%m-%d %H:%M:%S UTC"));
            } else {
                println!("  Last used: Never");
            }

            if let Some(comment) = &k.comment {
                println!("  Comment: {}", comment);
            }
        }
        None => {
            println!("-->  Key not found: {}", key_id);
        }
    }

    Ok(())
}

/// Handle revoke-key command
pub async fn handle_revoke_key(
    pool: &PgPool,
    username: &str,
    key_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("--> Revoking key: {}", key_id);

    let revoked = keys::revoke_key(pool, username, key_id).await?;

    if revoked {
        println!("-->   SSH key revoked successfully!");
        println!("   The key is now inactive and cannot be used for authentication");
        println!("   This takes effect immediately on next connection attempt");
    } else {
        println!("-->  Key not found or already revoked");
    }

    Ok(())
}

/// Helper function to format duration
fn format_duration(duration: chrono::Duration) -> String {
    let total_seconds = duration.num_seconds();

    if total_seconds < 60 {
        format!("{}s", total_seconds)
    } else if total_seconds < 3600 {
        format!("{}m", total_seconds / 60)
    } else if total_seconds < 86400 {
        format!("{}h", total_seconds / 3600)
    } else {
        format!("{}d", total_seconds / 86400)
    }
}

/// Handle make-admin command
pub async fn handle_make_admin(
    pool: &PgPool,
    username: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Check if user exists
    if !permissions::user_exists(pool, username).await? {
        println!("-->  User '{}' not found", username);
        return Ok(());
    }

    // Check if already admin
    if permissions::is_admin(pool, username).await? {
        println!("--> User '{}' is already an admin", username);
        return Ok(());
    }

    // Promote to admin
    sqlx::query("UPDATE users SET is_admin = TRUE WHERE username = $1")
        .bind(username)
        .execute(pool)
        .await?;

    println!("-->   User '{}' promoted to admin!", username);
    println!("   They now have automatic access to all servers");
    println!("   They can approve/deny access requests");
    println!("   They can grant direct access to users");

    Ok(())
}

/// Handle revoke-admin command
pub async fn handle_revoke_admin(
    pool: &PgPool,
    username: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Check if user exists
    if !permissions::user_exists(pool, username).await? {
        println!("-->  User '{}' not found", username);
        return Ok(());
    }

    // Check if is admin
    if !permissions::is_admin(pool, username).await? {
        println!("--> User '{}' is not an admin", username);
        return Ok(());
    }

    // Demote from admin
    sqlx::query("UPDATE users SET is_admin = FALSE WHERE username = $1")
        .bind(username)
        .execute(pool)
        .await?;

    println!("-->   Admin privileges revoked from '{}'", username);
    println!("   They are now a regular user");
    println!("   They will need approval for server access");

    Ok(())
}

/// Handle list-users command
pub async fn handle_list_users(pool: &PgPool) -> Result<(), Box<dyn std::error::Error>> {
    #[derive(sqlx::FromRow)]
    struct UserInfo {
        username: String,
        is_admin: bool,
        last_login: Option<chrono::DateTime<chrono::Utc>>,
        created_at: chrono::DateTime<chrono::Utc>,
    }

    let users = sqlx::query_as::<_, UserInfo>(
        "SELECT username, is_admin, last_login, created_at 
         FROM users 
         ORDER BY is_admin DESC, username ASC",
    )
    .fetch_all(pool)
    .await?;

    if users.is_empty() {
        println!("--> No users found");
        return Ok(());
    }

    println!("--> All Users:\n");

    // Calculate summary before consuming users
    let admin_count = users.iter().filter(|u| u.is_admin).count();
    let user_count = users.len() - admin_count;

    for user in users {
        let role = if user.is_admin { "[Admin]" } else { "[User]" };

        println!("  {} | {}", role, user.username);
        println!(
            "     Created: {}",
            user.created_at.format("%Y-%m-%d %H:%M:%S")
        );

        if let Some(last_login) = user.last_login {
            println!(
                "     Last login: {}",
                last_login.format("%Y-%m-%d %H:%M:%S")
            );
        } else {
            println!("     Last login: Never");
        }

        println!();
    }

    // Summary
    println!(
        "--> Summary: {} admin(s), {} regular user(s)",
        admin_count, user_count
    );

    Ok(())
}

/// Handle the list command (list available servers)
pub async fn handle_list(pool: &PgPool, username: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("--> Checking available servers for user '{}'...", username);

    // Get servers the user has permission to access
    let servers = permissions::get_user_permissions(pool, username).await?;

    if servers.is_empty() {
        println!("--> No accessible servers found.");
        println!("    Use 'bastion_cli request <server_name>' to request access.");
    } else {
        println!("--> Available Servers:");
        for server in servers {
            let expires_in = server.expires_at - chrono::Utc::now();
            let hours = expires_in.num_hours();
            let minutes = expires_in.num_minutes() % 60;

            println!("  {} ({})", server.server_name, server.server_address);
            println!("      Expires in: {}h {}m", hours, minutes);
        }
    }

    Ok(())
}
