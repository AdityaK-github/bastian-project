// User identification via SSH keys and IP addresses

use sqlx::PgPool;
use std::env;
use std::fs;
use std::process::Command;

/// Extract SSH key fingerprint from the current SSH connection
pub fn get_ssh_key_fingerprint() -> Option<String> {
    // Check for the fingerprint passed via authorized_keys environment option
    if let Ok(fp) = env::var("BASTION_KEY_FINGERPRINT") {
        return Some(fp);
    }

    // Try to get the SSH key from environment variables set by sshd
    if let Ok(key) = env::var("SSH_USER_AUTH") {
        return Some(key);
    }

    // Try to read from SSH_CONNECTION and extract key info
    if let Ok(ssh_key_file) = env::var("SSH_AUTH_SOCK") {
        // Parse authorized_keys to find matching key
        if let Ok(content) = fs::read_to_string("/home/dev/.ssh/authorized_keys") {
            // Extract fingerprint from the first key (simplified for now)
            return extract_fingerprint_from_key(&content);
        }
    }

    None
}

/// Extract fingerprint from SSH public key
fn extract_fingerprint_from_key(key_content: &str) -> Option<String> {
    for line in key_content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Use ssh-keygen to get fingerprint
        if let Ok(output) = Command::new("sh")
            .arg("-c")
            .arg(format!("echo '{}' | ssh-keygen -lf -", line))
            .output()
        {
            if output.status.success() {
                let fingerprint = String::from_utf8_lossy(&output.stdout);
                // Extract the SHA256 part
                if let Some(sha_part) = fingerprint.split_whitespace().nth(1) {
                    return Some(sha_part.to_string());
                }
            }
        }
    }

    None
}

/// Get client IP address from SSH connection
pub fn get_client_ip() -> Option<String> {
    // SSH_CONNECTION format: "client_ip client_port server_ip server_port"
    if let Ok(ssh_conn) = env::var("SSH_CONNECTION") {
        if let Some(client_ip) = ssh_conn.split_whitespace().next() {
            return Some(client_ip.to_string());
        }
    }

    // Try SSH_CLIENT as fallback
    if let Ok(ssh_client) = env::var("SSH_CLIENT") {
        if let Some(client_ip) = ssh_client.split_whitespace().next() {
            return Some(client_ip.to_string());
        }
    }

    None
}

/// Identify user by SSH key fingerprint
pub async fn identify_user_by_key(
    pool: &PgPool,
    fingerprint: &str,
) -> Result<Option<String>, sqlx::Error> {
    let result = sqlx::query_as::<_, (String,)>(
        "SELECT u.username 
         FROM users u 
         JOIN ssh_keys k ON k.user_id = u.id 
         WHERE k.fingerprint = $1",
    )
    .bind(fingerprint)
    .fetch_optional(pool)
    .await?;

    Ok(result.map(|r| r.0))
}

/// Store SSH key for a user
pub async fn store_user_key(
    pool: &PgPool,
    username: &str,
    public_key: &str,
    fingerprint: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE users 
        SET ssh_public_key = $1,
            ssh_key_fingerprint = $2
        WHERE username = $3
        "#,
    )
    .bind(public_key)
    .bind(fingerprint)
    .bind(username)
    .execute(pool)
    .await?;

    Ok(())
}

/// Update user's last seen information
pub async fn update_user_last_seen(
    pool: &PgPool,
    username: &str,
    ip_address: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE users 
        SET last_login = NOW(),
            last_seen_ip = $1::inet
        WHERE username = $2
        "#,
    )
    .bind(ip_address)
    .bind(username)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get detailed connection information for logging
pub fn get_connection_info() -> ConnectionInfo {
    ConnectionInfo {
        client_ip: get_client_ip(),
        ssh_key_fingerprint: get_ssh_key_fingerprint(),
        ssh_connection: env::var("SSH_CONNECTION").ok(),
        ssh_tty: env::var("SSH_TTY").ok(),
        user_env: env::var("USER").ok(),
    }
}

#[derive(Debug)]
pub struct ConnectionInfo {
    pub client_ip: Option<String>,
    pub ssh_key_fingerprint: Option<String>,
    pub ssh_connection: Option<String>,
    pub ssh_tty: Option<String>,
    pub user_env: Option<String>,
}

impl ConnectionInfo {
    pub fn display(&self) {
        println!("--> Connection Information:");
        if let Some(ip) = &self.client_ip {
            println!("    Client IP: {}", ip);
        }
        if let Some(fp) = &self.ssh_key_fingerprint {
            println!("    SSH Key: {}", fp);
        }
        if let Some(conn) = &self.ssh_connection {
            println!("    SSH Connection: {}", conn);
        }
    }
}
