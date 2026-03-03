// SSH key management operations
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use sqlx::PgPool;
use std::process::Command;

#[derive(sqlx::FromRow)]
pub struct SshKeyInfo {
    pub id: i32,
    pub fingerprint: String,
    pub created_at: NaiveDateTime,
    pub expires_at: Option<NaiveDateTime>,
    pub revoked_at: Option<NaiveDateTime>,
    pub last_used_at: Option<NaiveDateTime>,
    pub comment: Option<String>,
}

/// Calculate SSH key fingerprint using ssh-keygen
pub fn calculate_fingerprint(public_key: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Write key to temp file
    let temp_file = "/tmp/temp_key.pub";
    std::fs::write(temp_file, public_key)?;

    // Use ssh-keygen to get fingerprint
    let output = Command::new("ssh-keygen")
        .args(["-lf", temp_file])
        .output()?;

    // Clean up temp file
    let _ = std::fs::remove_file(temp_file);

    if !output.status.success() {
        return Err("Invalid SSH key format".into());
    }

    // Parse output: "2048 SHA256:... user@host (RSA)"
    let output_str = String::from_utf8(output.stdout)?;
    let fingerprint = output_str
        .split_whitespace()
        .nth(1)
        .ok_or("Could not parse fingerprint")?
        .to_string();

    Ok(fingerprint)
}

/// Parse TTL string (e.g., "10m", "2h", "7d") into DateTime
pub fn parse_ttl(ttl: &str) -> Result<DateTime<Utc>, Box<dyn std::error::Error>> {
    let ttl = ttl.trim();
    let (value, unit) = ttl.split_at(ttl.len() - 1);
    let value: i64 = value.parse()?;

    let duration = match unit {
        "s" => Duration::seconds(value),
        "m" => Duration::minutes(value),
        "h" => Duration::hours(value),
        "d" => Duration::days(value),
        "w" => Duration::weeks(value),
        _ => return Err(format!("Invalid TTL unit: {}. Use s, m, h, d, or w", unit).into()),
    };

    Ok(Utc::now() + duration)
}

/// Add a new SSH key
pub async fn add_key(
    pool: &PgPool,
    username: &str,
    public_key: String,
    ttl: Option<String>,
    comment: Option<String>,
) -> Result<(i32, String), Box<dyn std::error::Error>> {
    // Calculate fingerprint
    let fingerprint = calculate_fingerprint(&public_key)?;

    // Parse TTL if provided
    let expires_at = ttl.map(|t| parse_ttl(&t)).transpose()?;

    // Get user_id
    let user_id: i32 = sqlx::query_scalar("SELECT id FROM users WHERE username = $1")
        .bind(username)
        .fetch_one(pool)
        .await?;

    // Insert key
    let key_id: i32 = sqlx::query_scalar(
        "INSERT INTO ssh_keys (user_id, public_key, fingerprint, expires_at, comment)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id",
    )
    .bind(user_id)
    .bind(public_key.trim())
    .bind(&fingerprint)
    .bind(expires_at)
    .bind(comment)
    .fetch_one(pool)
    .await?;

    Ok((key_id, fingerprint))
}

/// List all keys for a user
pub async fn list_keys(
    pool: &PgPool,
    username: &str,
) -> Result<Vec<SshKeyInfo>, Box<dyn std::error::Error>> {
    let keys = sqlx::query_as::<_, SshKeyInfo>(
        "SELECT 
            k.id,
            k.fingerprint,
            k.created_at,
            k.expires_at,
            k.revoked_at,
            k.last_used_at,
            k.comment
         FROM ssh_keys k
         JOIN users u ON u.id = k.user_id
         WHERE u.username = $1
         ORDER BY k.created_at DESC",
    )
    .bind(username)
    .fetch_all(pool)
    .await?;

    Ok(keys)
}

/// Get detailed information about a specific key
pub async fn get_key_info(
    pool: &PgPool,
    username: &str,
    key_id: &str,
) -> Result<Option<SshKeyInfo>, Box<dyn std::error::Error>> {
    // Try to parse as ID first
    if let Ok(id) = key_id.parse::<i32>() {
        let key = sqlx::query_as::<_, SshKeyInfo>(
            "SELECT 
                k.id,
                k.fingerprint,
                k.created_at,
                k.expires_at,
                k.revoked_at,
                k.last_used_at,
                k.comment
             FROM ssh_keys k
             JOIN users u ON u.id = k.user_id
             WHERE u.username = $1 AND k.id = $2",
        )
        .bind(username)
        .bind(id)
        .fetch_optional(pool)
        .await?;

        return Ok(key);
    }

    // Otherwise treat as fingerprint
    let key = sqlx::query_as::<_, SshKeyInfo>(
        "SELECT 
            k.id,
            k.fingerprint,
            k.created_at,
            k.expires_at,
            k.revoked_at,
            k.last_used_at,
            k.comment
         FROM ssh_keys k
         JOIN users u ON u.id = k.user_id
         WHERE u.username = $1 AND k.fingerprint = $2",
    )
    .bind(username)
    .bind(key_id)
    .fetch_optional(pool)
    .await?;

    Ok(key)
}

/// Revoke a key
pub async fn revoke_key(
    pool: &PgPool,
    username: &str,
    key_id: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    // Try to parse as ID first
    let result = if let Ok(id) = key_id.parse::<i32>() {
        sqlx::query(
            "UPDATE ssh_keys k
             SET revoked_at = NOW()
             FROM users u
             WHERE k.user_id = u.id 
               AND u.username = $1 
               AND k.id = $2
               AND k.revoked_at IS NULL",
        )
        .bind(username)
        .bind(id)
        .execute(pool)
        .await?
    } else {
        sqlx::query(
            "UPDATE ssh_keys k
             SET revoked_at = NOW()
             FROM users u
             WHERE k.user_id = u.id 
               AND u.username = $1 
               AND k.fingerprint = $2
               AND k.revoked_at IS NULL",
        )
        .bind(username)
        .bind(key_id)
        .execute(pool)
        .await?
    };

    Ok(result.rows_affected() > 0)
}

/// Get key status as a display string
pub fn get_key_status(key: &SshKeyInfo) -> &'static str {
    if key.revoked_at.is_some() {
        "Revoked"
    } else if let Some(exp) = key.expires_at {
        if exp < Utc::now().naive_utc() {
            "Expired"
        } else {
            "Active"
        }
    } else {
        "Active (Permanent)"
    }
}
