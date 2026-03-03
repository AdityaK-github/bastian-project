// Database operations for permissions and access control

use sqlx::PgPool;

/// Check if a user is an admin
pub async fn is_admin(pool: &PgPool, username: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query_as::<_, (bool,)>("SELECT is_admin FROM users WHERE username = $1")
        .bind(username)
        .fetch_optional(pool)
        .await?;

    Ok(result.map(|r| r.0).unwrap_or(false))
}

/// Checks if a user has a valid, non-expired permission to access a server.
/// Returns Ok(Some((server_address, permission_id))) if authorized.
pub async fn check_permission(
    pool: &PgPool,
    username: &str,
    server_name: &str,
) -> Result<Option<(String, i32)>, sqlx::Error> {
    let result = sqlx::query_as::<_, (String, i32)>(
        r#"
        SELECT s.address, p.id
        FROM permissions p
        JOIN users u ON u.id = p.user_id
        JOIN servers s ON s.id = p.server_id
        WHERE u.username = $1 AND s.name = $2 AND p.expires_at > NOW()
        "#,
    )
    .bind(username)
    .bind(server_name)
    .fetch_optional(pool)
    .await?;

    Ok(result)
}

/// Get server address by name
pub async fn get_server_address(
    pool: &PgPool,
    server_name: &str,
) -> Result<Option<String>, sqlx::Error> {
    let result = sqlx::query_as::<_, (String,)>("SELECT address FROM servers WHERE name = $1")
        .bind(server_name)
        .fetch_optional(pool)
        .await?;

    Ok(result.map(|r| r.0))
}

#[derive(sqlx::FromRow)]
pub struct ServerPermission {
    pub server_name: String,
    pub server_address: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

pub async fn get_user_permissions(
    pool: &PgPool,
    username: &str,
) -> Result<Vec<ServerPermission>, sqlx::Error> {
    sqlx::query_as::<_, ServerPermission>(
        r#"
        SELECT s.name as server_name, s.address as server_address, p.expires_at
        FROM permissions p
        JOIN users u ON u.id = p.user_id
        JOIN servers s ON s.id = p.server_id
        WHERE u.username = $1 AND p.expires_at > NOW()
        ORDER BY s.name
        "#,
    )
    .bind(username)
    .fetch_all(pool)
    .await
}

/// Check if user exists
pub async fn user_exists(pool: &PgPool, username: &str) -> Result<bool, sqlx::Error> {
    let result =
        sqlx::query_as::<_, (bool,)>("SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)")
            .bind(username)
            .fetch_one(pool)
            .await?;

    Ok(result.0)
}

/// Check if server exists
pub async fn server_exists(pool: &PgPool, server_name: &str) -> Result<bool, sqlx::Error> {
    let result =
        sqlx::query_as::<_, (bool,)>("SELECT EXISTS(SELECT 1 FROM servers WHERE name = $1)")
            .bind(server_name)
            .fetch_one(pool)
            .await?;

    Ok(result.0)
}

/// Grant direct permission to a user
pub async fn grant_permission(
    pool: &PgPool,
    username: &str,
    server_name: &str,
    hours: i32,
) -> Result<(), sqlx::Error> {
    let expires_at_sql = format!("NOW() + INTERVAL '{} hours'", hours);

    sqlx::query(&format!(
        r#"
        INSERT INTO permissions (user_id, server_id, expires_at)
        VALUES (
            (SELECT id FROM users WHERE username = $1),
            (SELECT id FROM servers WHERE name = $2),
            {}
        )
        ON CONFLICT (user_id, server_id) 
        DO UPDATE SET expires_at = EXCLUDED.expires_at
        "#,
        expires_at_sql
    ))
    .bind(username)
    .bind(server_name)
    .execute(pool)
    .await?;

    Ok(())
}

/// List active permissions (all or for specific user)
pub async fn list_permissions(
    pool: &PgPool,
    username: Option<&str>,
) -> Result<Vec<(String, String, String, String)>, sqlx::Error> {
    if let Some(user) = username {
        // Specific user's permissions
        sqlx::query_as::<_, (String, String, String, String)>(
            r#"
            SELECT 
                u.username,
                s.name,
                s.address,
                to_char(p.expires_at, 'YYYY-MM-DD HH24:MI:SS')
            FROM permissions p
            JOIN users u ON u.id = p.user_id
            JOIN servers s ON s.id = p.server_id
            WHERE u.username = $1 AND p.expires_at > NOW()
            ORDER BY p.expires_at ASC
            "#,
        )
        .bind(user)
        .fetch_all(pool)
        .await
    } else {
        // All active permissions
        sqlx::query_as::<_, (String, String, String, String)>(
            r#"
            SELECT 
                u.username,
                s.name,
                s.address,
                to_char(p.expires_at, 'YYYY-MM-DD HH24:MI:SS')
            FROM permissions p
            JOIN users u ON u.id = p.user_id
            JOIN servers s ON s.id = p.server_id
            WHERE p.expires_at > NOW()
            ORDER BY p.expires_at ASC
            "#,
        )
        .fetch_all(pool)
        .await
    }
}
