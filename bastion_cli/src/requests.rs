// Database operations for access requests and approval workflow

use sqlx::PgPool;

/// Create a new access request
pub async fn create_request(
    pool: &PgPool,
    username: &str,
    server_name: &str,
    duration_hours: i32,
    notes: Option<&str>,
) -> Result<i32, sqlx::Error> {
    let request_id = sqlx::query_as::<_, (i32,)>(
        r#"
        INSERT INTO access_requests (user_id, server_id, duration_hours, notes)
        VALUES (
            (SELECT id FROM users WHERE username = $1),
            (SELECT id FROM servers WHERE name = $2),
            $3,
            $4
        )
        RETURNING id
        "#,
    )
    .bind(username)
    .bind(server_name)
    .bind(duration_hours)
    .bind(notes)
    .fetch_one(pool)
    .await?;

    Ok(request_id.0)
}

/// Get all pending access requests
pub async fn get_pending_requests(
    pool: &PgPool,
) -> Result<Vec<(i32, String, String, String, i32, Option<String>)>, sqlx::Error> {
    sqlx::query_as::<_, (i32, String, String, String, i32, Option<String>)>(
        r#"
        SELECT 
            ar.id,
            u.username,
            s.name,
            to_char(ar.requested_at, 'YYYY-MM-DD HH24:MI:SS'),
            ar.duration_hours,
            ar.notes
        FROM access_requests ar
        JOIN users u ON u.id = ar.user_id
        JOIN servers s ON s.id = ar.server_id
        WHERE ar.status = 'pending'
        ORDER BY ar.requested_at ASC
        "#,
    )
    .fetch_all(pool)
    .await
}

/// Get request details for approval
pub async fn get_request_details(
    pool: &PgPool,
    request_id: i32,
) -> Result<Option<(i32, i32, i32, String, String)>, sqlx::Error> {
    sqlx::query_as::<_, (i32, i32, i32, String, String)>(
        r#"
        SELECT ar.user_id, ar.server_id, ar.duration_hours, u.username, s.name
        FROM access_requests ar
        JOIN users u ON u.id = ar.user_id
        JOIN servers s ON s.id = ar.server_id
        WHERE ar.id = $1 AND ar.status = 'pending'
        "#,
    )
    .bind(request_id)
    .fetch_optional(pool)
    .await
}

/// Approve an access request
pub async fn approve_request(
    pool: &PgPool,
    request_id: i32,
    user_id: i32,
    server_id: i32,
    admin_username: &str,
    duration_hours: i32,
) -> Result<(), sqlx::Error> {
    let expires_at_sql = format!("NOW() + INTERVAL '{} hours'", duration_hours);

    // Create permission
    sqlx::query(&format!(
        r#"
        INSERT INTO permissions (user_id, server_id, expires_at)
        VALUES ($1, $2, {})
        ON CONFLICT (user_id, server_id) 
        DO UPDATE SET expires_at = EXCLUDED.expires_at
        "#,
        expires_at_sql
    ))
    .bind(user_id)
    .bind(server_id)
    .execute(pool)
    .await?;

    // Update request status
    sqlx::query(
        r#"
        UPDATE access_requests
        SET status = 'approved',
            approved_by = (SELECT id FROM users WHERE username = $1),
            approved_at = NOW(),
            expires_at = NOW() + INTERVAL '1 hour' * $2
        WHERE id = $3
        "#,
    )
    .bind(admin_username)
    .bind(duration_hours)
    .bind(request_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Deny an access request
pub async fn deny_request(
    pool: &PgPool,
    request_id: i32,
    admin_username: &str,
    reason: &str,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        r#"
        UPDATE access_requests
        SET status = 'denied',
            approved_by = (SELECT id FROM users WHERE username = $1),
            approved_at = NOW(),
            denial_reason = $2
        WHERE id = $3 AND status = 'pending'
        "#,
    )
    .bind(admin_username)
    .bind(reason)
    .bind(request_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

/// Get user's own requests
pub async fn get_user_requests(
    pool: &PgPool,
    username: &str,
) -> Result<
    Vec<(
        i32,
        String,
        String,
        String,
        i32,
        Option<String>,
        Option<String>,
    )>,
    sqlx::Error,
> {
    sqlx::query_as::<
        _,
        (
            i32,
            String,
            String,
            String,
            i32,
            Option<String>,
            Option<String>,
        ),
    >(
        r#"
        SELECT 
            ar.id,
            s.name,
            ar.status,
            to_char(ar.requested_at, 'YYYY-MM-DD HH24:MI:SS'),
            ar.duration_hours,
            to_char(ar.expires_at, 'YYYY-MM-DD HH24:MI:SS'),
            ar.denial_reason
        FROM access_requests ar
        JOIN users u ON u.id = ar.user_id
        JOIN servers s ON s.id = ar.server_id
        WHERE u.username = $1
        ORDER BY ar.requested_at DESC
        LIMIT 20
        "#,
    )
    .bind(username)
    .fetch_all(pool)
    .await
}
