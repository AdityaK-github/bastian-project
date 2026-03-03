// Session management and SSH connection handling

use sqlx::PgPool;
use std::process::{Command, Stdio};

/// Creates a new session record and returns the new session's ID.
pub async fn create_session(
    pool: &PgPool,
    username: &str,
    server_name: &str,
    permission_id: i32,
    client_ip: Option<&str>,
    ssh_key_fingerprint: Option<&str>,
) -> Result<i32, sqlx::Error> {
    let record = sqlx::query_as::<_, (i32,)>(
        r#"
        INSERT INTO sessions (user_id, server_id, permission_id, client_ip, ssh_key_fingerprint)
        VALUES (
            (SELECT id FROM users WHERE username = $1),
            (SELECT id FROM servers WHERE name = $2),
            $3,
            $4::inet,
            $5
        )
        RETURNING id
        "#,
    )
    .bind(username)
    .bind(server_name)
    .bind(permission_id)
    .bind(client_ip)
    .bind(ssh_key_fingerprint)
    .fetch_one(pool)
    .await?;

    Ok(record.0)
}

/// Updates a session record with an end_time and status.
pub async fn finalize_session(
    pool: &PgPool,
    session_id: i32,
    success: bool,
) -> Result<(), sqlx::Error> {
    let status = if success { "closed" } else { "error" };

    sqlx::query(
        r#"
        UPDATE sessions
        SET end_time = NOW(), status = $1
        WHERE id = $2
        "#,
    )
    .bind(status)
    .bind(session_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Connect to a server via SSH with session recording
pub async fn connect_to_server(
    pool: &PgPool,
    username: &str,
    server_address: &str,
    server_name: &str,
    permission_id: i32,
    client_ip: Option<&str>,
    ssh_key_fingerprint: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create a Session Record in the DB
    let session_id = create_session(
        pool,
        username,
        server_name,
        permission_id,
        client_ip,
        ssh_key_fingerprint,
    )
    .await?;
    let log_file = format!("/var/log/bastion/session-{}.log", session_id);

    println!(
        "--> Starting recorded session {}. Log: {}",
        session_id, log_file
    );

    // Start the SSH Proxy Session
    let ssh_command = format!("ssh -o StrictHostKeyChecking=no {}", server_address);
    let mut child = Command::new("script")
        .arg("-qf")
        .arg(&log_file)
        .arg("-c")
        .arg(&ssh_command)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    let status = child.wait()?;

    // Finalize the Session Record
    finalize_session(pool, session_id, status.success()).await?;
    println!("--> Session {} ended.", session_id);

    Ok(())
}
