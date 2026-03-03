use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Router,
};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::env;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(sqlx::FromRow)]
struct SshKey {
    public_key: String,
    fingerprint: Option<String>,
}

/// GET /api/keys/:username
/// Returns active (non-revoked, non-expired) SSH public keys for a user
/// Output format: OpenSSH authorized_keys format (one key per line)
async fn get_user_keys(
    Path(username): Path<String>,
    State(pool): State<PgPool>,
) -> Result<String, StatusCode> {
    tracing::info!("Fetching keys for user: {}", username);

    let keys = sqlx::query_as::<_, SshKey>(
        "SELECT k.public_key, k.fingerprint
         FROM ssh_keys k
         JOIN users u ON u.id = k.user_id
         WHERE u.username = $1
           AND k.revoked_at IS NULL
           AND (k.expires_at IS NULL OR k.expires_at > NOW())
         ORDER BY k.created_at DESC",
    )
    .bind(&username)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        tracing::error!("Database error fetching keys for {}: {}", username, e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if keys.is_empty() {
        tracing::warn!("No active keys found for user: {}", username);
        // Return empty response (valid for SSH - means no keys authorized)
        return Ok(String::new());
    }

    // Return keys in OpenSSH authorized_keys format (one per line)
    let output = keys
        .iter()
        .map(|k| {
            let key = k.public_key.trim();
            if let Some(fp) = &k.fingerprint {
                // Prepend environment option to pass fingerprint to the session
                format!("environment=\"BASTION_KEY_FINGERPRINT={}\" {}", fp, key)
            } else {
                key.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    tracing::info!("Returned {} key(s) for user: {}", keys.len(), username);
    Ok(output)
}

/// Health check endpoint
async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

fn app(pool: PgPool) -> Router {
    Router::new()
        .route("/api/keys/:username", get(get_user_keys))
        .route("/health", get(health_check))
        .with_state(pool)
        .layer(TraceLayer::new_for_http())
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "bastion_api=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Get database URL from environment
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    tracing::info!("Connecting to database...");

    // Create connection pool
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to create pool");

    tracing::info!("Database connection established");

    // Build application
    let app = app(pool);

    // Bind to port
    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind");

    tracing::info!("Bastion API server listening on {}", addr);
    tracing::info!("Endpoints:");
    tracing::info!("   GET /api/keys/:username - Fetch SSH keys");
    tracing::info!("   GET /health - Health check");

    // Start server
    axum::serve(listener, app).await.expect("Server failed");
}
