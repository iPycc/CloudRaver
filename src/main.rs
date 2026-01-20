mod config;
mod db;
mod error;
mod handlers;
mod middleware;
mod models;
mod services;
mod storage;

use handlers::{
    // admin, 
    auth, file, share, user,
};
// use middleware::auth::auth_middleware;

use axum::{
    extract::ConnectInfo,
    http::{Request, StatusCode},
    middleware::{self as axum_middleware, Next},
    response::Response,
    routing::{delete, get, post, put},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::Config;
use crate::db::Database;
use crate::storage::StorageManager;

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub config: Arc<Config>,
    pub storage: Arc<StorageManager>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cloudraver=info".into()),
        )
        .with(tracing_subscriber::fmt::layer().compact())
        .init();

    tracing::info!("Starting CloudRaver...");

    // Load configuration
    let config = Config::load()?;
    let config = Arc::new(config);
    tracing::info!("Configuration loaded");

    // Initialize database
    let db = Database::new(&config.database.path).await?;
    db.run_migrations().await?;
    tracing::info!("Database initialized");

    // Initialize storage manager
    let storage = Arc::new(StorageManager::new());

    // Create app state
    let state = AppState {
        db,
        config: config.clone(),
        storage,
    };

    // Build router
    let app = create_router(state);

    // Start server with ConnectInfo for IP tracking
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Server listening on {}", addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

/// Simple logging middleware with IP address
async fn logging_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let start = Instant::now();

    let response = next.run(req).await;

    let duration = start.elapsed();
    let status = response.status();

    // Simple log format: IP METHOD PATH STATUS DURATION
    tracing::info!(
        "{} {} {} {} {:?}",
        addr.ip(),
        method,
        uri.path(),
        status.as_u16(),
        duration
    );

    response
}

fn create_router(state: AppState) -> Router {
    // CORS configuration
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/auth/register", post(handlers::auth::register))
        .route("/auth/login", post(handlers::auth::login))
        .route("/auth/refresh", post(handlers::auth::refresh_token))
        .route("/avatar/:key", get(handlers::user::get_avatar_by_key))
        // Public share routes
        .route("/public/share/:token", get(handlers::share::get_public_share))
        .route("/public/share/:token/verify", post(handlers::share::verify_share))
        .route("/public/share/:token/download", get(handlers::share::download_public_share));

    // Protected routes (auth required)
    let protected_routes = Router::new()
        // Auth
        .route("/auth/logout", post(handlers::auth::logout))
        // User profile
        .route("/user/profile", get(handlers::user::get_profile).put(handlers::user::update_profile))
        .route("/user/password", put(handlers::user::change_password))
        .route("/user/storage", get(handlers::user::get_storage_usage))
        .route("/user/avatar", post(handlers::user::upload_avatar))
        // User sessions
        .route("/user/sessions", get(handlers::auth::list_sessions))
        .route("/user/sessions/:id", delete(handlers::auth::delete_session))
        .route("/user/sessions/others", delete(handlers::auth::delete_other_sessions))
        // Storage policies
        .route(
            "/storage/policies",
            get(handlers::storage::list_policies).post(handlers::storage::create_policy),
        )
        .route(
            "/storage/policies/validate",
            post(handlers::storage::validate_policy),
        )
        .route(
            "/storage/policies/:id",
            get(handlers::storage::get_policy)
                .put(handlers::storage::update_policy)
                .delete(handlers::storage::delete_policy),
        )
        .route(
            "/storage/policies/:id/default",
            put(handlers::storage::set_default_policy),
        )
        .route(
            "/storage/policies/:id/cors",
            post(handlers::storage::configure_cors),
        )
        // Files
        .route(
            "/files",
            get(handlers::file::list_files).post(handlers::file::create_directory),
        )
        .route("/files/multipart/init", post(handlers::multipart::init_multipart))
        .route("/files/multipart/sign", post(handlers::multipart::sign_part))
        .route("/files/multipart/complete", post(handlers::multipart::complete_multipart))
        .route("/files/multipart/abort", post(handlers::multipart::abort_multipart))
        .route("/files/upload", post(handlers::file::upload_file))
        .route(
            "/files/:id",
            get(handlers::file::get_file)
                .patch(handlers::file::rename_file)
                .delete(handlers::file::delete_file),
        )
        .route("/files/:id/download", get(handlers::file::download_file))
        // Trash routes
        .route("/files/trash", get(handlers::file::list_trash))
        .route("/files/trash/restore", post(handlers::file::restore_from_trash))
        .route("/files/trash/delete", post(handlers::file::delete_from_trash))
        .route("/files/trash/empty", post(handlers::file::empty_trash))
        // Admin routes
        .route("/admin/users", get(handlers::admin::list_users))
        .route(
            "/admin/users/:id/status",
            put(handlers::admin::update_user_status),
        )
        .route("/admin/users/:id/files", get(handlers::admin::get_user_files))
        .route(
            "/admin/users/:id/policies",
            get(handlers::admin::get_user_policies),
        )
        // Share routes (Authenticated)
        .route("/shares", post(handlers::share::create_share))
        .route("/shares/my", get(handlers::share::list_my_shares))
        .route("/shares/:id", delete(handlers::share::delete_share))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth::auth_middleware,
        ));

    // Combine all routes under /api/v1
    Router::new()
        .nest("/api/v1", public_routes.merge(protected_routes))
        .layer(axum_middleware::from_fn(logging_middleware))
        .layer(cors)
        .with_state(state)
}
