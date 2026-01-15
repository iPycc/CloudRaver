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
    routing::{delete, get, post, put},
    Router,
};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
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
                .unwrap_or_else(|_| "cloudraver=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
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

    // Start server
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Server listening on {}", addr);

    axum::serve(listener, app).await?;

    Ok(())
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
        .route("/user/profile", get(handlers::user::get_profile))
        .route("/user/password", put(handlers::user::change_password))
        .route("/user/storage", get(handlers::user::get_storage_usage))
        .route("/user/avatar", post(handlers::user::upload_avatar))
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
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}
