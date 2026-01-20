use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};

use crate::error::Result;

/// Database connection pool wrapper
#[derive(Clone)]
pub struct Database {
    pool: SqlitePool,
}

impl Database {
    /// Create a new database connection
    pub async fn new(path: &str) -> Result<Self> {
        // Create database URL
        let url = format!("sqlite:{}?mode=rwc", path);

        // Use only 1 connection to avoid SQLite locking issues
        // SQLite works best with a single writer
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .after_connect(|conn, _meta| {
                Box::pin(async move {
                    use sqlx::Executor;
                    // WAL mode for better concurrency
                    conn.execute("PRAGMA journal_mode=WAL;").await?;
                    // Wait up to 30 seconds when database is locked
                    conn.execute("PRAGMA busy_timeout=30000;").await?;
                    // Faster writes with acceptable safety
                    conn.execute("PRAGMA synchronous=NORMAL;").await?;
                    // Store temp tables in memory
                    conn.execute("PRAGMA temp_store=MEMORY;").await?;
                    // Larger cache for better performance
                    conn.execute("PRAGMA cache_size=-64000;").await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await?;

        Ok(Self { pool })
    }

    /// Get the connection pool
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Run database migrations
    pub async fn run_migrations(&self) -> Result<()> {
        // Create tables
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL DEFAULT '',
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                default_policy_id TEXT,
                storage_used INTEGER NOT NULL DEFAULT 0,
                storage_limit INTEGER NOT NULL DEFAULT 10737418240,
                is_active INTEGER NOT NULL DEFAULT 1,
                token_version INTEGER NOT NULL DEFAULT 0,
                avatar_key TEXT,
                avatar_path TEXT,
                avatar_mime TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Backward-compatible columns for existing databases
        let _ = sqlx::query("ALTER TABLE users ADD COLUMN avatar_key TEXT")
            .execute(&self.pool)
            .await;
        let _ = sqlx::query("ALTER TABLE users ADD COLUMN avatar_path TEXT")
            .execute(&self.pool)
            .await;
        let _ = sqlx::query("ALTER TABLE users ADD COLUMN avatar_mime TEXT")
            .execute(&self.pool)
            .await;
        let _ = sqlx::query("ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0")
            .execute(&self.pool)
            .await;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS storage_policies (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                policy_type TEXT NOT NULL,
                config TEXT NOT NULL,
                is_default INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                parent_id TEXT,
                name TEXT NOT NULL,
                is_dir INTEGER NOT NULL DEFAULT 0,
                size INTEGER NOT NULL DEFAULT 0,
                policy_id TEXT,
                mime_type TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                deleted_at TEXT,
                original_parent_id TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (parent_id) REFERENCES files(id) ON DELETE CASCADE,
                FOREIGN KEY (policy_id) REFERENCES storage_policies(id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Add trash columns for existing databases
        let _ = sqlx::query("ALTER TABLE files ADD COLUMN deleted_at TEXT")
            .execute(&self.pool)
            .await;
        let _ = sqlx::query("ALTER TABLE files ADD COLUMN original_parent_id TEXT")
            .execute(&self.pool)
            .await;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS file_blobs (
                id TEXT PRIMARY KEY,
                file_id TEXT NOT NULL,
                policy_id TEXT NOT NULL,
                storage_path TEXT NOT NULL,
                size INTEGER NOT NULL,
                hash TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
                FOREIGN KEY (policy_id) REFERENCES storage_policies(id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                device_info TEXT,
                ip_address TEXT,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Add ip_address column for existing databases
        let _ = sqlx::query("ALTER TABLE refresh_tokens ADD COLUMN ip_address TEXT")
            .execute(&self.pool)
            .await;

        // Create indexes
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_files_user_id ON files(user_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_files_parent_id ON files(parent_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_files_deleted_at ON files(deleted_at)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_storage_policies_user_id ON storage_policies(user_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_file_blobs_file_id ON file_blobs(file_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_avatar_key ON users(avatar_key)")
            .execute(&self.pool)
            .await?;

        // Shares table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS shares (
                id TEXT PRIMARY KEY,
                file_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                token TEXT UNIQUE NOT NULL,
                password_hash TEXT,
                views INTEGER NOT NULL DEFAULT 0,
                max_views INTEGER,
                expires_at TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_shares_token ON shares(token)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_shares_user_id ON shares(user_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_shares_file_id ON shares(file_id)")
            .execute(&self.pool)
            .await?;

        tracing::info!("Database migrations completed");
        Ok(())
    }
}
