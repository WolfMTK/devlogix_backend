#![cfg(test)]

use bytes::{Bytes, BytesMut};
use chrono::{Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::infra::state::AppState;

const BOUNDARY: &str = "TestBoundary";

pub fn unique_credentials() -> (String, String) {
    let id = Uuid::now_v7().as_simple().to_string();
    let username = format!("t_{}", &id[..16]);
    let email = format!("{}@test.example", &id[..16]);

    (username, email)
}

pub async fn find_user_by_email(pool: &PgPool, email: &str) -> Option<Uuid> {
    sqlx::query_scalar::<_, Uuid>("SELECT id FROM users WHERE email = $1")
        .bind(email)
        .fetch_optional(pool)
        .await
        .expect("find user by email")
}

pub async fn delete_user(pool: &PgPool, user_id: Uuid) {
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .expect("delete user");
}

pub async fn hash_password(state: &AppState, password: &str) -> String {
    state.hasher.hash_password(password).await.expect("hash password")
}

pub async fn insert_confirmed_user(pool: &PgPool, username: &str, email: &str, hashed_password: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO users (username, email, password, is_confirmed) VALUES ($1, $2, $3, true) RETURNING id",
    )
    .bind(username)
    .bind(email)
    .bind(hashed_password)
    .fetch_one(pool)
    .await
    .expect("insert confirmed user")
}

pub fn session_cookie(session_id: Uuid, cookie_name: &str) -> String {
    format!("{}={}", cookie_name, session_id)
}

pub async fn insert_session(pool: &PgPool, user_id: Uuid) -> Uuid {
    sqlx::query_scalar::<_, Uuid>("INSERT INTO sessions (user_id) VALUES ($1) RETURNING id")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("insert session")
}

pub async fn insert_unconfirmed_user(pool: &PgPool, username: &str, email: &str, hashed_password: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>("INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id")
        .bind(username)
        .bind(email)
        .bind(hashed_password)
        .fetch_one(pool)
        .await
        .expect("insert unconfirmed user")
}

pub async fn insert_email_confirmation(pool: &PgPool, user_id: Uuid, token: &str) {
    let expires_at = Utc::now() + Duration::hours(24);
    sqlx::query("INSERT INTO email_confirmations (user_id, token, expires_at) VALUES ($1, $2, $3)")
        .bind(user_id)
        .bind(token)
        .bind(expires_at)
        .execute(pool)
        .await
        .expect("insert email confirmation");
}

pub async fn insert_password_reset_token(pool: &PgPool, user_id: Uuid, token: &str) {
    let expires_at = Utc::now() + Duration::hours(1);
    sqlx::query("INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)")
        .bind(user_id)
        .bind(token)
        .bind(expires_at)
        .execute(pool)
        .await
        .expect("insert password reset token");
}

pub fn build_multipart_body(fields: &[(&str, &str)]) -> Bytes {
    let mut body = BytesMut::new();
    for (name, value) in fields {
        body.extend_from_slice(format!("--{}\r\n", BOUNDARY).as_bytes());
        body.extend_from_slice(format!("Content-Disposition: form-data; name=\"{}\"\r\n\r\n", name).as_bytes());
        body.extend_from_slice(format!("{}\r\n", value).as_bytes());
    }
    body.extend_from_slice(format!("--{}--\r\n", BOUNDARY).as_bytes());
    body.freeze()
}

pub fn multipart_content_type() -> String {
    format!("multipart/form-data; boundary={}", BOUNDARY)
}

pub async fn find_workspace_id(pool: &PgPool, owner_user_id: Uuid) -> Option<Uuid> {
    sqlx::query_scalar::<_, Uuid>("SELECT id FROM workspaces WHERE owner_user_id = $1 ORDER BY created_at DESC LIMIT 1")
        .bind(owner_user_id)
        .fetch_optional(pool)
        .await
        .expect("find workspace id")
}

pub async fn find_workspace_id_and_slug(pool: &PgPool, owner_user_id: Uuid) -> Option<(Uuid, String)> {
    sqlx::query_as::<_, (Uuid, String)>(
        "SELECT id, slug FROM workspaces WHERE owner_user_id = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(owner_user_id)
    .fetch_optional(pool)
    .await
    .expect("find workspace id and slug")
}
