#![cfg(test)]

use sqlx::PgPool;
use uuid::Uuid;

use crate::infra::state::AppState;

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
