use crate::{
    adapter::http::{
        middleware::{
            auth::{
                build_logout_cookie,
                build_session_cookie
            },
            extractor::AuthUser
        },
        schema::auth::{LoginRequest, MessageResponse}
    },
    application::{
        app_error::AppResult,
        dto::{
            auth::LoginDTO,
            id::IdDTO
        },
        interactors::auth::{
            LoginInteractor,
            LogoutInteractor
        }
    },
    infra::config::AppConfig
};
use axum::{
    extract::State,
    http::{header::SET_COOKIE, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    Json,
};
use std::sync::Arc;

pub async fn login(
    interactor: LoginInteractor,
    State(config): State<Arc<AppConfig>>,
    Json(payload): Json<LoginRequest>,
) -> AppResult<impl IntoResponse> {
    let dto = LoginDTO {
        email: payload.email.to_string(),
        password: payload.password,
        remember_me: payload.remember_me,
    };
    let result = interactor.execute(dto).await?;
    let cookie = build_session_cookie(&result.session_id, result.remember_me, &config.session);
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, HeaderValue::from_str(&cookie)?);
    Ok((
        StatusCode::OK,
        headers,
        Json(MessageResponse {
            message: "Login successful".to_string(),
        }),
    ))
}

pub async fn logout(
    auth_user: AuthUser,
    interactor: LogoutInteractor,
    State(config): State<Arc<AppConfig>>,
) -> AppResult<impl IntoResponse> {
    let cookie = build_logout_cookie(&config.session);
    let dto = IdDTO {
        id: auth_user.user_id,
    };
    interactor.execute(dto).await?;
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, HeaderValue::from_str(&cookie)?);
    Ok((
        StatusCode::OK,
        headers,
        Json(MessageResponse {
            message: "Logged out successfully".to_string(),
        }),
    ))
}
