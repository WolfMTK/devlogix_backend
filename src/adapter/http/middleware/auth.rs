use crate::{
    adapter::http::middleware::extractor::AuthUser,
    application::{
        app_error::{AppError, AppResult},
        dto::session::{SessionDTO, SessionValidationResult},
        interactors::session::ValidateSessionInteractor,
    },
    infra::config::{AppConfig, SessionConfig},
};
use axum::{
    extract::{Request, State},
    http::header::SET_COOKIE,
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct SessionRotation {
    pub new_session_id: String,
    pub remember_me: bool,
}

pub async fn auth_middleware(
    State(config): State<Arc<AppConfig>>,
    interactor: ValidateSessionInteractor,
    mut request: Request,
    next: Next,
) -> AppResult<Response> {
    let config_session = &config.session;
    let session_id = extract_session_id(&request, &config_session.cookie_name)?;
    let dto = SessionDTO {
        id: session_id,
        default_max_lifetime: config_session.default_max_lifetime,
        default_idle_timeout: config_session.default_idle_timeout,
        remembered_max_lifetime: config_session.remembered_max_lifetime,
        remembered_idle_timeout: config_session.remembered_idle_timeout,
        rotation_interval: config_session.rotation_interval,
    };
    let result = interactor.execute(dto).await?;
    match result.status {
        SessionValidationResult::Valid(user_id) => {
            request.extensions_mut().insert(AuthUser {
                user_id: user_id.value.to_string(),
            });
        }
        SessionValidationResult::Rotated {
            user_id,
            new_session_id,
        } => {
            request.extensions_mut().insert(AuthUser {
                user_id: user_id.value.to_string(),
            });
            request.extensions_mut().insert(SessionRotation {
                new_session_id: new_session_id.value.to_string(),
                remember_me: true,
            });
        }
        SessionValidationResult::Expired => {
            return Err(AppError::InvalidCredentials);
        }
        SessionValidationResult::Invalid => {
            return Err(AppError::InvalidCredentials);
        }
    }

    Ok(next.run(request).await)
}

fn extract_session_id(request: &Request, cookie_name: &str) -> AppResult<String> {
    let cookie_header = request
        .headers()
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::InvalidCredentials)?;

    for cookie in cookie_header.split(";") {
        let cookie = cookie.trim();
        if let Some(value) = cookie.strip_prefix(&format!("{}=", cookie_name)) {
            return Ok(value.to_string());
        }
    }

    Err(AppError::InvalidCredentials)
}

pub async fn session_cookie_middleware(
    State(config): State<Arc<AppConfig>>,
    request: Request,
    next: Next,
) -> Response {
    let rotated = request.extensions().get::<SessionRotation>().cloned();
    let mut response = next.run(request).await;
    if let Some(rotated) = rotated {
        let cookie = build_session_cookie(
            &rotated.new_session_id,
            rotated.remember_me,
            &config.session,
        );

        if let Ok(value) = cookie.parse() {
            response.headers_mut().insert(SET_COOKIE, value);
        }
    }
    response
}

pub fn build_session_cookie(session_id: &str, remember_me: bool, config: &SessionConfig) -> String {
    let max_age = if remember_me {
        config.remembered_max_lifetime
    } else {
        config.default_max_lifetime
    };

    let secure = if config.cookie_secure { "; Secure" } else { "" };
    let http_only = if config.cookie_http_only {
        "; HttpOnly"
    } else {
        ""
    };
    format!(
        "{}={}; Path=/; Max-Age={}; SameSite=Lax{}{}",
        config.cookie_name, session_id, max_age, secure, http_only
    )
}

pub fn build_logout_cookie(config: &SessionConfig) -> String {
    format!("{}=; Path=/; Max-Age=0; SameSite=Lax", config.cookie_name)
}
