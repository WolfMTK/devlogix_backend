use crate::{
    adapter::http::{
        middleware::extractor::AuthUser,
        schema::{
            id::IdResponse,
            user::{CreateUserRequest, GetUserResponse},
        },
        validation::ValidJson,
    },
    application::{
        app_error::AppResult,
        dto::{id::IdDTO, user::CreateUserDTO},
        interactors::users::{CreateUserInteractor, GetMeInteractor},
    },
};
use axum::{Json, http::StatusCode, response::IntoResponse};

pub async fn register(
    interactor: CreateUserInteractor,
    ValidJson(payload): ValidJson<CreateUserRequest>,
) -> AppResult<impl IntoResponse> {
    let dto = CreateUserDTO {
        username: payload.username,
        email: payload.email.to_string(),
        password: payload.password,
    };
    let user_id = interactor.execute(dto).await?;
    let response = IdResponse { id: user_id.id };
    Ok((StatusCode::OK, Json(response)))
}

pub async fn get_me(
    auth_user: AuthUser,
    interactor: GetMeInteractor,
) -> AppResult<impl IntoResponse> {
    let dto = IdDTO {
        id: auth_user.user_id,
    };
    let user = interactor.execute(dto).await?;
    let response = GetUserResponse {
        id: user.id,
        username: user.username,
        email: user.email,
        created_at: user.created_at,
        updated_at: user.updated_at,
    };
    Ok((StatusCode::OK, Json(response)))
}
