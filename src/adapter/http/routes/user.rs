use crate::{
    adapter::http::{
        schema::id::IdResponse,
        schema::user::CreateUserRequest
    },
    application::{
        app_error::AppResult,
        dto::user::CreateUserDTO,
        interactors::users::CreateUserInteractor
    }
};
use axum::{
    http::StatusCode,
    response::IntoResponse,
    Json
};

pub async fn register(
    interactor: CreateUserInteractor,
    Json(payload): Json<CreateUserRequest>,
) -> AppResult<impl IntoResponse> {
    let dto = CreateUserDTO {
        username: payload.username,
        email: payload.email,
        password: payload.password,
    };
    let user_id = interactor.execute(dto).await?;
    let response = IdResponse {
      id: user_id.id,
    };
    Ok((StatusCode::OK, Json(response)))
}
