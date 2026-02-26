use serde::Deserialize;
use serde_email::Email;
use serde_json::json;
use utoipa::ToSchema;
use validator::Validate;

use crate::adapter::http::schema::ValidPassword;

#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({ "email": "user@example.com" }))]
pub struct ForgotPasswordResetRequest {
    #[schema(value_type = String, format = Email, example = "user@example.com")]
    pub email: Email,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
#[schema(example = json!({
    "token": "a1b2c3d4e5f6",
    "password": "NewPassword123!"
}))]
pub struct ResetPasswordRequest {
    #[schema(example = "a1b2c3d4e5f6")]
    pub token: String,
    #[schema(value_type = String, example = "NewPassword123!")]
    #[validate(nested)]
    pub password: ValidPassword,
}
