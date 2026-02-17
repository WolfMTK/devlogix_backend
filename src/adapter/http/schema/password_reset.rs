use serde::Deserialize;
use serde_email::Email;
use utoipa::ToSchema;
use validator::Validate;

use crate::adapter::http::schema::ValidPassword;

#[derive(Debug, Deserialize, ToSchema)]
pub struct ForgotPasswordResetRequest {
    #[schema[value_type = String, format = Email, example = "user@example.com"]]
    pub email: Email,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ResetPasswordRequest {
    pub token: String,
    #[schema(value_type = String)]
    #[validate(nested)]
    pub password: ValidPassword,
}
