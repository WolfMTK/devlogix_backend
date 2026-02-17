use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_email::Email;
use utoipa::ToSchema;
use validator::{Validate, ValidationError};

use crate::adapter::http::schema::ValidPassword;

#[derive(Debug, Deserialize, Validate, ToSchema)]
#[schema(description = "Request payload to register a new user.")]
pub struct CreateUserRequest {
    #[validate(length(min = 6, max = 50, message = "Username must be between 6 and 50 characters"))]
    pub username: String,
    #[schema(value_type = String, format = Email, example = "user@example.com")]
    pub email: Email,
    #[schema(value_type = String, example = "Password123!")]
    #[validate(nested)]
    pub password1: ValidPassword,
    #[schema(value_type = String, example = "Password123!")]
    #[validate(nested)]
    pub password2: ValidPassword,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GetUserResponse {
    pub id: String,
    pub username: String,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
#[validate(schema(function = "validate_update_user_request"))]
#[schema(
    description = "Request payload to update user profile fields. If password1 is provided, old_password and password2 are required."
)]
pub struct UpdateUserRequest {
    #[schema(value_type = Option<String>, format = Email, example = "user@example.com")]
    pub email: Option<Email>,
    #[schema(example = "username")]
    #[validate(length(min = 6, max = 50, message = "Username must be between 6 and 50 characters"))]
    pub username: Option<String>,
    #[schema(value_type = Option<String>, example = "OldPassword123!")]
    #[validate(nested)]
    pub old_password: Option<ValidPassword>,
    #[schema(value_type = Option<String>, example = "NewPassword123!")]
    #[validate(nested)]
    pub password1: Option<ValidPassword>,
    #[schema(value_type = Option<String>, example = "NewPassword123!")]
    #[validate(nested)]
    pub password2: Option<ValidPassword>,
}

fn validate_update_user_request(req: &UpdateUserRequest) -> Result<(), ValidationError> {
    if req.password1.is_some() {
        if req.old_password.is_none() {
            return Err(ValidationError::new("old_password_empty"));
        }
        let password_match = match (&req.password1, &req.password2) {
            (Some(password1), Some(password2)) => password1.value() == password2.value(),
            _ => false,
        };
        if !password_match {
            return Err(ValidationError::new("invalid_password"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use serde_json::json;
    use validator::Validate;

    use crate::adapter::http::schema::user::UpdateUserRequest;

    #[rstest]
    fn test_update_user_password_requires_old_password() {
        let req = UpdateUserRequest {
            email: None,
            username: None,
            old_password: None,
            password1: serde_json::from_value(json!("Password123!")).ok(),
            password2: serde_json::from_value(json!("Password123!")).ok(),
        };
        assert!(req.validate().is_err());
    }

    #[rstest]
    fn test_update_user_passwords_must_match() {
        let req = UpdateUserRequest {
            email: None,
            username: None,
            old_password: serde_json::from_value(json!("OldPassword123!")).ok(),
            password1: serde_json::from_value(json!("Password123!")).ok(),
            password2: serde_json::from_value(json!("InvalidPassword123!")).ok(),
        };
        assert!(req.validate().is_err());
    }
}
