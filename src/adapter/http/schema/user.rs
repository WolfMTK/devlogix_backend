use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_email::Email;
use utoipa::ToSchema;
use validator::{Validate, ValidationError};

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateUserRequest {
    #[validate(length(
        min = 6,
        max = 50,
        message = "Username must be between 6 and 50 characters"
    ))]
    pub username: String,
    #[schema(value_type = String, format = Email)]
    pub email: Email,
    #[validate(nested)]
    pub password1: ValidPassword,
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
pub struct UpdateUserRequest {
    #[schema(value_type = Option<String>, format = Email)]
    pub email: Option<Email>,
    #[validate(length(
        min = 6,
        max = 50,
        message = "Username must be between 6 and 50 characters"
    ))]
    pub username: Option<String>,
    #[validate(nested)]
    pub old_password: Option<ValidPassword>,
    #[validate(nested)]
    pub password1: Option<ValidPassword>,
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

#[derive(Debug, Validate, Deserialize, ToSchema)]
#[serde(transparent)]
pub struct ValidPassword {
    #[validate(
        length(min = 8, message = "Password must be at least 8 characters long"),
        custom(
            function = "has_uppercase_letter",
            message = "Password must contain at least one uppercase letter (A-Z)"
        ),
        custom(
            function = "has_digit",
            message = "Password must contain at least one digit (0-9)"
        ),
        custom(
            function = "has_special_char",
            message = "Password must contain at least one special character (!@#$%^&* etc.)"
        )
    )]
    value: String,
}

impl ValidPassword {
    pub fn value(&self) -> &str {
        &self.value
    }
}

fn has_uppercase_letter(password: &str) -> Result<(), ValidationError> {
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        return Ok(());
    }
    Err(ValidationError::new("password_no_uppercase"))
}

fn has_digit(password: &str) -> Result<(), ValidationError> {
    if password.chars().any(|c| c.is_ascii_digit()) {
        return Ok(());
    }
    Err(ValidationError::new("password_no_digit"))
}

fn has_special_char(password: &str) -> Result<(), ValidationError> {
    let special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?~`";

    if password.chars().any(|c| special_chars.contains(c)) {
        return Ok(());
    }
    Err(ValidationError::new("password_no_special_char"))
}

#[cfg(test)]
mod tests {
    use crate::adapter::http::schema::user::{UpdateUserRequest, ValidPassword};
    use rstest::rstest;
    use serde_json::json;
    use validator::Validate;

    #[rstest]
    fn test_valid_password_success() {
        let passwords = vec![
            "Password123!",
            "MyP@ssw0rd",
            "Pa0!Pass",
            "Test123$",
            "P@!s0Word",
        ];
        let all_valid = passwords.iter().all(|&password| {
            if let Ok(valid_pwd) = serde_json::from_value::<ValidPassword>(json!(password)) {
                valid_pwd.validate().is_ok()
            } else {
                false
            }
        });
        assert!(all_valid, "All passwords should be valid")
    }

    #[rstest]
    #[case("Pass1!", "too short")]
    #[case("password123!", "no uppercase")]
    #[case("Password!", "no digit")]
    #[case("Password123", "no special char")]
    fn test_password_invalid(#[case] password: &str, #[case] message: &str) {
        let result = serde_json::from_value::<ValidPassword>(json!(password));

        let is_invalid = match result {
            Ok(pwd) => pwd.validate().is_err(),
            Err(_) => true,
        };

        assert!(
            is_invalid,
            "Password `{}` should fail ({})",
            password, message
        )
    }

    #[rstest]
    fn test_password_value_getter() {
        let password = "Password123!";
        let result = serde_json::from_value::<ValidPassword>(json!(password));
        assert_eq!(result.unwrap().value(), password);
    }

    #[rstest]
    fn test_password_unicode_characters() {
        let password = "Пароль123!";
        let result = serde_json::from_value::<ValidPassword>(json!(password));

        let is_invalid = match result {
            Ok(pwd) => pwd.validate().is_err(),
            Err(_) => true,
        };

        assert!(is_invalid);
    }

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
