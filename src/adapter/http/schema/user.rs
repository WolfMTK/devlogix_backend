use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_email::Email;
use validator::{Validate, ValidationError, ValidationErrors};

#[derive(Debug, Deserialize, Validate)]
pub struct CreateUserRequest {
    #[validate(length(
        min = 6,
        max = 50,
        message = "Username must be between 6 and 50 characters"
    ))]
    pub username: String,
    pub email: Email,
    pub password: ValidPassword,
}

#[derive(Debug, Serialize)]
pub struct GetUserResponse {
    pub id: String,
    pub username: String,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub email: Option<Email>,
    pub username: Option<String>,
    pub password: Option<ValidPassword>,
}

#[derive(Debug, Validate, Deserialize)]
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
    pub fn new(password: String) -> Result<Self, ValidationErrors> {
        let valid_password = ValidPassword { value: password };
        valid_password.validate()?;
        Ok(valid_password)
    }

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
