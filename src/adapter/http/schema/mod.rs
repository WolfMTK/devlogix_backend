pub mod auth;
pub mod email_confirmation;
pub mod id;
pub mod pagination;
pub mod password_reset;
pub mod user;
pub mod workspace;

use serde::Deserialize;
use utoipa::ToSchema;
use validator::{Validate, ValidationError};

#[derive(Debug, Validate, Deserialize, ToSchema)]
#[serde(transparent)]
#[schema(
    description = "Validated password string. Validation rules: min length 8, at least one uppercase letter, one digit, and one special character."
)]
pub struct ValidPassword {
    #[validate(
        length(min = 8, message = "Password must be at least 8 characters long"),
        custom(
            function = "has_uppercase_letter",
            message = "Password must contain at least one uppercase letter (A-Z)"
        ),
        custom(function = "has_digit", message = "Password must contain at least one digit (0-9)"),
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
    use rstest::rstest;
    use serde_json::json;
    use validator::Validate;

    use crate::adapter::http::schema::ValidPassword;

    #[rstest]
    fn test_valid_password_success() {
        let passwords = vec!["Password123!", "MyP@ssw0rd", "Pa0!Pass", "Test123$", "P@!s0Word"];
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

        assert!(is_invalid, "Password `{}` should fail ({})", password, message)
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
}
