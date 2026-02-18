use std::collections::BTreeMap;

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::json;
use utoipa::ToSchema;
use validator::{ValidationErrors, ValidationErrorsKind};

use crate::application::app_error::AppError;

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            // BAD REQUEST
            AppError::InvalidId(_) => (StatusCode::BAD_REQUEST, None),
            AppError::AxumJsonRejection(_) => (StatusCode::BAD_REQUEST, Some(self.to_string())),
            AppError::UserAlreadyExists => (StatusCode::BAD_REQUEST, Some(self.to_string())),
            AppError::DatabaseError(_) => (StatusCode::BAD_REQUEST, None),
            AppError::ValidationError(_) => (StatusCode::BAD_REQUEST, None),
            AppError::InvalidPassword => (StatusCode::BAD_REQUEST, Some(self.to_string())),
            AppError::OldPasswordEmpty => (StatusCode::BAD_REQUEST, Some(self.to_string())),
            AppError::InvalidOldPassword => (StatusCode::BAD_REQUEST, Some(self.to_string())),
            AppError::InvalidConfirmationToken => (StatusCode::BAD_REQUEST, Some(self.to_string())),
            AppError::ConfirmationTokenExpired => (StatusCode::BAD_REQUEST, Some(self.to_string())),
            AppError::EmailSendError(_) => (StatusCode::BAD_REQUEST, Some(self.to_string())),
            AppError::InvalidResetToken => (StatusCode::BAD_REQUEST, Some(self.to_string())),
            AppError::ResetTokenAlreadyUsed => (StatusCode::BAD_REQUEST, Some(self.to_string())),
            AppError::ResetTokenExpired => (StatusCode::BAD_REQUEST, Some(self.to_string())),
            AppError::InvalidVisibility(_) => (StatusCode::BAD_REQUEST, Some(self.to_string())),
            AppError::CreatedWorkspaceError => (StatusCode::BAD_REQUEST, Some(self.to_string())),
            AppError::UnsupportedImageFormat => (StatusCode::BAD_REQUEST, Some(self.to_string())),

            // NOT FOUND
            AppError::StorageNotFound => (StatusCode::NOT_FOUND, Some(self.to_string())),

            // FORBIDDEN
            AppError::EmailNotConfirmed => (StatusCode::FORBIDDEN, Some(self.to_string())),

            // UNAUTHORIZED
            AppError::InvalidCredentials => (StatusCode::UNAUTHORIZED, Some(self.to_string())),

            // CONFLICT
            AppError::EmailAlreadyConfirmed => (StatusCode::CONFLICT, Some(self.to_string())),

            // INTERNAL_SERVER_ERROR
            _ => (StatusCode::INTERNAL_SERVER_ERROR, None),
        };

        let error = match &self {
            AppError::ValidationError(errors) => {
                let validation_error = build_validation_error_details(errors);
                validation_error.unwrap_or_else(|| ErrorDetails::Message("Validation failed".to_string()))
            }
            _ => {
                let message = match message {
                    Some(msg) => msg,
                    None => status.canonical_reason().unwrap_or_else(|| "Unknown error").to_string(),
                };

                ErrorDetails::Message(message)
            }
        };

        let body = Json(json!({
            "error": error
        }));

        (status, body).into_response()
    }
}

fn build_validation_error_details(errors: &ValidationErrors) -> Option<ErrorDetails> {
    let mut field_messages: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut global_messages: Vec<String> = Vec::new();

    collect_validation_errors(errors, None, &mut field_messages, &mut global_messages);

    if !field_messages.is_empty() {
        let normalized = field_messages
            .into_iter()
            .map(|(field, messages)| {
                let value = if messages.len() == 1 {
                    FieldErrorValue::Single(messages.into_iter().next().unwrap_or_default())
                } else {
                    FieldErrorValue::Multiple(messages)
                };
                (field, value)
            })
            .collect::<BTreeMap<_, _>>();

        return Some(ErrorDetails::Fields(normalized));
    }

    if !global_messages.is_empty() {
        if global_messages.len() == 1 {
            return global_messages.into_iter().next().map(ErrorDetails::Message);
        }
        return Some(ErrorDetails::Fields(BTreeMap::from([(
            "general".to_string(),
            FieldErrorValue::Multiple(global_messages),
        )])));
    }

    None
}

fn collect_validation_errors(
    errors: &ValidationErrors,
    parent: Option<&str>,
    field_messages: &mut BTreeMap<String, Vec<String>>,
    global_messages: &mut Vec<String>,
) {
    errors.errors().iter().for_each(|(field, kind)| {
        let path = match parent {
            Some(parent_field) => format!("{parent_field}.{field}"),
            None => field.to_string(),
        };

        match kind {
            ValidationErrorsKind::Field(validation_errors) => {
                validation_errors.iter().for_each(|validation_error| {
                    let (normalized_field, message) = map_error_target(
                        path.as_str(),
                        validation_error.code.as_ref(),
                        validation_error
                            .message
                            .as_ref()
                            .map(ToString::to_string)
                            .unwrap_or_else(|| format_validation_code(validation_error.code.as_ref())),
                    );

                    if let Some(field_name) = normalized_field {
                        push_unique_field_message(field_messages, field_name, message);
                    } else {
                        push_unique_global_message(global_messages, message);
                    }
                });
            }
            ValidationErrorsKind::Struct(struct_errors) => {
                collect_validation_errors(struct_errors, Some(path.as_str()), field_messages, global_messages);
            }
            ValidationErrorsKind::List(list_errors) => {
                list_errors.iter().for_each(|(index, item_errors)| {
                    let list_path = format!("{path}[{index}]");
                    collect_validation_errors(item_errors, Some(list_path.as_str()), field_messages, global_messages);
                });
            }
        }
    });
}

fn push_unique_field_message(field_messages: &mut BTreeMap<String, Vec<String>>, field_name: String, message: String) {
    let messages = field_messages.entry(field_name).or_default();
    if !messages.iter().any(|existing| existing == &message) {
        messages.push(message);
    }
}

fn push_unique_global_message(global_messages: &mut Vec<String>, message: String) {
    if !global_messages.iter().any(|existing| existing == &message) {
        global_messages.push(message);
    }
}

fn map_error_target(path: &str, code: &str, message: String) -> (Option<String>, String) {
    if code == "invalid_password" {
        return (Some("password".to_string()), "Passwords does not match".to_string());
    }

    if code == "old_password_empty" {
        return (
            Some("old_password".to_string()),
            "The old password field is required when changing password".to_string(),
        );
    }

    let normalized = path.trim_end_matches(".value").split('.').next().map(str::to_string);

    match normalized.as_deref() {
        Some("password1") | Some("password2") => (Some("password".to_string()), message),
        Some("__all__") => (None, message),
        Some(field) => (Some(field.to_string()), message),
        None => (None, message),
    }
}

fn format_validation_code(code: &str) -> String {
    match code {
        "old_password_empty" => "The old password field is required when changing password".to_string(),
        "invalid_password" => "Passwords does not match".to_string(),
        _ => "Validation failed".to_string(),
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(untagged)]
pub enum ErrorDetails {
    #[schema(example = "Invalid Credentials")]
    Message(String),
    #[schema(example = json!({"password": ["Password must contain at least one uppercase letter (A-Z)", "Passwords does not match"], "old_password": "The old password field is required when changing password"}))]
    Fields(BTreeMap<String, FieldErrorValue>),
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(untagged)]
pub enum FieldErrorValue {
    #[schema(example = "Username must be between 6 and 50 characters")]
    Single(String),
    #[schema(example = json!(["Password must be at least 8 characters long", "Password must contain at least one uppercase letter (A-Z)"]))]
    Multiple(Vec<String>),
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorResponse {
    pub error: ErrorDetails,
}

#[cfg(test)]
mod tests {
    use axum::body;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use serde_json::Value;
    use validator::{Validate, ValidationError};

    use crate::application::app_error::AppError;

    #[derive(Validate)]
    struct MultiMessagePasswordValidation {
        #[validate(length(min = 8, message = "Password must be at least 8 characters long"))]
        password1: String,
        #[validate(custom(function = "always_invalid", message = "Passwords does not match"))]
        password2: String,
    }

    fn always_invalid(_: &str) -> Result<(), ValidationError> {
        Err(ValidationError::new("invalid_password"))
    }

    #[tokio::test]
    async fn validation_error_password_fields_are_merged_to_password() {
        let payload = MultiMessagePasswordValidation {
            password1: "short".to_string(),
            password2: "whatever".to_string(),
        };

        let response = AppError::ValidationError(payload.validate().unwrap_err()).into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let bytes = body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&bytes).unwrap();

        assert!(json["error"].is_object());
        assert!(json["error"]["password"].is_array());
        let password_errors = json["error"]["password"].as_array().unwrap();
        assert_eq!(password_errors.len(), 2);
        assert!(
            password_errors
                .iter()
                .any(|v| v == "Password must be at least 8 characters long")
        );
        assert!(password_errors.iter().any(|v| v == "Passwords does not match"));
        assert!(json["error"].get("password1").is_none());
        assert!(json["error"].get("password2").is_none());
    }

    #[derive(Validate)]
    struct SingleFieldValidation {
        #[validate(length(min = 3, message = "username too short"))]
        username: String,
    }

    #[tokio::test]
    async fn validation_error_single_field_returns_object_with_string() {
        let payload = SingleFieldValidation {
            username: "ab".to_string(),
        };

        let response = AppError::ValidationError(payload.validate().unwrap_err()).into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let bytes = body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&bytes).unwrap();

        assert!(json["error"].is_object());
        assert_eq!(json["error"]["username"], "username too short");
    }

    fn require_uppercase(value: &str) -> Result<(), ValidationError> {
        if value.chars().any(|c| c.is_ascii_uppercase()) {
            Ok(())
        } else {
            Err(ValidationError::new("password_no_uppercase"))
        }
    }

    fn require_special(value: &str) -> Result<(), ValidationError> {
        if value.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?~`".contains(c)) {
            Ok(())
        } else {
            Err(ValidationError::new("password_no_special_char"))
        }
    }

    #[derive(Validate)]
    struct DuplicatePasswordMessageValidation {
        #[validate(
            custom(
                function = "require_uppercase",
                message = "Password must contain at least one uppercase letter (A-Z)"
            ),
            custom(
                function = "require_special",
                message = "Password must contain at least one special character (!@#$%^&* etc.)"
            )
        )]
        password1: String,
        #[validate(
            custom(
                function = "require_uppercase",
                message = "Password must contain at least one uppercase letter (A-Z)"
            ),
            custom(
                function = "require_special",
                message = "Password must contain at least one special character (!@#$%^&* etc.)"
            )
        )]
        password2: String,
    }

    #[tokio::test]
    async fn validation_error_password_messages_are_deduplicated() {
        let payload = DuplicatePasswordMessageValidation {
            password1: "password123".to_string(),
            password2: "password123".to_string(),
        };

        let response = AppError::ValidationError(payload.validate().unwrap_err()).into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let bytes = body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&bytes).unwrap();

        let password_errors = json["error"]["password"].as_array().unwrap();
        assert_eq!(password_errors.len(), 2);
        assert!(
            password_errors
                .iter()
                .any(|v| v == "Password must contain at least one uppercase letter (A-Z)")
        );
        assert!(
            password_errors
                .iter()
                .any(|v| v == "Password must contain at least one special character (!@#$%^&* etc.)")
        );
    }
}
