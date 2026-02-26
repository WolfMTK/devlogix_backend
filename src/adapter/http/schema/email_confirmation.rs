use serde::Deserialize;
use utoipa::IntoParams;

#[derive(Debug, Deserialize, IntoParams)]
pub struct ConfirmEmailQuery {
    #[param(example = "a1b2c3d4e5f6")]
    pub token: String,
}
