use serde::Deserialize;
use utoipa::IntoParams;

#[derive(Debug, Deserialize, IntoParams)]
pub struct ConfirmEmailQuery {
    pub token: String,
}
