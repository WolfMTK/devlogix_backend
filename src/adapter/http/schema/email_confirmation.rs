use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ConfirmEmailQuery {
    pub token: String,
}
