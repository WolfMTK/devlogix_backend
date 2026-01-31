use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct IdResponse {
    pub id: String,
}
