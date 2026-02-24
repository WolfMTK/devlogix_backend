use serde::Deserialize;
use utoipa::IntoParams;

#[derive(Debug, Deserialize, IntoParams)]
pub struct PaginationQuery {
    #[param(minimum = 1, default = 1)]
    pub page: Option<i64>,
    #[param(minimum = 1, maximum = 100, default = 20)]
    pub per_page: Option<i64>,
}
