#[derive(Debug)]
pub struct ConfirmEmailDTO {
    pub token: String,
}

#[derive(Debug)]
pub struct ResendConfirmationDTO {
    pub email: String,
    pub ttl: i64,
    pub confirmation_url: String,
}
