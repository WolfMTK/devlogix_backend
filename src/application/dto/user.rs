#[derive(Debug)]
pub struct CreateUserDTO {
    pub username: String,
    pub email: String,
    pub password: String,
}
