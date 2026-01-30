use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {}

pub type AppResult<T> = Result<T, AppError>;
