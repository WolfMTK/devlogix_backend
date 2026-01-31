use crate::application::app_error::AppError;
use std::marker::PhantomData;
use std::str::FromStr;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Id<T> {
    pub value: Uuid,
    _marker: PhantomData<T>
}

impl<T> Id<T> {
    pub fn new(value: Uuid) -> Self {
        Self {
            value,
            _marker: PhantomData
        }
    }

    pub fn generate() -> Id<T> {
        Id::new(Uuid::now_v7())
    }
}

impl <T> TryFrom<String> for Id<T> {
    type Error = AppError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let uuid = Uuid::from_str(&value)
            .map_err(|e| AppError::InvalidId(format!("Invalid UUID: {}", e)))?;
        Ok(Id::new(uuid))
    }
}
