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

#[cfg(test)]
mod tests {
    use crate::domain::entities::id::Id;
    use uuid::Uuid;

    #[derive(Clone)]
struct TestEntity;

    #[test]
    fn test_id_new() {
        let uuid = Uuid::now_v7();
        let id: Id<TestEntity> = Id::new(uuid);
        assert_eq!(id.value, uuid)
    }

    #[test]
    fn test_id_generate() {
        let id1: Id<TestEntity> = Id::generate();
        let id2: Id<TestEntity> = Id::generate();
        assert_ne!(id1.value, id2.value);
    }

    #[test]
    fn test_id_try_from_valid_uuid() {
        let uuid = Uuid::now_v7();
        let uuid_str = uuid.to_string();
        let id: Id<TestEntity> = uuid_str.try_into().unwrap();
        assert_eq!(id.value, uuid);
    }

    #[test]
    fn test_id_try_from_invalid_uuid() {
        let invalid_uuid = "invalid".to_owned();
        let result: Result<Id<TestEntity>, _> = invalid_uuid.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_id_clone() {
        let id: Id<TestEntity> = Id::generate();
        let cloned_id = id.clone();
        assert_eq!(id.value, cloned_id.value);
    }
}
