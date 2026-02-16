use chrono::{DateTime, Duration, Utc};

use crate::domain::entities::id::Id;
use crate::domain::entities::user::User;

#[derive(Debug, Clone)]
pub struct EmailConfirmation {
    pub id: Id<EmailConfirmation>,
    pub user_id: Id<User>,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl EmailConfirmation {
    pub fn new(user_id: Id<User>, token: String, ttl_seconds: i64) -> Self {
        let now = Utc::now();
        Self {
            id: Id::generate(),
            user_id,
            token,
            expires_at: now + Duration::seconds(ttl_seconds),
            confirmed_at: None,
            created_at: now,
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn is_confirmed(&self) -> bool {
        self.confirmed_at.is_some()
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use crate::domain::entities::email_confirmation::EmailConfirmation;
    use crate::domain::entities::id::Id;
    use crate::domain::entities::user::User;

    const TTL_SECONDS: i64 = 3600;

    #[rstest]
    fn test_new_email_confirmation() {
        let user_id: Id<User> = Id::generate();
        let token = "test_token".to_string();
        let confirmation = EmailConfirmation::new(user_id.clone(), token.clone(), TTL_SECONDS);
        assert_eq!(confirmation.token, token);
        assert_eq!(confirmation.user_id.value, user_id.value);
        assert!(confirmation.confirmed_at.is_none());
        assert!(!confirmation.is_expired());
        assert!(!confirmation.is_confirmed());
    }

    #[rstest]
    fn test_expired_confirmation() {
        let user_id: Id<User> = Id::generate();
        let token = "test_token".to_string();
        let confirmation = EmailConfirmation::new(user_id.clone(), token.clone(), -1);
        assert!(confirmation.is_expired());
    }
}
