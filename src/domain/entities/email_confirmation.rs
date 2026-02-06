use crate::domain::entities::{id::Id, user::User};
use chrono::{DateTime, Duration, Utc};

#[derive(Debug, Clone)]
pub struct EmailConfirmation {
    id: Id<EmailConfirmation>,
    user_id: Id<User>,
    token: String,
    expires_at: DateTime<Utc>,
    confirmed_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
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
    use crate::domain::entities::{email_confirmation::EmailConfirmation, id::Id, user::User};
    use rstest::rstest;

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
        let confirmation = EmailConfirmation::new(user_id.clone(), token.clone(), TTL_SECONDS);
        assert!(confirmation.is_expired());
    }
}
