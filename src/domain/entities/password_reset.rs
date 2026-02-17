use chrono::{DateTime, Utc};

use crate::domain::entities::id::Id;
use crate::domain::entities::user::User;

#[derive(Debug, Clone)]
pub struct PasswordResetToken {
    pub id: Id<PasswordResetToken>,
    pub user_id: Id<User>,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl PasswordResetToken {
    pub fn new(user_id: Id<User>, token: String, ttl: i64) -> Self {
        let now = Utc::now();
        Self {
            id: Id::generate(),
            user_id,
            token,
            expires_at: now + chrono::Duration::seconds(ttl),
            used_at: None,
            created_at: now,
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn is_used(&self) -> bool {
        self.used_at.is_some()
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use rstest::rstest;

    use crate::domain::entities::id::Id;
    use crate::domain::entities::password_reset::PasswordResetToken;
    use crate::domain::entities::user::User;

    const TTL: i64 = 3600;

    #[rstest]
    fn test_new_password_reset_token() {
        let user_id: Id<User> = Id::generate();
        let token = "token".to_string();
        let reset_token = PasswordResetToken::new(user_id.clone(), token.clone(), TTL);

        assert_eq!(reset_token.token, token);
        assert_eq!(reset_token.user_id.value, user_id.value);
        assert!(reset_token.used_at.is_none());
        assert!(!reset_token.is_expired());
        assert!(!reset_token.is_used());
    }

    #[rstest]
    fn test_expired_token() {
        let user_id: Id<User> = Id::generate();
        let reset_token = PasswordResetToken::new(user_id, "token".to_string(), -1);

        assert!(reset_token.is_expired());
    }

    #[rstest]
    fn test_used_token() {
        let user_id: Id<User> = Id::generate();
        let mut reset_token = PasswordResetToken::new(user_id, "token".to_string(), TTL);
        reset_token.used_at = Some(Utc::now());

        assert!(reset_token.is_used());
    }

    #[rstest]
    fn test_unique_ids() {
        let user_id: Id<User> = Id::generate();
        let token1 = PasswordResetToken::new(user_id.clone(), "token1".to_string(), TTL);
        let token2 = PasswordResetToken::new(user_id, "token2".to_string(), TTL);

        assert_ne!(token1.id.value, token2.id.value);
    }

    #[rstest]
    fn test_clone() {
        let user_id: Id<User> = Id::generate();
        let reset_token = PasswordResetToken::new(user_id, "token".to_string(), TTL);
        let cloned = reset_token.clone();

        assert_eq!(reset_token.id.value, cloned.id.value);
        assert_eq!(reset_token.token, cloned.token);
        assert_eq!(reset_token.user_id.value, cloned.user_id.value);
    }
}
