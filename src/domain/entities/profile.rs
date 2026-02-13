use crate::domain::entities::{
    id::Id,
    user::User
};

#[derive(Debug, Clone)]
struct Profile {
    id: Id<Profile>,
    user_id: Id<User>,
    first_name: String,
    last_name: String,
    avatar: String,
    bio: String,
}
