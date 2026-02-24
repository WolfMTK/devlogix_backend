use std::str::FromStr;

use chrono::{DateTime, Duration, Utc};
use slug::slugify;
use uuid::Uuid;

use crate::application::app_error::AppError;
use crate::domain::entities::id::Id;
use crate::domain::entities::user::User;

#[derive(Debug, Clone)]
pub enum WorkspaceVisibility {
    Private,
    Public,
}

impl FromStr for WorkspaceVisibility {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "public" => Ok(WorkspaceVisibility::Public),
            "private" => Ok(WorkspaceVisibility::Private),
            other => Err(AppError::InvalidVisibility(other.to_string())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Workspace {
    pub id: Id<Workspace>,
    pub owner_user_id: Id<User>,
    pub name: String,
    pub description: Option<String>,
    pub slug: String,
    pub logo: Option<String>,
    pub primary_color: String,
    pub visibility: WorkspaceVisibility,
    pub updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl Workspace {
    pub fn new(
        owner_user_id: Id<User>,
        name: String,
        description: Option<String>,
        primary_color: String,
        visibility: WorkspaceVisibility,
    ) -> Self {
        let now = Utc::now();
        let slug = slugify(name.as_str());

        Self {
            id: Id::generate(),
            owner_user_id,
            name,
            description,
            slug,
            logo: None,
            primary_color,
            visibility,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn set_slug(&mut self, name: &str) {
        self.slug = slugify(name)
    }
}

#[derive(Debug, Clone)]
pub enum WorkspaceMemberRole {
    Admin,
    Member,
}

#[derive(Debug, Clone)]
pub enum WorkspaceMemberStatus {
    Awaiting,
    Active,
    Inactive,
}

#[derive(Debug, Clone)]
pub struct WorkspaceMember {
    pub id: Id<WorkspaceMember>,
    pub workspace_id: Id<Workspace>,
    pub user_id: Id<User>,
    pub role: WorkspaceMemberRole,
    #[allow(dead_code)]
    pub joined_at: Option<DateTime<Utc>>,
    pub invited_by: Id<User>,
    pub status: WorkspaceMemberStatus,
    #[allow(dead_code)]
    pub created_at: DateTime<Utc>,
}

impl WorkspaceMember {
    pub fn new(
        workspace_id: Id<Workspace>,
        user_id: Id<User>,
        invited_by: Id<User>,
        role: WorkspaceMemberRole,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Id::generate(),
            workspace_id,
            user_id,
            role,
            joined_at: None,
            invited_by,
            status: WorkspaceMemberStatus::Awaiting,
            created_at: now,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WorkspaceInvite {
    pub id: Id<WorkspaceInvite>,
    pub workspace_id: Id<Workspace>,
    pub email: String,
    pub invite_token: String,
    pub invited_by: Id<User>,
    pub expires_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl WorkspaceInvite {
    pub fn new(workspace_id: Id<Workspace>, email: String, invited_by: Id<User>, ttl: i64) -> Self {
        let now = Utc::now();
        let invite_token = Uuid::now_v7();
        Self {
            id: Id::generate(),
            workspace_id,
            email,
            invite_token: invite_token.to_string(),
            invited_by,
            expires_at: now + Duration::seconds(ttl),
            accepted_at: None,
            revoked_at: None,
            created_at: now,
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn is_accepted(&self) -> bool {
        self.accepted_at.is_some()
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    pub fn is_pending(&self) -> bool {
        !self.is_accepted() && !self.is_revoked() && !self.is_expired()
    }
}

#[derive(Debug, Clone)]
pub enum WorkspaceUserRole {
    Owner,
    Admin,
    Member,
}

impl FromStr for WorkspaceUserRole {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "owner" => Ok(WorkspaceUserRole::Owner),
            "admin" => Ok(WorkspaceUserRole::Admin),
            "member" => Ok(WorkspaceUserRole::Member),
            other => Err(AppError::InvalidVisibility(other.to_string())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct WorkspaceView {
    pub workspace: Workspace,
    pub total_members: i64,
    pub total_projects: i64,
    pub user_role: WorkspaceUserRole,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::application::app_error::AppError;
    use crate::domain::entities::id::Id;
    use crate::domain::entities::user::User;
    use crate::domain::entities::workspace::{Workspace, WorkspaceVisibility};

    fn owner_id() -> Id<User> {
        Id::generate()
    }

    fn make_workspace(name: &str) -> Workspace {
        Workspace::new(
            owner_id(),
            name.to_string(),
            None,
            "#ffffff".to_string(),
            WorkspaceVisibility::Private,
        )
    }

    #[test]
    fn test_visibility_private() {
        assert!(matches!(
            WorkspaceVisibility::from_str("private").unwrap(),
            WorkspaceVisibility::Private
        ));
    }

    #[test]
    fn test_visibility_public() {
        assert!(matches!(
            WorkspaceVisibility::from_str("public").unwrap(),
            WorkspaceVisibility::Public
        ));
    }

    #[test]
    fn test_visibility_case_insensitive() {
        assert!(matches!(
            WorkspaceVisibility::from_str("PRIVATE").unwrap(),
            WorkspaceVisibility::Private
        ));
        assert!(matches!(
            WorkspaceVisibility::from_str("PUBLIC").unwrap(),
            WorkspaceVisibility::Public
        ));
        assert!(matches!(
            WorkspaceVisibility::from_str("Private").unwrap(),
            WorkspaceVisibility::Private
        ));
    }

    #[test]
    fn test_visibility_invalid_returns_error() {
        let err = WorkspaceVisibility::from_str("unknown").unwrap_err();
        assert!(matches!(err, AppError::InvalidVisibility(v) if v == "unknown"));
    }

    #[test]
    fn test_visibility_empty_string_returns_error() {
        let err = WorkspaceVisibility::from_str("").unwrap_err();
        assert!(matches!(err, AppError::InvalidVisibility(v) if v.is_empty()));
    }

    #[test]
    fn test_workspace_new_sets_fields() {
        let owner = owner_id();
        let workspace = Workspace::new(
            owner.clone(),
            "My Workspace".to_string(),
            Some("A description".to_string()),
            "#ff0000".to_string(),
            WorkspaceVisibility::Public,
        );

        assert_eq!(workspace.name, "My Workspace");
        assert_eq!(workspace.description, Some("A description".to_string()));
        assert_eq!(workspace.primary_color, "#ff0000");
        assert_eq!(workspace.owner_user_id.value, owner.value);
        assert!(workspace.logo.is_none());
    }

    #[test]
    fn test_workspace_new_generates_unique_ids() {
        let w1 = make_workspace("Workspace 1");
        let w2 = make_workspace("Workspace 2");
        assert_ne!(w1.id.value, w2.id.value);
    }

    #[test]
    fn test_workspace_new_logo_is_none() {
        let workspace = make_workspace("Test");
        assert!(workspace.logo.is_none());
    }

    #[test]
    fn test_workspace_new_description_none() {
        let workspace = Workspace::new(
            owner_id(),
            "Test".to_string(),
            None,
            "#000000".to_string(),
            WorkspaceVisibility::Private,
        );
        assert!(workspace.description.is_none());
    }

    #[test]
    fn test_workspace_new_created_at_equals_updated_at() {
        let workspace = make_workspace("Test");
        assert_eq!(workspace.created_at, workspace.updated_at);
    }

    #[test]
    fn test_slug_basic() {
        let workspace = make_workspace("My Workspace");
        assert_eq!(workspace.slug, "my-workspace");
    }

    #[test]
    fn test_slug_special_characters() {
        let workspace = make_workspace("Hello, World!");
        assert_eq!(workspace.slug, "hello-world");
    }

    #[test]
    fn test_slug_multiple_spaces() {
        let workspace = make_workspace("My   Cool   Workspace");
        assert_eq!(workspace.slug, "my-cool-workspace");
    }

    #[test]
    fn test_slug_already_lowercase() {
        let workspace = make_workspace("simple");
        assert_eq!(workspace.slug, "simple");
    }

    #[test]
    fn test_slug_numbers() {
        let workspace = make_workspace("Team 42");
        assert_eq!(workspace.slug, "team-42");
    }
}
