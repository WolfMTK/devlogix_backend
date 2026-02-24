use std::str::FromStr;

use chrono::{DateTime, Utc};

use crate::application::app_error::AppError;
use crate::domain::entities::id::Id;
use crate::domain::entities::workspace::Workspace;

#[derive(Debug, Clone)]
pub enum ProjectType {
    Kanban,
    Scrum,
}

impl FromStr for ProjectType {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "kanban" => Ok(ProjectType::Kanban),
            "scrum" => Ok(ProjectType::Scrum),
            other => Err(AppError::InvalidProjectType(other.to_string())),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ProjectVisibility {
    Private,
    Public,
}

impl FromStr for ProjectVisibility {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "private" => Ok(ProjectVisibility::Private),
            "public" => Ok(ProjectVisibility::Public),
            other => Err(AppError::InvalidVisibility(other.to_string())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Project {
    pub id: Id<Project>,
    pub workspace_id: Id<Workspace>,
    pub name: String,
    pub description: Option<String>,
    pub project_key: String,
    pub type_project: ProjectType,
    pub visibility: ProjectVisibility,
    pub updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl Project {
    pub fn new(
        workspace_id: Id<Workspace>,
        name: String,
        description: Option<String>,
        project_key: String,
        type_project: ProjectType,
        visibility: ProjectVisibility,
    ) -> Self {
        let now = Utc::now();

        Self {
            id: Id::generate(),
            workspace_id,
            name,
            description,
            project_key,
            type_project,
            visibility,
            created_at: now,
            updated_at: now,
        }
    }
}
