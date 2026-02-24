use std::sync::Arc;

use crate::application::app_error::{AppError, AppResult};
use crate::application::dto::project::CreateProjectDTO;
use crate::application::interface::db::DBSession;
use crate::application::interface::gateway::project::{ProjectReader, ProjectWriter};
use crate::application::interface::gateway::workspace::WorkspaceReader;
use crate::domain::entities::id::Id;
use crate::domain::entities::project::{Project, ProjectType, ProjectVisibility};
use crate::domain::entities::user::User;
use crate::domain::entities::workspace::Workspace;

#[derive(Clone)]
pub struct CreateProjectInteractor {
    db_session: Arc<dyn DBSession>,
    workspace_reader: Arc<dyn WorkspaceReader>,
    project_reader: Arc<dyn ProjectReader>,
    project_writer: Arc<dyn ProjectWriter>,
}

impl CreateProjectInteractor {
    pub fn new(
        db_session: Arc<dyn DBSession>,
        workspace_reader: Arc<dyn WorkspaceReader>,
        project_reader: Arc<dyn ProjectReader>,
        project_writer: Arc<dyn ProjectWriter>,
    ) -> Self {
        Self {
            db_session,
            workspace_reader,
            project_reader,
            project_writer,
        }
    }

    pub async fn execute(&self, dto: CreateProjectDTO) -> AppResult<()> {
        let workspace_id: Id<Workspace> = dto.workspace_id.try_into()?;
        let user_id: Id<User> = dto.user_id.try_into()?;

        let accessible = self
            .workspace_reader
            .is_accessible_by_user(&workspace_id, &user_id)
            .await?;

        if !accessible {
            return Err(AppError::InvalidCredentials);
        }

        let is_key_project = self.project_reader.check_project_key(dto.project_key.as_str()).await?;

        if is_key_project {
            return Err(AppError::ProjectAlreadyExists);
        }

        let type_project: ProjectType = dto.type_project.parse()?;
        let visibility: ProjectVisibility = dto.visibility.parse()?;

        let project = Project::new(
            workspace_id,
            dto.name,
            dto.description,
            dto.project_key,
            type_project,
            visibility,
        );

        self.project_writer.insert(project).await?;
        self.db_session.commit().await?;

        Ok(())
    }
}
