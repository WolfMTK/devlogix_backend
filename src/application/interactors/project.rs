use std::sync::Arc;

use crate::application::app_error::{AppError, AppResult};
use crate::application::dto::project::{
    CreateProjectDTO, GetProjectDTO, GetProjectListDTO, ProjectDTO, ProjectListDTO,
};
use crate::application::interface::db::DBSession;
use crate::application::interface::gateway::project::{ProjectReader, ProjectWriter};
use crate::application::interface::gateway::workspace::WorkspaceReader;
use crate::domain::entities::id::Id;
use crate::domain::entities::project::{Project, ProjectType, ProjectVisibility};
use crate::domain::entities::user::User;
use crate::domain::entities::workspace::Workspace;
use crate::infra::constants::MAX_PER_PAGE;

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

#[derive(Clone)]
struct GetProjectListInteractor {
    workspace_reader: Arc<dyn WorkspaceReader>,
    project_reader: Arc<dyn ProjectReader>,
}

impl GetProjectListInteractor {
    pub fn new(workspace_reader: Arc<dyn WorkspaceReader>, project_reader: Arc<dyn ProjectReader>) -> Self {
        Self {
            workspace_reader,
            project_reader,
        }
    }

    pub async fn executor(&self, dto: GetProjectListDTO) -> AppResult<ProjectListDTO> {
        let user_id: Id<User> = dto.user_id.try_into()?;
        let workspace_id: Id<Workspace> = dto.workspace_id.try_into()?;

        let accessible = self
            .workspace_reader
            .is_accessible_by_user(&workspace_id, &user_id)
            .await?;

        if !accessible {
            return Err(AppError::AccessDenied);
        }

        let per_page = dto.per_page.clamp(1, MAX_PER_PAGE);
        let page = dto.page.max(1);
        let offset = (page - 1) * per_page;

        let total = self.project_reader.count_projects(&workspace_id).await?;
        let projects = self.project_reader.get_all(&workspace_id, per_page, offset).await?;

        let items = projects
            .into_iter()
            .map(|project| ProjectDTO {
                id: project.id.value.to_string(),
                workspace_id: project.workspace_id.value.to_string(),
                name: project.name,
                description: project.description,
                project_key: project.project_key,
                type_project: match project.type_project {
                    ProjectType::Kanban => "kanban".to_string(),
                    ProjectType::Scrum => "scrum".to_string(),
                },
                visibility: match project.visibility {
                    ProjectVisibility::Private => "private".to_string(),
                    ProjectVisibility::Public => "public".to_string(),
                },
                updated_at: project.updated_at,
                created_at: project.created_at,
            })
            .collect();

        Ok(ProjectListDTO {
            page,
            per_page,
            total,
            items,
        })
    }
}

#[derive(Clone)]
struct GetProjectInteractor {
    workspace_reader: Arc<dyn WorkspaceReader>,
    project_reader: Arc<dyn ProjectReader>,
}

impl GetProjectInteractor {
    pub fn new(workspace_reader: Arc<dyn WorkspaceReader>, project_reader: Arc<dyn ProjectReader>) -> Self {
        Self {
            workspace_reader,
            project_reader,
        }
    }

    pub async fn execute(&self, dto: GetProjectDTO) -> AppResult<ProjectDTO> {
        let user_id: Id<User> = dto.user_id.try_into()?;
        let workspace_id: Id<Workspace> = dto.workspace_id.try_into()?;
        let project_id: Id<Project> = dto.project_id.try_into()?;

        let project = self
            .project_reader
            .get(&workspace_id, &project_id)
            .await?
            .ok_or(AppError::ProjectNotFound)?;

        let accessible = self
            .workspace_reader
            .is_accessible_by_user(&workspace_id, &user_id)
            .await?;

        if !accessible {
            return Err(AppError::InvalidCredentials);
        }

        Ok(ProjectDTO {
            id: project.id.value.to_string(),
            workspace_id: project.workspace_id.value.to_string(),
            name: project.name,
            description: project.description,
            project_key: project.project_key,
            type_project: match project.type_project {
                ProjectType::Scrum => "scrum".to_string(),
                ProjectType::Kanban => "kanban".to_string(),
            },
            visibility: match project.visibility {
                ProjectVisibility::Public => "public".to_string(),
                ProjectVisibility::Private => "private".to_string(),
            },
            created_at: project.created_at,
            updated_at: project.updated_at,
        })
    }
}

#[derive(Clone)]
struct UpdateProjectInteractor {
    db_session: Arc<dyn DBSession>,
    workspace_reader: Arc<dyn WorkspaceReader>,
    project_reader: Arc<dyn ProjectReader>,
    project_writer: Arc<dyn ProjectWriter>,
}

impl UpdateProjectInteractor {
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
}
