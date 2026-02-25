-- Add up migration script here
CREATE TYPE projects_visibility AS ENUM('private', 'public');

CREATE TYPE projects_type_project AS ENUM('kanban', 'scrum');

CREATE TABLE IF NOT EXISTS projects (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
  name VARCHAR(120) NOT NULL,
  description TEXT,
  project_key VARCHAR(10) NOT NULL,
  type_project projects_type_project DEFAULT 'kanban',
  visibility projects_visibility NOT NULL DEFAULT 'private',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, project_key)
);

CREATE INDEX IF NOT EXISTS idx_projects_workspace_id ON projects (workspace_id);

CREATE INDEX IF NOT EXISTS idx_projects_project_key ON projects (project_key);
