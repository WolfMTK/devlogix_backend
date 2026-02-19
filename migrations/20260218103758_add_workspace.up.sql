-- Add up migration script here
CREATE TYPE workspace_visibility AS ENUM ('private', 'public');

CREATE TABLE IF NOT EXISTS workspaces (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(80) NOT NULL,
    description TEXT,
    slug VARCHAR(40) NOT NULL,
    logo TEXT,
    primary_color VARCHAR(6) NOT NULL,
    visibility workspace_visibility NOT NULL DEFAULT 'private',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_workspaces_name ON workspaces(name);
CREATE INDEX IF NOT EXISTS idx_workspaces_owner_user_id ON workspaces(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_workspaces_slug ON workspaces(slug);

DROP TRIGGER IF EXISTS users_updated_at ON users;
DROP FUNCTION IF EXISTS update_column_updated_at();

CREATE TYPE workspace_members_role AS ENUM ('admin', 'member');
CREATE TYPE workspace_members_status AS ENUM ('awaiting', 'active', 'inactive');

CREATE TABLE IF NOT EXISTS workspace_members (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role workspace_members_role NOT NULL DEFAULT 'member',
    joined_at TIMESTAMPTZ,
    invited_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status workspace_members_status NOT NULL DEFAULT 'awaiting',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_workspace_members_workspace_user ON workspace_members(workspace_id, user_id);
CREATE INDEX IF NOT EXISTS idx_workspace_members_workspace_id ON workspace_members(workspace_id);
CREATE INDEX IF NOT EXISTS idx_workspace_members_user_id ON workspace_members(user_id);

CREATE TABLE IF NOT EXISTS workspace_invites (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    invite_token VARCHAR(255) UNIQUE NOT NULL,
    invited_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_workspace_invites_token ON workspace_invites(invite_token);
CREATE INDEX IF NOT EXISTS idx_workspace_invites_workspace_id ON workspace_invites(workspace_id);
CREATE INDEX IF NOT EXISTS idx_workspace_invites_email ON workspace_invites(email);
