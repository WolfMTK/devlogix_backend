-- Add down migration script here
DROP TABLE IF EXISTS workspace_invites;
DROP TABLE IF EXISTS workspace_members;
DROP TABLE IF EXISTS workspaces;

DROP TYPE IF EXISTS workspace_invite_status;
DROP TYPE IF EXISTS workspace_members_status;
DROP TYPE IF EXISTS workspace_members_role;
DROP TYPE IF EXISTS workspace_visibility;

CREATE OR REPLACE FUNCTION update_column_updated_at()
    RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
EXECUTE FUNCTION update_column_updated_at();
