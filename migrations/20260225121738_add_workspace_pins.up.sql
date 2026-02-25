-- Add up migration script here
CREATE TABLE IF NOT EXISTS workspace_pins (
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (workspace_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_workspace_pins_user_id ON workspace_pins(user_id);
