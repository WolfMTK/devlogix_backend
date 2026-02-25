-- Add up migration script here
CREATE TABLE IF NOT EXISTS workspace_pins
(
    user_id      UUID PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    workspace_id UUID NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_workspace_pins_user_id ON workspace_pins (user_id);
