-- Add up migration script here
CREATE TABLE IF NOT EXISTS sessions
(
    id            UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_activity TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_rotation TIMESTAMPTZ NOT NULL DEFAULT now(),
    remember_me   BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
