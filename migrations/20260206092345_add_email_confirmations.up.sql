-- Add up migration script here
ALTER TABLE users
    ADD COLUMN is_confirmed BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS email_confirmations
(
    id           UUID PRIMARY KEY             DEFAULT uuidv7(),
    user_id      UUID                NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token        VARCHAR(255) UNIQUE NOT NULL,
    expires_at   TIMESTAMPTZ         NOT NULL,
    confirmed_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ         NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_email_confirmations_token ON email_confirmations (token);
CREATE INDEX IF NOT EXISTS idx_email_confirmations_user_id ON email_confirmations (user_id);
