use crate::{
    application::{
        app_error::AppResult,
        dto::session::{GetSessionStatusDTO, SessionDTO, SessionValidationResult},
        interface::{
            db::DBSession,
            gateway::session::{SessionReader, SessionWriter}
        },
    },
    domain::entities::{
        id::Id,
        session::Session
    }
};
use chrono::{Duration, Utc};
use std::sync::Arc;

#[derive(Debug, Clone)]
struct SessionTimeouts {
    pub default_max_lifetime: i64,
    pub default_idle_timeout: i64,
    pub remembered_max_lifetime: i64,
    pub remembered_idle_timeout: i64,
}

#[derive(Clone)]
pub struct ValidateSessionInteractor {
    db_session: Arc<dyn DBSession>,
    session_reader: Arc<dyn SessionReader>,
    session_writer: Arc<dyn SessionWriter>,
}

impl ValidateSessionInteractor {
    pub fn new(
        db_session: Arc<dyn DBSession>,
        session_reader: Arc<dyn SessionReader>,
        session_writer: Arc<dyn SessionWriter>,
    ) -> Self {
        Self {
            db_session,
            session_reader,
            session_writer,
        }
    }

    fn get_timeouts(timeouts: SessionTimeouts, remember_me: bool) -> (Duration, Duration) {
        if remember_me {
            return (
                Duration::seconds(timeouts.remembered_max_lifetime),
                Duration::seconds(timeouts.remembered_idle_timeout),
            );
        }
        return (
            Duration::seconds(timeouts.default_max_lifetime),
            Duration::seconds(timeouts.default_idle_timeout),
        );
    }

    pub async fn execute(&self, dto: SessionDTO) -> AppResult<GetSessionStatusDTO> {
        let session_id: Id<Session> = dto.id.try_into()?;
        let session = match self.session_reader.find_by_id(&session_id).await? {
            Some(s) => s,
            None => {
                return Ok(GetSessionStatusDTO {
                    status: SessionValidationResult::Invalid,
                });
            }
        };
        let now = Utc::now();
        let timeouts = SessionTimeouts {
            default_max_lifetime: dto.default_max_lifetime,
            default_idle_timeout: dto.default_idle_timeout,
            remembered_max_lifetime: dto.remembered_max_lifetime,
            remembered_idle_timeout: dto.remembered_idle_timeout,
        };
        let (max_lifetime, idle_timeout) = Self::get_timeouts(timeouts, session.remember_me);

        if now - session.created_at > max_lifetime {
            self.session_writer.delete(&session_id).await?;
            self.db_session.commit().await?;
            return Ok(GetSessionStatusDTO {
                status: SessionValidationResult::Expired,
            });
        }

        if now - session.last_activity > idle_timeout {
            self.session_writer.delete(&session_id).await?;
            self.db_session.commit().await?;
            return Ok(GetSessionStatusDTO {
                status: SessionValidationResult::Expired,
            });
        }

        let rotation_interval = Duration::seconds(dto.rotation_interval);
        let needs_rotation = now - session.last_rotation > rotation_interval;
        if needs_rotation {
            let new_session = Session {
                id: Id::generate(),
                user_id: session.user_id.clone(),
                created_at: session.created_at,
                last_activity: now,
                last_rotation: now,
                remember_me: session.remember_me,
            };
            let new_session_id = self.session_writer.rotate(&session_id, new_session).await?;
            self.db_session.commit().await?;
            return Ok(GetSessionStatusDTO {
                status: SessionValidationResult::Rotated {
                    user_id: session.user_id,
                    new_session_id,
                },
            });
        }
        self.session_writer
            .update_activity(&session_id, now)
            .await?;
        self.db_session.commit().await?;
        Ok(GetSessionStatusDTO {
            status: SessionValidationResult::Valid(session.user_id),
        })
    }
}
