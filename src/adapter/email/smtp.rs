use crate::{
    application::{
        app_error::{AppError, AppResult},
        interface::email::EmailSender,
    },
    infra::config::SMTPConfig,
};
use async_trait::async_trait;
use lettre::{
    message::Mailbox, transport::smtp::{authentication::Credentials, AsyncSmtpTransport}, AsyncTransport,
    Message,
    Tokio1Executor,
};

#[derive(Clone)]
pub struct SMTPEmailSender {
    from: String,
    mailer: AsyncSmtpTransport<Tokio1Executor>,
}

impl SMTPEmailSender {
    pub fn new(config: &SMTPConfig) -> Self {
        let mut transport =
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host).port(config.port);
        if !config.username.is_empty() {
            transport = transport.credentials(Credentials::new(
                config.username.clone(),
                config.password.clone(),
            ));
        }
        Self {
            from: config.from.clone(),
            mailer: transport.build(),
        }
    }
}

#[async_trait]
impl EmailSender for SMTPEmailSender {
    async fn send(&self, to: &str, subject: &str, body: &str) -> AppResult<()> {
        let from: Mailbox = self
            .from
            .parse()
            .map_err(|_| AppError::EmailSendError("Invalid FROM email address".to_string()))?;
        let to: Mailbox = to
            .parse()
            .map_err(|_| AppError::EmailSendError("Invalid TO email address".to_string()))?;
        let message = Message::builder()
            .to(to)
            .subject(subject)
            .from(from)
            .body(body.to_string())
            .map_err(|err| AppError::EmailSendError(err.to_string()))?;
        self.mailer
            .send(message)
            .await
            .map_err(|err| AppError::EmailSendError(err.to_string()))?;
        Ok(())
    }
}
