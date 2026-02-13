use crate::application::{
    app_error::{AppError, AppResult},
    interface::email::EmailSender
};
use async_trait::async_trait;
use chrono::Utc;
use std::{
    fs,
    path::PathBuf
};
use uuid::Uuid;

#[derive(Clone)]
pub struct LocalEmailSender {
    output_dir: PathBuf,
}

impl LocalEmailSender {
    pub fn new(output_dir: impl Into<PathBuf>) -> Self {
        Self {
            output_dir: output_dir.into(),
        }
    }
}

#[async_trait]
impl EmailSender for LocalEmailSender {
    async fn send(&self, to: &str, subject: &str, body: &str) -> AppResult<()> {
        fs::create_dir_all(&self.output_dir)
            .map_err(|err| AppError::EmailSendError(err.to_string()))?;
        let file_name = format!(
            "{}_{}.txt",
            Utc::now().format("%Y%m%d%H%M%S"),
            Uuid::now_v7()
        );
        let file_path = self.output_dir.join(file_name);
        let message = format!("To: {to}\nSubject: {subject}\n\n{body}\n");
        fs::write(file_path, message).map_err(|err| AppError::EmailSendError(err.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::adapter::email::local::LocalEmailSender;
    use crate::application::interface::email::EmailSender;
    use std::fs;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_local_email_sender_writes_file() {
        let dir = PathBuf::from("./tmp/test-local-email-sender");
        if dir.exists() {
            fs::remove_dir_all(&dir).expect("cleanup test directory");
        }
        let email = "ex@example.com";
        let sender = LocalEmailSender::new(&dir);
        sender
            .send(email, "subject", "body")
            .await
            .expect("send locally");

        let mut entries = fs::read_dir(&dir).expect("read output dir");
        let first = entries
            .next()
            .expect("one file expected")
            .expect("valid dir entry");
        let text = fs::read_to_string(first.path()).expect("read email file");

        assert!(text.contains(&format!("To: {}", email)));
        assert!(text.contains("Subject: subject"));
        assert!(text.contains("body"));

        fs::remove_dir_all(&dir).expect("cleanup test directory");
    }
}
