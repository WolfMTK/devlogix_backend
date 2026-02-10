use crate::{
    application::{
        app_error::{AppError, AppResult},
        dto::{
            id::IdDTO,
            user::{CreateUserDTO, UpdateUserDTO, UserDTO},
        },
        interface::{
            crypto::CredentialsHasher,
            db::DBSession,
            gateway::user::{UserReader, UserWriter},
        },
    },
    domain::entities::{id::Id, user::User},
};
use std::sync::Arc;
use tracing::{error, info};

#[derive(Clone)]
pub struct CreateUserInteractor {
    db_session: Arc<dyn DBSession>,
    user_writer: Arc<dyn UserWriter>,
    user_reader: Arc<dyn UserReader>,
    hasher: Arc<dyn CredentialsHasher>,
}

impl CreateUserInteractor {
    pub fn new(
        db_session: Arc<dyn DBSession>,
        user_writer: Arc<dyn UserWriter>,
        user_reader: Arc<dyn UserReader>,
        hasher: Arc<dyn CredentialsHasher>,
    ) -> Self {
        Self {
            db_session,
            user_writer,
            user_reader,
            hasher,
        }
    }

    pub async fn execute(&self, dto: CreateUserDTO) -> AppResult<IdDTO> {
        Self::check_password(&dto.password1, &dto.password2)?;
        self.check_user_exists(&dto.username, &dto.email).await?;
        let hash = self.hasher.hash_password(dto.password1.as_str()).await?;
        let username = dto.username.clone();
        let user = User::new(dto.username, dto.email, hash);
        let user_id = match self.user_writer.insert(user).await {
            Ok(id) => id.value.to_string(),
            Err(err) => {
                error!(
                    "The {} has not been created created. Error: {}",
                    username, err
                );
                return Err(err);
            }
        };
        self.db_session.commit().await?;
        info!("The {} has been created", username);
        Ok(IdDTO { id: user_id })
    }

    fn check_password(password1: &str, password2: &str) -> AppResult<()> {
        if password1 != password2 {
            return Err(AppError::InvalidPassword);
        }
        Ok(())
    }

    async fn check_user_exists(&self, username: &str, email: &str) -> AppResult<()> {
        let is_user = self.user_reader.is_user(username, email).await?;
        if is_user {
            return Err(AppError::UserAlreadyExists);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct GetMeInteractor {
    user_reader: Arc<dyn UserReader>,
}

impl GetMeInteractor {
    pub fn new(user_reader: Arc<dyn UserReader>) -> Self {
        Self { user_reader }
    }

    pub async fn execute(&self, dto: IdDTO) -> AppResult<UserDTO> {
        let user_id: Id<User> = dto.id.try_into()?;
        let user = self
            .user_reader
            .find_by_id(&user_id)
            .await?
            .ok_or_else(|| {
                error!("User not found for authenticated session {:?}", user_id);
                AppError::InvalidCredentials
            })?;
        Ok(UserDTO {
            id: user.id.value.to_string(),
            username: user.username,
            email: user.email,
            created_at: user.created_at,
            updated_at: user.updated_at,
        })
    }
}

#[derive(Clone)]
pub struct UpdateUserInteractor {
    db_session: Arc<dyn DBSession>,
    user_writer: Arc<dyn UserWriter>,
    user_reader: Arc<dyn UserReader>,
    hasher: Arc<dyn CredentialsHasher>,
}

impl UpdateUserInteractor {
    pub fn new(
        db_session: Arc<dyn DBSession>,
        user_writer: Arc<dyn UserWriter>,
        user_reader: Arc<dyn UserReader>,
        hasher: Arc<dyn CredentialsHasher>,
    ) -> Self {
        Self {
            db_session,
            user_writer,
            user_reader,
            hasher,
        }
    }

    // TODO: Remove password validation
    pub async fn execute(&self, dto: UpdateUserDTO) -> AppResult<()> {
        Self::check_passwords(&dto)?;
        let user_id: Id<User> = dto.id.try_into()?;
        self.check_username_or_email(&user_id, dto.username.as_deref(), dto.email.as_deref())
            .await?;
        let user = self.user_reader.find_by_id(&user_id).await?;
        match user {
            Some(mut user) => {
                self.check_old_password(dto.old_password, &user.password)
                    .await?;
                if let Some(username) = dto.username {
                    user.username = username;
                }
                if let Some(email) = dto.email {
                    user.email = email;
                }
                if let Some(password) = dto.password1 {
                    let hash = self.hasher.hash_password(password.as_str()).await?;
                    user.password = hash;
                }
                self.user_writer.update(user).await?;
                self.db_session.commit().await?;
                Ok(())
            }
            None => Ok(()),
        }
    }

    async fn check_username_or_email(
        &self,
        user_id: &Id<User>,
        username: Option<&str>,
        email: Option<&str>,
    ) -> AppResult<()> {
        let is_username_or_email = self
            .user_reader
            .is_username_or_email_unique(&user_id, username, email)
            .await?;
        if is_username_or_email {
            return Err(AppError::UserAlreadyExists);
        }
        Ok(())
    }

    async fn check_old_password(
        &self,
        old_password: Option<String>,
        password: &str,
    ) -> AppResult<()> {
        if let Some(pwd) = old_password {
            if !self.hasher.verify_password(&pwd, password).await? {
                return Err(AppError::InvalidOldPassword);
            }
        }
        Ok(())
    }

    fn check_passwords(dto: &UpdateUserDTO) -> AppResult<()> {
        if !dto.password1.is_none() {
            if dto.old_password.is_none() {
                return Err(AppError::OldPasswordEmpty);
            }

            if dto.password1 != dto.password2 {
                return Err(AppError::InvalidPassword);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        application::{
            app_error::{AppError, AppResult},
            dto::id::IdDTO,
            dto::user::CreateUserDTO,
            interactors::users::{
                CreateUserInteractor,
                GetMeInteractor
            },
            interface::{
                crypto::CredentialsHasher,
                db::DBSession,
                gateway::user::{UserReader, UserWriter},
            }
        },
        domain::entities::{id::Id, user::User}
    };
    use async_trait::async_trait;
    use mockall::mock;
    use rstest::{fixture, rstest};
    use std::sync::Arc;
    use uuid::Uuid;

    // Mocks
    mock! {
        pub DBSessionMock {}

        #[async_trait]
        impl DBSession for DBSessionMock {
            async fn commit(&self) -> AppResult<()>;
        }
    }

    mock! {
        pub UserWriterMock {}

        #[async_trait]
        impl UserWriter for UserWriterMock {
            async fn insert(&self, user: User) -> AppResult<Id<User>>;
            async fn update(&self, user: User) -> AppResult<Id<User>>;
        }
    }

    mock! {
        pub HasherMock {}

        #[async_trait]
        impl CredentialsHasher for HasherMock {
            async fn hash_password(&self, password: &str) -> AppResult<String>;
            async fn verify_password(&self, password: &str, hashed: &str) -> AppResult<bool>;
        }
    }

    type BoxFn<A, R> = Box<dyn Fn(A) -> R + Send + Sync>;

    struct MockUserReader {
        is_user_fn: Option<BoxFn<(String, String), AppResult<bool>>>,
        find_by_id_fn: Option<BoxFn<uuid::Uuid, AppResult<Option<User>>>>,
        find_by_email_fn: Option<BoxFn<String, AppResult<Option<User>>>>,
        is_unique_fn: Option<BoxFn<(), AppResult<bool>>>,
    }

    impl MockUserReader {
        fn new() -> Self {
            Self {
                is_user_fn: None,
                find_by_id_fn: None,
                find_by_email_fn: None,
                is_unique_fn: None,
            }
        }

        fn expect_is_user(
            &mut self,
            f: impl Fn(&str, &str) -> AppResult<bool> + Send + Sync + 'static,
        ) {
            self.is_user_fn = Some(Box::new(move |(u, e)| f(&u, &e)));
        }

        #[allow(dead_code)]
        fn expect_find_by_id(
            &mut self,
            f: impl Fn(uuid::Uuid) -> AppResult<Option<User>> + Send + Sync + 'static,
        ) {
            self.find_by_id_fn = Some(Box::new(f));
        }

        #[allow(dead_code)]
        fn expect_find_by_email(
            &mut self,
            f: impl Fn(&str) -> AppResult<Option<User>> + Send + Sync + 'static,
        ) {
            self.find_by_email_fn = Some(Box::new(move |e| f(&e)));
        }

        #[allow(dead_code)]
        fn expect_is_unique(&mut self, f: impl Fn() -> AppResult<bool> + Send + Sync + 'static) {
            self.is_unique_fn = Some(Box::new(move |()| f()));
        }
    }

    #[async_trait]
    impl UserReader for MockUserReader {
        async fn find_by_email(&self, email: &str) -> AppResult<Option<User>> {
            (self
                .find_by_email_fn
                .as_ref()
                .expect("find_by_email not mocked"))(email.to_string())
        }

        async fn is_user(&self, username: &str, email: &str) -> AppResult<bool> {
            (self.is_user_fn.as_ref().expect("is_user not mocked"))((
                username.to_string(),
                email.to_string(),
            ))
        }

        async fn find_by_id(&self, user_id: &Id<User>) -> AppResult<Option<User>> {
            (self.find_by_id_fn.as_ref().expect("find_by_id not mocked"))(user_id.value)
        }

        async fn is_username_or_email_unique(
            &self,
            _user_id: &Id<User>,
            _username: Option<&str>,
            _email: Option<&str>,
        ) -> AppResult<bool> {
            match &self.is_unique_fn {
                Some(f) => f(()),
                None => Ok(false),
            }
        }
    }

    // Constants
    const USER_ID: &str = "019c47ec-183d-744e-b11d-cd409015bf13";
    const USERNAME: &str = "testuser";
    const EMAIL: &str = "test@example.com";
    const PASSWORD: &str = "Password123!";
    const HASHED_PASSWORD: &str = "$argon2id$v=19$m=16384,t=2,p=1$fakesalt$fakehash";

    // Fixtures
    #[fixture]
    fn valid_user() -> User {
        let mut user = User::new(
            USERNAME.to_owned(),
            EMAIL.to_owned(),
            HASHED_PASSWORD.to_owned(),
        );
        let user_id: Id<User> = USER_ID.to_string().try_into().unwrap();
        user.id = user_id;
        user
    }

    #[fixture]
    fn valid_user_id_dto(valid_user: User) -> IdDTO {
        IdDTO {
            id: valid_user.id.value.to_string(),
        }
    }

    #[fixture]
    fn valid_dto() -> CreateUserDTO {
        CreateUserDTO {
            username: USERNAME.to_string(),
            email: EMAIL.to_string(),
            password1: PASSWORD.to_string(),
            password2: PASSWORD.to_string(),
        }
    }

    #[fixture]
    fn mismatched_passwords_dto() -> CreateUserDTO {
        CreateUserDTO {
            username: USERNAME.to_string(),
            email: EMAIL.to_string(),
            password1: PASSWORD.to_string(),
            password2: "DifferentPass1!".to_string(),
        }
    }

    struct InteractorDeps {
        db_session: MockDBSessionMock,
        user_writer: MockUserWriterMock,
        user_reader: MockUserReader,
        hasher: MockHasherMock,
    }

    impl InteractorDeps {
        fn new() -> Self {
            Self {
                db_session: MockDBSessionMock::new(),
                user_writer: MockUserWriterMock::new(),
                user_reader: MockUserReader::new(),
                hasher: MockHasherMock::new(),
            }
        }

        fn create_user_interactor(self) -> CreateUserInteractor {
            CreateUserInteractor::new(
                Arc::new(self.db_session),
                Arc::new(self.user_writer),
                Arc::new(self.user_reader),
                Arc::new(self.hasher),
            )
        }

        fn get_me_interactor(self) -> GetMeInteractor {
            GetMeInteractor::new(Arc::new(self.user_reader))
        }
    }

    #[fixture]
    fn deps() -> InteractorDeps {
        InteractorDeps::new()
    }

    // Helpers
    fn setup_happy_path(deps: &mut InteractorDeps) {
        deps.user_reader.expect_is_user(|_, _| Ok(false));

        deps.hasher
            .expect_hash_password()
            .returning(|_| Ok(HASHED_PASSWORD.to_string()));

        deps.user_writer
            .expect_insert()
            .returning(|user| Ok(user.id.clone()));

        deps.db_session.expect_commit().returning(|| Ok(()));
    }

    // CreateUserInteractor tests
    #[rstest]
    #[tokio::test]
    async fn test_create_user_success(valid_dto: CreateUserDTO, mut deps: InteractorDeps) {
        setup_happy_path(&mut deps);
        let interactor = deps.create_user_interactor();
        let result = interactor.execute(valid_dto).await;
        assert!(result.is_ok());
        let id_dto = result.unwrap();
        assert!(!id_dto.id.is_empty());
        assert!(uuid::Uuid::parse_str(&id_dto.id).is_ok());
    }

    #[rstest]
    #[tokio::test]
    async fn test_create_user_password_mismatch(
        mismatched_passwords_dto: CreateUserDTO,
        deps: InteractorDeps,
    ) {
        let interactor = deps.create_user_interactor();
        let result = interactor.execute(mismatched_passwords_dto).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::InvalidPassword));
    }

    #[rstest]
    #[tokio::test]
    async fn test_create_user_already_exists(valid_dto: CreateUserDTO, mut deps: InteractorDeps) {
        deps.user_reader.expect_is_user(|_, _| Ok(true));
        let interactor = deps.create_user_interactor();
        let result = interactor.execute(valid_dto).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::UserAlreadyExists));
    }

    #[rstest]
    #[tokio::test]
    async fn test_create_user_hash_error(valid_dto: CreateUserDTO, mut deps: InteractorDeps) {
        deps.user_reader.expect_is_user(|_, _| Ok(false));
        deps.hasher
            .expect_hash_password()
            .returning(|_| Err(AppError::PasswordHashError));
        let interactor = deps.create_user_interactor();
        let result = interactor.execute(valid_dto).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::PasswordHashError));
    }

    #[rstest]
    #[tokio::test]
    async fn test_create_user_insert_db_error(valid_dto: CreateUserDTO, mut deps: InteractorDeps) {
        deps.user_reader.expect_is_user(|_, _| Ok(false));
        deps.hasher
            .expect_hash_password()
            .returning(|_| Ok(HASHED_PASSWORD.to_string()));
        deps.user_writer
            .expect_insert()
            .returning(|_| Err(AppError::DatabaseError(sqlx::Error::PoolClosed)));
        let interactor = deps.create_user_interactor();
        let result = interactor.execute(valid_dto).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::DatabaseError(_)));
    }

    #[rstest]
    #[tokio::test]
    async fn test_create_user_commit_error(valid_dto: CreateUserDTO, mut deps: InteractorDeps) {
        deps.user_reader.expect_is_user(|_, _| Ok(false));
        deps.hasher
            .expect_hash_password()
            .returning(|_| Ok(HASHED_PASSWORD.to_string()));
        deps.user_writer
            .expect_insert()
            .returning(|user| Ok(user.id.clone()));
        deps.db_session
            .expect_commit()
            .returning(|| Err(AppError::SessionAlreadyCommitted));
        let interactor = deps.create_user_interactor();
        let result = interactor.execute(valid_dto).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AppError::SessionAlreadyCommitted
        ));
    }

    #[rstest]
    #[tokio::test]
    async fn test_create_user_reader_db_error(valid_dto: CreateUserDTO, mut deps: InteractorDeps) {
        deps.user_reader
            .expect_is_user(|_, _| Err(AppError::DatabaseError(sqlx::Error::PoolClosed)));
        let interactor = deps.create_user_interactor();
        let result = interactor.execute(valid_dto).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::DatabaseError(_)));
    }

    #[rstest]
    #[case("", "test@example.com", "Password123!", "Password123!")]
    #[case("testuser", "", "Password123!", "Password123!")]
    #[tokio::test]
    async fn test_create_user_empty_fields_still_passes_interactor(
        #[case] username: &str,
        #[case] email: &str,
        #[case] password1: &str,
        #[case] password2: &str,
        mut deps: InteractorDeps,
    ) {
        setup_happy_path(&mut deps);
        let interactor = deps.create_user_interactor();
        let dto = CreateUserDTO {
            username: username.to_string(),
            email: email.to_string(),
            password1: password1.to_string(),
            password2: password2.to_string(),
        };
        let result = interactor.execute(dto).await;
        assert!(result.is_ok());
    }

    #[rstest]
    #[tokio::test]
    async fn test_create_user_identical_passwords_both_empty(mut deps: InteractorDeps) {
        setup_happy_path(&mut deps);
        let interactor = deps.create_user_interactor();
        let dto = CreateUserDTO {
            username: USERNAME.to_string(),
            email: EMAIL.to_string(),
            password1: "".to_string(),
            password2: "".to_string(),
        };
        let result = interactor.execute(dto).await;
        assert!(result.is_ok());
    }

    // GetMeInteractor tests
    #[rstest]
    #[tokio::test]
    async fn test_get_me_success(
        valid_user: User,
        valid_user_id_dto: IdDTO,
        mut deps: InteractorDeps,
    ) {
        deps.user_reader
            .expect_find_by_id(move |_| Ok(Some(valid_user.clone())));
        let interactor = deps.get_me_interactor();
        let result = interactor.execute(valid_user_id_dto).await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.username, USERNAME);
        assert_eq!(result.email, EMAIL);
        assert_eq!(result.id.as_str(), USER_ID);
        assert!(Uuid::parse_str(&result.id).is_ok());
    }

    #[rstest]
    #[tokio::test]
    async fn test_get_me_user_not_found(valid_user_id_dto: IdDTO, mut deps: InteractorDeps) {
        deps.user_reader.expect_find_by_id(|_| Ok(None));
        let interactor = deps.get_me_interactor();
        let result = interactor.execute(valid_user_id_dto).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::InvalidCredentials));
    }

    #[rstest]
    #[tokio::test]
    async fn test_get_me_invalid_id(deps: InteractorDeps) {
        let interactor = deps.get_me_interactor();
        let dto = IdDTO {
            id: "invalid".to_owned(),
        };
        let result = interactor.execute(dto).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::InvalidId(_)));
    }

    #[rstest]
    #[tokio::test]
    async fn test_get_me_reader_db_error(valid_user_id_dto: IdDTO, mut deps: InteractorDeps) {
        deps.user_reader
            .expect_find_by_id(|_| Err(AppError::DatabaseError(sqlx::Error::PoolClosed)));
        let interactor = deps.get_me_interactor();
        let result = interactor.execute(valid_user_id_dto).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::DatabaseError(_)));
    }
}
