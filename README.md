# DevLogix Backend Service

A simple and efficient task manager for organizing personal and team projects.

# Current Status

Under development

# Quick Start

1. Clone the repository: `git clone git@github.com:WolfMTK/devlogix_backend.git`.

2. Install SQLx CLI: `cargo install sqlx-cli --no-default-features --features native-tls,postgres`.

3. Configure environment variables:

    ```
    # Application
    BASE_CONFIG=<YOUR_PATH>
    
    # Postgres
    POSTGRES_USER=<YOUR_USER>
    POSTGRES_PASSWORD=<YOUR_PASSWORD>
    POSTGRES_DB=<YOUR_DB>
    ```

4. Run database migrations: `sqlx migrate run`.

5. Run the application: `cargo run --release`.
