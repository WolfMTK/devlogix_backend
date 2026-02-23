# DevLogix Backend Service

A simple and efficient task manager for organizing personal and team projects.

## Current Status

Under development

## Requirements

- Rust 1.92+ (edition 2024)
- PostgreSQL 18+
- SQLx CLI

## Installation

### 1. Clone the repository

```bash
git clone git@github.com:WolfMTK/devlogix_backend.git
cd devlogix_backend
```

### 2. Install SQLx CLI

```bash
cargo install sqlx-cli --no-default-features --features native-tls,postgres
```

### 3. Set up environment variables

```env
# Path to configuration file
BASE_CONFIG=YOUR_PATH/config/config.toml

# PostgreSQL
POSTGRES_USER=<YOUR_USER>
POSTGRES_PASSWORD=<YOUR_PASSWORD>
POSTGRES_DB=<YOUR_DB>

# Application
DATABASE_URL=<YOUR_DB_URL>
```

### 4. Configure the application

Edit [`config.toml`](./config/config.toml)

### 5. Start the database

```bash
docker run -d \
  --name devlogix-postgres \
  -e POSTGRES_USER=$POSTGRES_USER \
  -e POSTGRES_PASSWORD=$POSTGRES_PASSWORD \
  -e POSTGRES_DB=$POSTGRES_DB \
  -p 5432:5432 \
  postgres:18.1
```

### 6. Run migrations

```bash
sqlx migrate run
```

## Running

### Development mode

```bash
cargo run
```

### Production

```bash
cargo build --release
```

## Testing

###

Environment Variables for Testing

```
bash

# DATABASE
export TEST_DATABASE_URL="postgres://postgres:password@localhost:5432/test"

# S3-STORAGE
export TEST_S3_ENDPOINT="http://127.0.0.1:9000"
export TEST_S3_ACCESS_KEY="admin"
export TEST_S3_SECRET_KEY="password"
export TEST_S3_REGION="us-east-1"

# SMTP
export TEST_SMTP_HOST="smtp.example.com"
export TEST_SMTP_PORT="587"
export TEST_SMTP_USERNAME="user"
export TEST_SMTP_PASSWORD="pass"
export TEST_SMTP_FROM="example@example.com"
```

## Configuration

### Application parameters

| Parameter                   | Description                 | Example                             |
|-----------------------------|-----------------------------|-------------------------------------|
| `application.address`       | Server address and port     | `0.0.0.0:3001`                      |
| `application.allow_origins` | Allowed CORS origins        | `["http://localhost:3000"]`         |
| `db.url`                    | PostgreSQL connection URL   | `postgres://user:pass@host:5432/db` |
| `db.max_connections`        | Maximum connections in pool | `100`                               |
| `logger.log_path`           | Directory for log files     | `./logs`                            |

### Logging

Logs are written to two files:

- `app_logs.YYYY-MM-DD.jsonl` — INFO and WARN levels
- `err_logs.YYYY-MM-DD.jsonl` — ERROR level

Format: JSON Lines (NDJSON)

### Email delivery for confirmation links

For local development without SMTP, use:

```toml
[email]
provider = "local"
local_output_dir = "./tmp/emails"
```

In this mode, each outgoing email is saved as a text file into `local_output_dir`.
Use `provider = "smtp"` to send real emails via `[smtp]` settings.


## API

### Health Check
```bash
curl http://localhost:3001/
```

## License

BSD 3-Clause License. See [LICENSE](LICENSE).

