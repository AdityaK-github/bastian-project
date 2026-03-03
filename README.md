# Bastion Server

A self-hosted SSH bastion (jump server) with time-based access control, request/approval workflows, session recording, and dynamic SSH key management. Built with Rust and PostgreSQL, deployed via Docker Compose.

## Architecture

```
                          +------------------+
  SSH Client ----------> | Bastion Server   |------> Target Servers
  (port 2222)            | (sshd + CLI)     |        (prod-db, staging, etc.)
                          +--------+---------+
                                   |
                          +--------+---------+
                          |  Bastion API     |
                          |  (Axum, :8080)   |
                          +--------+---------+
                                   |
                          +--------+---------+
                          |  PostgreSQL      |
                          +------------------+
```

**bastion_cli** -- Rust CLI invoked via SSH `ForceCommand`. Handles user identification, permission checks, session recording, access requests, and admin operations. Connects directly to PostgreSQL.

**bastion_api** -- Rust HTTP service (Axum). Serves SSH public keys to `sshd` via `AuthorizedKeysCommand` for dynamic key-based authentication.

**sshd** -- OpenSSH server configured to fetch authorized keys from the API and force all sessions through the CLI wrapper.

## Features

- Time-based access control with automatic expiration
- Request/approval workflow for server access
- Admin and regular user roles
- SSH session recording via `script`
- Dynamic SSH key management with TTL support
- Key-based user identification (multiple users share a single OS account, distinguished by key fingerprint)
- Audit trail of all sessions and access requests

## Prerequisites

- Docker and Docker Compose
- Rust toolchain (for local development / cross-compilation)
- `cross` (for building the Linux musl binary on macOS): `cargo install cross`

## Quick Start

### 1. Build the CLI binary (Linux musl target)

```sh
cd bastion_cli
cross build --release --target x86_64-unknown-linux-musl
cd ..
```

### 2. Start the services

```sh
docker compose up --build -d
```

This starts three containers: PostgreSQL, the Bastion API, and the Bastion SSH server (port 2222).

### 3. Initialize the database

Run the schema scripts in order:

```sh
docker exec -i <db-container> psql -U postgres -d postgres < db_scripts/user_tracking_schema.sql
docker exec -i <db-container> psql -U postgres -d postgres < db_scripts/schema_updates.sql
docker exec -i <db-container> psql -U postgres -d postgres < db_scripts/migration_ssh_keys.sql
```

### 4. Set up users and keys

Use the `reset_demo_env.sh` script to create demo users with fresh SSH keys, or manually insert users and keys via SQL / the CLI.

### 5. Connect

```sh
ssh -i <private_key> -p 2222 dev@localhost <command>
```

## CLI Commands

All commands are issued over SSH. The bastion intercepts the SSH session and routes commands through the CLI.

```sh
# Usage pattern:
ssh -i <key> -p 2222 dev@localhost <command> [args]
```

### General

| Command | Description                |
| ------- | -------------------------- |
| `ping`  | Test database connectivity |
| `list`  | List available servers     |

### Access

| Command                                       | Description                                                    |
| --------------------------------------------- | -------------------------------------------------------------- |
| `connect <server>`                            | Connect to a server (requires active permission or admin role) |
| `request <server> [--hours N] [--note "..."]` | Request access to a server                                     |
| `my-requests`                                 | View your access requests and their statuses                   |
| `list-access`                                 | List all active permissions                                    |

### SSH Key Management

| Command                                                                      | Description                     |
| ---------------------------------------------------------------------------- | ------------------------------- |
| `add-key --file <path>` or `--key-data <key>` `[--ttl 2h] [--comment "..."]` | Register a new SSH public key   |
| `list-keys`                                                                  | List your SSH keys              |
| `key-info <id>`                                                              | Show details for a specific key |
| `revoke-key <id>`                                                            | Revoke an SSH key               |

### Admin

| Command                             | Description                                            |
| ----------------------------------- | ------------------------------------------------------ |
| `pending`                           | List pending access requests                           |
| `approve [request_id] [--hours N]`  | Approve an access request (interactive if no ID given) |
| `deny <request_id> --reason "..."`  | Deny an access request                                 |
| `grant <user> <server> [--hours N]` | Grant direct access, bypassing approval flow           |
| `make-admin <user>`                 | Promote a user to admin                                |
| `revoke-admin <user>`               | Demote a user from admin                               |
| `list-users`                        | List all users and roles                               |

## Project Structure

```
.
├── bastion_api/             # HTTP API for SSH key serving
│   ├── src/main.rs
│   ├── Cargo.toml
│   └── Dockerfile
├── bastion_cli/             # CLI tool (ForceCommand target)
│   ├── src/
│   │   ├── main.rs          # Entry point, argument parsing, command routing
│   │   ├── cli.rs           # Clap command definitions
│   │   ├── handlers.rs      # Business logic for each command
│   │   ├── permissions.rs   # Permission and RBAC queries
│   │   ├── requests.rs      # Access request workflow queries
│   │   ├── session.rs       # Session creation and SSH proxying
│   │   ├── identity.rs      # SSH key fingerprint-based user identification
│   │   └── keys.rs          # SSH key CRUD operations
│   └── Cargo.toml
├── db_scripts/              # SQL schema and migrations
│   ├── user_tracking_schema.sql
│   ├── schema_updates.sql
│   ├── migration_ssh_keys.sql
│   └── test_setup.sql
├── bastion_wrapper.sh       # ForceCommand wrapper, routes SSH commands to CLI
├── fetch-bastian-keys       # AuthorizedKeysCommand script, queries API for keys
├── sshd_config              # Bastion sshd configuration
├── Dockerfile               # Bastion SSH server image
├── docker-compose.yml       # Core services (bastion, API, database)
├── docker-compose-with-prod.yml  # Extended compose with test prod server and client
├── add_spare_key.sh         # Helper to register an additional SSH key
```

## Database Schema

Core tables:

- **users** -- username, admin flag, SSH key metadata, last login tracking
- **servers** -- server name and address
- **permissions** -- maps users to servers with an expiration timestamp
- **ssh_keys** -- multiple keys per user, with fingerprint, TTL, revocation, and audit fields
- **access_requests** -- request/approval/denial workflow with admin tracking
- **sessions** -- session log with client IP, key fingerprint, start/end time, and status

## How It Works

1. A user SSHs to the bastion on port 2222 as the `dev` OS user.
2. `sshd` calls `fetch-bastian-keys` (via `AuthorizedKeysCommand`), which queries the API for the user's active public keys and injects the key fingerprint as an environment variable.
3. After authentication, `sshd` invokes `bastion_wrapper.sh` (via `ForceCommand`), which passes the SSH command to `bastion_cli`.
4. The CLI identifies the actual user by matching the SSH key fingerprint against the database, checks permissions, and either proxies the connection (with session recording) or rejects it.

## Configuration

Key environment variables (set in `docker-compose.yml`):

| Variable          | Description                                   |
| ----------------- | --------------------------------------------- |
| `DATABASE_URL`    | PostgreSQL connection string                  |
| `BASTION_API_URL` | Internal URL of the key-serving API           |
| `RUST_LOG`        | Log level for the API (`info`, `debug`, etc.) |
| `PORT`            | API listen port (default `8080`)              |

## License

MIT
