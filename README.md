# CSCE 3550 Project 3 — Encrypted SQLite JWKS Server

This Go HTTP server persists RSA signing keys in SQLite, publishes their public components as JWKS, and issues RS256 JWTs. Project 3 adds AES-GCM private-key encryption, user registration with Argon2id password hashing, authentication audit logs, and a thread-safe per-IP rate limit.

## Requirements

- Go 1.23 or newer
- A 16, 24, or 32-byte AES key in `NOT_MY_KEY` (raw or base64 encoded)
- Gradebot v1.1.2 for official grading

The main dependencies are `modernc.org/sqlite` and `golang.org/x/crypto/argon2`.

## Configure and run

Never commit the encryption key. In PowerShell, generate a key for the current terminal and start the server:

```powershell
$keyBytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Fill($keyBytes)
$env:NOT_MY_KEY = [Convert]::ToBase64String($keyBytes)
go mod tidy
go run .
```

The server listens on `http://localhost:8080` and creates `totally_not_my_privateKeys.db`. It fails safely at startup when `NOT_MY_KEY` is absent or invalid. A database must be reopened with the same key used to create it.

## Endpoints

- `GET /.well-known/jwks.json` returns valid public signing keys.
- `POST /auth` returns an RS256 JWT. Add `?expired=true` to select an expired signing key.
- `POST /register` accepts a username and email and returns a generated UUIDv4 password once.

Example registration:

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8080/register `
  -ContentType application/json `
  -Body '{"username":"MyCoolUsername","email":"user@example.com"}'
```

The password is stored only as a salted Argon2id hash. Successful `/auth` requests are recorded in `auth_logs`; if the supplied username is registered, the log links its user ID and updates `last_login`. Requests rejected by the limiter are not authentication-log successes. Client identity comes from the TCP peer address, not untrusted forwarding headers.

Each client IP may make 10 `/auth` requests per one-second fixed window. Further requests receive HTTP 429 with `Retry-After: 1`.

## Test and coverage

```powershell
go build ./...
go vet ./...
go test ./... -v
go test -race ./...
go test ./... -coverprofile=coverage.out
go tool cover -func=coverage.out
```

## Gradebot

With `NOT_MY_KEY` configured, build first so Gradebot's one-second startup delay is sufficient, then run the official Windows client from outside the repository:

```powershell
go build -o project3-server.exe .
& 'C:\Users\anash\Downloads\CSCE3550_Windows_x86_64\gradebot.exe' project-3 `
  --dir . --run '.\project3-server.exe' --port 8080 --code-dir . `
  --database totally_not_my_privateKeys.db -e "NOT_MY_KEY=$env:NOT_MY_KEY"
```

## Security design

Private keys remain PKCS#1 only in memory. The existing `keys.key` BLOB stores a version marker, a fresh random AES-GCM nonce, and authenticated ciphertext. Existing plaintext PEM rows are rejected with a migration error rather than silently rewritten. Database operations use bound parameters, JSON bodies are size limited, generated passwords are UUIDv4 values from `crypto/rand`, and plaintext passwords or encryption keys are never logged.
