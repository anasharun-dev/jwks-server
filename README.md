# JWKS Server

A Go HTTP server that manages RSA signing keys in SQLite, publishes public keys as JWKS, and issues RS256 JSON Web Tokens.

## Features

- AES-GCM encryption for persisted RSA private keys
- SQLite-backed key, user, and authentication-log storage
- UUIDv4 password generation with salted Argon2id hashing
- Valid and expired JWT generation
- Thread-safe per-IP rate limiting for authentication requests

## Setup

Requires Go 1.23 or newer. Set `NOT_MY_KEY` to a raw or base64-encoded 16, 24, or 32-byte AES key. The same key is required whenever an existing database is reopened.

```powershell
$keyBytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Fill($keyBytes)
$env:NOT_MY_KEY = [Convert]::ToBase64String($keyBytes)

go mod tidy
go run .
```

The server listens on `http://localhost:8080`.

## API

- `GET /.well-known/jwks.json` returns valid public signing keys.
- `POST /auth` returns a signed JWT. Use `?expired=true` for an expired token.
- `POST /register` accepts `username` and `email` as JSON and returns a generated password.

## Tests

```powershell
go build ./...
go vet ./...
go test ./... -v
go test ./... -coverprofile=coverage.out
go tool cover -func=coverage.out
```

Private keys, plaintext passwords, and encryption keys are never logged. Local databases, environment files, build output, and coverage artifacts are excluded from version control.
