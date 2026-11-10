# Project 3 Results

Student: Anas Harun
Course: CSCE 3550
Project: Project 3 — Bulking Up Our JWKS Server
Verified: November 10, 2026

## Completed requirements

- SQLite `users` and `auth_logs` tables use the required schemas.
- `POST /register` returns a cryptographically generated UUIDv4 password and stores only its salted Argon2id hash.
- RSA private keys are stored as AES-GCM ciphertext using `NOT_MY_KEY`, with a fresh random nonce for every encryption.
- Project 2 JWKS, valid JWT, and expired-JWT behavior is preserved.
- Successful authentication requests record peer IP, timestamp, and the matching registered user ID when present.
- A thread-safe per-IP fixed-window limiter permits 10 `/auth` requests per second and returns HTTP 429 afterward; rejected requests are not logged as successful authentications.
- Tests cover encryption, tampering, invalid configuration, persistence, registration, hashes, duplicates, logging, JWT/JWKS behavior, rate-limit boundaries, and concurrency.

## Verification results

- `go mod tidy`: passed
- `go fmt ./...`: passed
- `go build ./...`: passed
- `go vet ./...`: passed
- `go test ./... -v`: passed, 15 test groups
- `go test ./... -coverprofile=coverage.out`: passed
- Statement coverage: **86.1%**
- Live integration: server startup passed; JWKS returned 200; registration returned 201; authentication returned 200; requests 1–10 returned 200 and request 11 returned 429.
- `go test -race ./...`: not available on this Windows installation. Go requires CGO for the race detector, and the machine has no C compiler (`gcc` was not found). Normal concurrency tests pass and the limiter is mutex-protected.

## Official Gradebot v1.1.2

The final clean run used an isolated production-source copy, an ephemeral database, and a one-use encryption key. No Project 2 files, unrelated projects, existing databases, `.env` files, credentials, or private-key material were included.

| Rubric item | Awarded |
|---|---:|
| Create users table | 5/5 |
| `/register` endpoint | 20/20 |
| Private keys encrypted in database | 25/25 |
| Create auth_logs table | 5/5 |
| `/auth` requests logged | 10/10 |
| Optional rate limiter | 25/25 |
| Automated quality review | 4.25/5 |

Actual Gradebot result: **99.21%**. All functional and security checks received full credit; the only deduction was 0.75 points in the subjective automated quality review.

## Screenshots

- `Screenshots/Project3_Gradebot.png` — captured and verified; shows Anas Harun, CSCE 3550, Project 3, and the official 99.21% Gradebot result.
- `Screenshots/Project3_Coverage.png` — captured and verified; shows Anas Harun, CSCE 3550, Project 3, and 86.1% statement coverage.

## Repository status

- Local repository: initialized on `main` at `C:\Users\anash\Documents\CSCE3550\Project3\CSCE3550-Project3`.
- Remote: `https://github.com/anasharun-dev/CSCE3550-Project3.git` (verified to exist and currently empty before submission).
- Commit and push: screenshots are present; final repository audit is in progress.
- Original Project 2 ZIP remains unchanged.

## Remaining issues

- Run the final secret/tracked-file check, commit, push, and verify the remote.
