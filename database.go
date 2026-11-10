package main

import (
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"time"

	_ "modernc.org/sqlite"
)

var errPlaintextPrivateKey = errors.New("unencrypted private key record found; migrate or remove the legacy database")

// keyStore owns all persistent state used by the server.
type keyStore struct {
	db            *sql.DB
	encryptionKey []byte
}

func openKeyStore(path string) (*keyStore, error) {
	encryptionKey, err := encryptionKeyFromEnvironment()
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	statements := []string{
		`PRAGMA foreign_keys = ON`,
		`CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )`,
		`CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )`,
		`CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )`,
	}
	for _, statement := range statements {
		if _, err = db.Exec(statement); err != nil {
			db.Close()
			return nil, fmt.Errorf("initialize database: %w", err)
		}
	}
	return &keyStore{db: db, encryptionKey: encryptionKey}, nil
}

func (s *keyStore) Close() error { return s.db.Close() }

func marshalPrivateKey(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func parsePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid private key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return key, nil
}

func (s *keyStore) saveKey(key signingKey) (string, error) {
	ciphertext, err := encryptPrivateKey(s.encryptionKey, marshalPrivateKey(key.PrivateKey))
	if err != nil {
		return "", err
	}
	result, err := s.db.Exec("INSERT INTO keys(key,exp) VALUES (?,?)", ciphertext, key.ExpiresAt.Unix())
	if err != nil {
		return "", err
	}
	id, err := result.LastInsertId()
	return strconv.FormatInt(id, 10), err
}

func (s *keyStore) decodeRow(kid int64, data []byte, exp int64) (signingKey, error) {
	if block, _ := pem.Decode(data); block != nil {
		return signingKey{}, errPlaintextPrivateKey
	}
	plaintext, err := decryptPrivateKey(s.encryptionKey, data)
	if err != nil {
		return signingKey{}, err
	}
	key, err := parsePrivateKey(plaintext)
	if err != nil {
		return signingKey{}, err
	}
	return signingKey{PrivateKey: key, Kid: strconv.FormatInt(kid, 10), ExpiresAt: time.Unix(exp, 0)}, nil
}

func (s *keyStore) ensureKeys(now time.Time) error {
	var validCount int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM keys WHERE exp > ?", now.Unix()).Scan(&validCount); err != nil {
		return err
	}
	if validCount == 0 {
		key, err := generateSigningKey(now.Add(2 * time.Hour))
		if err != nil {
			return err
		}
		if _, err = s.saveKey(key); err != nil {
			return err
		}
	}
	var expiredCount int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM keys WHERE exp <= ?", now.Unix()).Scan(&expiredCount); err != nil {
		return err
	}
	if expiredCount == 0 {
		key, err := generateSigningKey(now.Add(-time.Hour))
		if err != nil {
			return err
		}
		if _, err = s.saveKey(key); err != nil {
			return err
		}
	}
	return nil
}

func (s *keyStore) findKey(now int64, expired bool) (signingKey, error) {
	op := "exp > ?"
	if expired {
		op = "exp <= ?"
	}
	query := "SELECT kid,key,exp FROM keys WHERE " + op + " ORDER BY exp DESC LIMIT 1"
	var kid, exp int64
	var data []byte
	if err := s.db.QueryRow(query, now).Scan(&kid, &data, &exp); err != nil {
		return signingKey{}, err
	}
	return s.decodeRow(kid, data, exp)
}

func (s *keyStore) listValid(now int64) ([]signingKey, error) {
	rows, err := s.db.Query("SELECT kid,key,exp FROM keys WHERE exp > ? ORDER BY kid", now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := []signingKey{}
	for rows.Next() {
		var kid, exp int64
		var data []byte
		if err := rows.Scan(&kid, &data, &exp); err != nil {
			return nil, err
		}
		key, err := s.decodeRow(kid, data, exp)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (s *keyStore) registerUser(username, email, passwordHash string) error {
	_, err := s.db.Exec("INSERT INTO users(username,password_hash,email) VALUES (?,?,?)", username, passwordHash, email)
	return err
}

func (s *keyStore) userID(username string) (sql.NullInt64, error) {
	if username == "" {
		return sql.NullInt64{}, nil
	}
	var id int64
	err := s.db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return sql.NullInt64{}, nil
	}
	if err != nil {
		return sql.NullInt64{}, err
	}
	return sql.NullInt64{Int64: id, Valid: true}, nil
}

func (s *keyStore) logAuthentication(requestIP, username string, when time.Time) error {
	userID, err := s.userID(username)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(
		"INSERT INTO auth_logs(request_ip,request_timestamp,user_id) VALUES (?,?,?)",
		requestIP, when.UTC(), userID,
	); err != nil {
		return err
	}
	if userID.Valid {
		if _, err = tx.Exec("UPDATE users SET last_login = ? WHERE id = ?", when.UTC(), userID.Int64); err != nil {
			return err
		}
	}
	return tx.Commit()
}
