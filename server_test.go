package main

import (
	"bytes"
	"crypto/rsa"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testEncryptionKey = "0123456789abcdef0123456789abcdef"

func testServer(t *testing.T) *server {
	t.Helper()
	t.Setenv(encryptionKeyVariable, testEncryptionKey)
	s, err := newServerAt(filepath.Join(t.TempDir(), "totally_not_my_privateKeys.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.store.Close() })
	return s
}

func request(t *testing.T, s *server, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.routes().ServeHTTP(recorder, req)
	return recorder
}

func TestJWKSAndValidJWT(t *testing.T) {
	s := testServer(t)
	recorder := request(t, s, http.MethodGet, "/.well-known/jwks.json", "")
	if recorder.Code != http.StatusOK {
		t.Fatal(recorder.Code, recorder.Body.String())
	}
	var body jwksResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Keys) == 0 {
		t.Fatal("missing public keys")
	}
	for _, key := range body.Keys {
		if key.Kty != "RSA" || key.Alg != "RS256" || key.Use != "sig" {
			t.Fatalf("bad JWK: %+v", key)
		}
	}

	auth := request(t, s, http.MethodPost, "/auth", `{"username":"userABC","password":"ignored"}`)
	if auth.Code != http.StatusOK {
		t.Fatal(auth.Code, auth.Body.String())
	}
	parts := splitJWT(auth.Body.String())
	if len(parts) != 3 {
		t.Fatal("bad JWT parts")
	}
	var header map[string]string
	var claims jwtClaims
	if err := decodeSegment(parts[0], &header); err != nil {
		t.Fatal(err)
	}
	if err := decodeSegment(parts[1], &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Sub != "userABC" || claims.Exp <= time.Now().Unix() {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	for _, key := range body.Keys {
		if key.Kid != header["kid"] {
			continue
		}
		publicKey, err := rsaPublicKeyFromJWK(key)
		if err != nil {
			t.Fatal(err)
		}
		if err = verifyJWT(auth.Body.String(), publicKey); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatal("token kid missing from JWKS")
}

func TestExpiredAuth(t *testing.T) {
	s := testServer(t)
	for _, target := range []string{"/auth?expired", "/auth?expired=true"} {
		recorder := request(t, s, http.MethodPost, target, "")
		if recorder.Code != http.StatusOK {
			t.Fatal(recorder.Code, recorder.Body.String())
		}
		var claims jwtClaims
		if err := decodeSegment(splitJWT(recorder.Body.String())[1], &claims); err != nil {
			t.Fatal(err)
		}
		if claims.Exp > time.Now().Unix() {
			t.Fatal("expected expired token")
		}
	}
}

func TestAESGCMEncryption(t *testing.T) {
	plaintext := []byte("private material")
	first, err := encryptPrivateKey([]byte(testEncryptionKey), plaintext)
	if err != nil {
		t.Fatal(err)
	}
	second, err := encryptPrivateKey([]byte(testEncryptionKey), plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("unique nonces should produce distinct ciphertext")
	}
	if bytes.Contains(first, plaintext) {
		t.Fatal("ciphertext contains plaintext")
	}
	decrypted, err := decryptPrivateKey([]byte(testEncryptionKey), first)
	if err != nil || !bytes.Equal(decrypted, plaintext) {
		t.Fatal(err, string(decrypted))
	}
	first[len(first)-1] ^= 1
	if _, err = decryptPrivateKey([]byte(testEncryptionKey), first); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	if _, err = decryptPrivateKey([]byte("short"), second); err == nil {
		t.Fatal("invalid AES key accepted")
	}
	if _, err = decryptPrivateKey([]byte(testEncryptionKey), []byte("bad")); err == nil {
		t.Fatal("unrecognized ciphertext accepted")
	}
	truncated := append(append([]byte{}, encryptedKeyPrefix...), make([]byte, 4)...)
	if _, err = decryptPrivateKey([]byte(testEncryptionKey), truncated); err == nil {
		t.Fatal("truncated ciphertext accepted")
	}
}

func TestEncryptionEnvironmentValidation(t *testing.T) {
	t.Setenv(encryptionKeyVariable, "")
	if _, err := encryptionKeyFromEnvironment(); err == nil {
		t.Fatal("missing key accepted")
	}
	t.Setenv(encryptionKeyVariable, "invalid")
	if _, err := encryptionKeyFromEnvironment(); err == nil {
		t.Fatal("invalid key accepted")
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(testEncryptionKey))
	t.Setenv(encryptionKeyVariable, encoded)
	key, err := encryptionKeyFromEnvironment()
	if err != nil || string(key) != testEncryptionKey {
		t.Fatal(err)
	}
}

func TestEncryptedDatabasePersistence(t *testing.T) {
	t.Setenv(encryptionKeyVariable, testEncryptionKey)
	path := filepath.Join(t.TempDir(), "totally_not_my_privateKeys.db")
	s1, err := newServerAt(path)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := s1.store.listValid(time.Now().Unix())
	if err != nil || len(keys) == 0 {
		t.Fatal(err)
	}
	originalKid := keys[0].Kid
	var stored []byte
	if err = s1.store.db.QueryRow("SELECT key FROM keys WHERE kid = ?", originalKid).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte("PRIVATE KEY")) || !bytes.HasPrefix(stored, encryptedKeyPrefix) {
		t.Fatal("private key was not stored as ciphertext")
	}
	if err = s1.store.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := newServerAt(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.store.Close()
	keys, err = s2.store.listValid(time.Now().Unix())
	if err != nil || len(keys) == 0 || keys[0].Kid != originalKid {
		t.Fatal("key did not persist", err)
	}
}

func TestLegacyPlaintextRecordRejected(t *testing.T) {
	s := testServer(t)
	key, err := generateSigningKey(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.store.db.Exec("INSERT INTO keys(key,exp) VALUES (?,?)", marshalPrivateKey(key.PrivateKey), key.ExpiresAt.Unix()); err != nil {
		t.Fatal(err)
	}
	var kid int64
	if err = s.store.db.QueryRow("SELECT MAX(kid) FROM keys").Scan(&kid); err != nil {
		t.Fatal(err)
	}
	if _, err = s.store.decodeRow(kid, marshalPrivateKey(key.PrivateKey), key.ExpiresAt.Unix()); !errors.Is(err, errPlaintextPrivateKey) {
		t.Fatalf("expected legacy plaintext error, got %v", err)
	}
}

func TestRegistrationAndPasswordHash(t *testing.T) {
	s := testServer(t)
	recorder := request(t, s, http.MethodPost, "/register", `{"username":"MyCoolUsername","email":"cool@example.com"}`)
	if recorder.Code != http.StatusCreated {
		t.Fatal(recorder.Code, recorder.Body.String())
	}
	var response registrationResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	uuidV4 := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !uuidV4.MatchString(response.Password) {
		t.Fatalf("password is not UUIDv4: %q", response.Password)
	}
	var passwordHash string
	if err := s.store.db.QueryRow("SELECT password_hash FROM users WHERE username = ?", "MyCoolUsername").Scan(&passwordHash); err != nil {
		t.Fatal(err)
	}
	if passwordHash == response.Password || !strings.HasPrefix(passwordHash, "$argon2id$") {
		t.Fatal("password was not stored as an Argon2id hash")
	}
	if !verifyPassword(response.Password, passwordHash) || verifyPassword("wrong", passwordHash) {
		t.Fatal("stored password hash verification failed")
	}
}

func TestRegistrationValidationAndDuplicates(t *testing.T) {
	s := testServer(t)
	cases := []string{"", `{`, `{}`, `{"username":"a"}`, `{"email":"a@example.com"}`, `{"username":"a","email":"b","extra":true}`, `{} {}`}
	for _, body := range cases {
		if got := request(t, s, http.MethodPost, "/register", body).Code; got != http.StatusBadRequest {
			t.Fatalf("body %q: got %d", body, got)
		}
	}
	if got := request(t, s, http.MethodPost, "/register", `{"username":"one","email":"one@example.com"}`).Code; got != http.StatusCreated {
		t.Fatal(got)
	}
	for _, body := range []string{
		`{"username":"one","email":"two@example.com"}`,
		`{"username":"two","email":"one@example.com"}`,
	} {
		if got := request(t, s, http.MethodPost, "/register", body).Code; got != http.StatusConflict {
			t.Fatalf("duplicate registration returned %d", got)
		}
	}
}

func TestAuthenticationLogging(t *testing.T) {
	s := testServer(t)
	if got := request(t, s, http.MethodPost, "/register", `{"username":"logged","email":"logged@example.com"}`).Code; got != http.StatusCreated {
		t.Fatal(got)
	}
	req := httptest.NewRequest(http.MethodPost, "/auth", strings.NewReader(`{"username":"logged"}`))
	req.RemoteAddr = "198.51.100.25:4321"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	recorder := httptest.NewRecorder()
	s.routes().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatal(recorder.Code, recorder.Body.String())
	}
	var ip string
	var userID sql.NullInt64
	if err := s.store.db.QueryRow("SELECT request_ip,user_id FROM auth_logs ORDER BY id DESC LIMIT 1").Scan(&ip, &userID); err != nil {
		t.Fatal(err)
	}
	if ip != "198.51.100.25" || !userID.Valid {
		t.Fatalf("unexpected log: ip=%q user=%+v", ip, userID)
	}
	var lastLogin sql.NullTime
	if err := s.store.db.QueryRow("SELECT last_login FROM users WHERE username = ?", "logged").Scan(&lastLogin); err != nil || !lastLogin.Valid {
		t.Fatal("last_login not updated", err)
	}

	if got := request(t, s, http.MethodPost, "/auth", `{"username":"unknown"}`).Code; got != http.StatusOK {
		t.Fatal(got)
	}
	if err := s.store.db.QueryRow("SELECT user_id FROM auth_logs ORDER BY id DESC LIMIT 1").Scan(&userID); err != nil || userID.Valid {
		t.Fatal("unknown user should log a NULL user_id", err)
	}
}

func TestRateLimitBoundaryAndLogging(t *testing.T) {
	s := testServer(t)
	fixed := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return fixed }
	for i := 1; i <= 10; i++ {
		if got := request(t, s, http.MethodPost, "/auth", "").Code; got != http.StatusOK {
			t.Fatalf("request %d returned %d", i, got)
		}
	}
	if got := request(t, s, http.MethodPost, "/auth", "").Code; got != http.StatusTooManyRequests {
		t.Fatalf("eleventh request returned %d", got)
	}
	var count int
	if err := s.store.db.QueryRow("SELECT COUNT(*) FROM auth_logs").Scan(&count); err != nil || count != 10 {
		t.Fatalf("rate-limited request was logged: count=%d err=%v", count, err)
	}
	fixed = fixed.Add(time.Second)
	if got := request(t, s, http.MethodPost, "/auth", "").Code; got != http.StatusOK {
		t.Fatalf("request after window returned %d", got)
	}
}

func TestRateLimiterConcurrentAndPerIP(t *testing.T) {
	limiter := newIPRateLimiter(10, time.Second)
	now := time.Now()
	var allowed int32
	var wait sync.WaitGroup
	for i := 0; i < 50; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if limiter.allow("192.0.2.1", now) {
				atomic.AddInt32(&allowed, 1)
			}
		}()
	}
	wait.Wait()
	if allowed != 10 {
		t.Fatalf("allowed %d concurrent requests", allowed)
	}
	if !limiter.allow("192.0.2.2", now) {
		t.Fatal("one IP exhausted another IP's window")
	}
	if !limiter.allow("192.0.2.1", now.Add(time.Second)) {
		t.Fatal("window did not expire")
	}
	if !limiter.allow("192.0.2.1", now.Add(-time.Second)) {
		t.Fatal("clock rollback did not reset window")
	}
}

func TestMethodsAndHelperErrors(t *testing.T) {
	s := testServer(t)
	for _, test := range []struct{ method, path string }{
		{http.MethodGet, "/auth"},
		{http.MethodPost, "/.well-known/jwks.json"},
		{http.MethodGet, "/register"},
	} {
		recorder := request(t, s, test.method, test.path, "")
		if recorder.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s: got %d", test.method, test.path, recorder.Code)
		}
	}
	if err := verifyJWT("invalid", &rsa.PublicKey{}); err == nil {
		t.Fatal("invalid token accepted")
	}
	if _, err := rsaPublicKeyFromJWK(jwk{N: "***", E: "AQAB"}); err == nil {
		t.Fatal("bad modulus accepted")
	}
	if _, err := rsaPublicKeyFromJWK(jwk{N: "AQ", E: ""}); err == nil {
		t.Fatal("bad exponent accepted")
	}
	if clientIP(httptest.NewRequest(http.MethodGet, "/", nil)) != "192.0.2.1" {
		t.Fatal("unexpected httptest client IP")
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "not-an-ip"
	if clientIP(req) != "unknown" {
		t.Fatal("invalid address should map to unknown")
	}
	if verifyPassword("x", "bad") || verifyPassword("x", "$argon2id$v=1$m=1,t=1,p=1$bad$bad") {
		t.Fatal("malformed password hash accepted")
	}
}

func TestStoreAndHandlerDatabaseErrors(t *testing.T) {
	s := testServer(t)
	future := time.Now().Add(100 * 365 * 24 * time.Hour).Unix()
	valid, err := s.store.listValid(future)
	if err != nil || len(valid) != 0 {
		t.Fatal(err, len(valid))
	}
	if _, err = s.store.findKey(future, false); err == nil {
		t.Fatal("expected missing key error")
	}
	if _, err = s.store.decodeRow(1, []byte("bad"), 0); err == nil {
		t.Fatal("expected ciphertext parsing error")
	}
	badPEM, err := encryptPrivateKey([]byte(testEncryptionKey), []byte("bad PEM"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.store.decodeRow(1, badPEM, 0); err == nil {
		t.Fatal("expected PEM parsing error")
	}
	if err = s.store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = s.store.listValid(time.Now().Unix()); err == nil {
		t.Fatal("expected database query error")
	}
	if err = s.store.ensureKeys(time.Now()); err == nil {
		t.Fatal("expected database initialization error")
	}
	for _, test := range []struct{ method, path string }{
		{http.MethodPost, "/auth"},
		{http.MethodGet, "/.well-known/jwks.json"},
		{http.MethodPost, "/register"},
	} {
		recorder := request(t, s, test.method, test.path, `{"username":"new","email":"new@example.com"}`)
		if recorder.Code != http.StatusInternalServerError {
			t.Fatalf("%s: expected 500, got %d", test.path, recorder.Code)
		}
	}
}

func TestGenerateSigningAndPasswordHelpers(t *testing.T) {
	key, err := generateSigningKey(time.Now().Add(time.Hour))
	if err != nil || key.PrivateKey == nil {
		t.Fatal(err)
	}
	key.Kid = "test"
	token, err := signJWT(key, jwtClaims{Sub: "test", Iat: time.Now().Unix(), Exp: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if err = verifyJWT(token, &key.PrivateKey.PublicKey); err != nil {
		t.Fatal(err)
	}
	password, err := generateUUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := hashPassword(password)
	if err != nil || !verifyPassword(password, hash) {
		t.Fatal("password helper round trip failed", err)
	}
}

func TestDefaultServerAndAdditionalValidationBranches(t *testing.T) {
	t.Setenv(encryptionKeyVariable, testEncryptionKey)
	originalDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(originalDirectory) })
	s, err := newServer()
	if err != nil {
		t.Fatal(err)
	}
	if err = s.store.Close(); err != nil {
		t.Fatal(err)
	}

	invalidRSA := []byte("-----BEGIN RSA PRIVATE KEY-----\nZm9v\n-----END RSA PRIVATE KEY-----")
	if _, err = parsePrivateKey(invalidRSA); err == nil {
		t.Fatal("invalid PKCS#1 data accepted")
	}
	if err = decodeSegment("***", &jwtClaims{}); err == nil {
		t.Fatal("invalid base64 segment accepted")
	}
	if _, err = rsaPublicKeyFromJWK(jwk{N: "AQ", E: "***"}); err == nil {
		t.Fatal("invalid exponent encoding accepted")
	}
	if err = verifyJWT("e30.e30.invalid*", &rsa.PublicKey{}); err == nil {
		t.Fatal("invalid signature encoding accepted")
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "2001:db8::1"
	if got := clientIP(request); got != "2001:db8::1" {
		t.Fatalf("bare IP parsed as %q", got)
	}
}
