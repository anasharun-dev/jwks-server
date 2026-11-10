package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	keySize       = 2048
	tokenLifetime = time.Hour
	maxJSONBody   = 1 << 20
)

type signingKey struct {
	PrivateKey *rsa.PrivateKey
	Kid        string
	ExpiresAt  time.Time
}

type server struct {
	store   *keyStore
	now     func() time.Time
	limiter *ipRateLimiter
}

type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwksResponse struct {
	Keys []jwk `json:"keys"`
}

type jwtClaims struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

type registrationRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
}

type registrationResponse struct {
	Password string `json:"password"`
}

type authRequest struct {
	Username string `json:"username"`
}

func newServer() (*server, error) { return newServerAt("totally_not_my_privateKeys.db") }

func newServerAt(path string) (*server, error) {
	store, err := openKeyStore(path)
	if err != nil {
		return nil, err
	}
	if err = store.ensureKeys(time.Now()); err != nil {
		store.Close()
		return nil, err
	}
	return &server{store: store, now: time.Now, limiter: newIPRateLimiter(10, time.Second)}, nil
}

func generateSigningKey(expiresAt time.Time) (signingKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return signingKey{}, err
	}
	return signingKey{PrivateKey: privateKey, ExpiresAt: expiresAt}, nil
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("/auth", s.handleAuth)
	mux.HandleFunc("/register", s.handleRegister)
	return mux
}

func (s *server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	keys, err := s.store.listValid(s.now().Unix())
	if err != nil {
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	public := make([]jwk, 0, len(keys))
	for _, key := range keys {
		public = append(public, publicJWK(key))
	}
	writeJSON(w, http.StatusOK, jwksResponse{Keys: public})
}

func (s *server) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := clientIP(r)
	if !s.limiter.allow(ip, s.now()) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	username := readOptionalAuthUsername(r)
	_, expired := r.URL.Query()["expired"]
	key, err := s.store.findKey(s.now().Unix(), expired)
	if err != nil {
		http.Error(w, "no signing key available", http.StatusInternalServerError)
		return
	}
	expiresAt := s.now().Add(tokenLifetime).Unix()
	if expired {
		expiresAt = key.ExpiresAt.Unix()
	}
	subject := "fake-user"
	if username != "" {
		subject = username
	}
	token, err := signJWT(key, jwtClaims{Sub: subject, Iat: s.now().Unix(), Exp: expiresAt})
	if err != nil {
		http.Error(w, "failed to sign token", http.StatusInternalServerError)
		return
	}
	if err = s.store.logAuthentication(ip, username, s.now()); err != nil {
		http.Error(w, "failed to record authentication", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(token))
}

func readOptionalAuthUsername(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	defer r.Body.Close()
	var request authRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxJSONBody)).Decode(&request); err != nil {
		return ""
	}
	return strings.TrimSpace(request.Username)
}

func (s *server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	var request registrationRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, maxJSONBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "invalid JSON request", http.StatusBadRequest)
		return
	}
	if err := ensureJSONDocumentEnds(decoder); err != nil {
		http.Error(w, "invalid JSON request", http.StatusBadRequest)
		return
	}
	request.Username = strings.TrimSpace(request.Username)
	request.Email = strings.TrimSpace(request.Email)
	if request.Username == "" || request.Email == "" {
		http.Error(w, "username and email are required", http.StatusBadRequest)
		return
	}
	password, err := generateUUIDv4()
	if err != nil {
		http.Error(w, "failed to generate password", http.StatusInternalServerError)
		return
	}
	passwordHash, err := hashPassword(password)
	if err != nil {
		http.Error(w, "failed to protect password", http.StatusInternalServerError)
		return
	}
	if err = s.store.registerUser(request.Username, request.Email, passwordHash); err != nil {
		if isUniqueConstraint(err) {
			http.Error(w, "username or email already registered", http.StatusConflict)
			return
		}
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, registrationResponse{Password: password})
}

func ensureJSONDocumentEnds(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	return err
}

func isUniqueConstraint(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "unique constraint failed")
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	if parsed := net.ParseIP(r.RemoteAddr); parsed != nil {
		return parsed.String()
	}
	return "unknown"
}

func publicJWK(key signingKey) jwk {
	pub := &key.PrivateKey.PublicKey
	return jwk{Kty: "RSA", Use: "sig", Kid: key.Kid, Alg: "RS256", N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()), E: encodeExponent(pub.E)}
}

func encodeExponent(e int) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(e))
	first := 0
	for first < len(buf)-1 && buf[first] == 0 {
		first++
	}
	return base64.RawURLEncoding.EncodeToString(buf[first:])
}

func signJWT(key signingKey, claims jwtClaims) (string, error) {
	header := map[string]string{"alg": "RS256", "typ": "JWT", "kid": key.Kid}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	headerPart := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsPart := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := headerPart + "." + claimsPart
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key.PrivateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func verifyJWT(token string, pub *rsa.PublicKey) error {
	parts := splitJWT(token)
	if len(parts) != 3 {
		return errors.New("invalid token format")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature)
}

func splitJWT(token string) []string { return strings.Split(token, ".") }

func decodeSegment[T any](segment string, out *T) error {
	data, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func rsaPublicKeyFromJWK(j jwk) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(j.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(j.E)
	if err != nil {
		return nil, err
	}
	if len(eBytes) == 0 || len(eBytes) > 8 {
		return nil, errors.New("invalid exponent")
	}
	var e uint64
	for _, b := range eBytes {
		e = (e << 8) | uint64(b)
	}
	if e > uint64(^uint(0)>>1) {
		return nil, errors.New("exponent too large")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(e)}, nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
