package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	encryptionKeyVariable = "NOT_MY_KEY"
	argonTime             = 1
	argonMemory           = 64 * 1024
	argonThreads          = 4
	argonKeyLength        = 32
)

var encryptedKeyPrefix = []byte("AESGCM1")

func validAESKeyLength(length int) bool {
	return length == 16 || length == 24 || length == 32
}

func encryptionKeyFromEnvironment() ([]byte, error) {
	value, ok := os.LookupEnv(encryptionKeyVariable)
	if !ok || value == "" {
		return nil, fmt.Errorf("%s must be set to a 16, 24, or 32-byte AES key", encryptionKeyVariable)
	}
	if validAESKeyLength(len(value)) {
		return []byte(value), nil
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		decoded, err := encoding.DecodeString(value)
		if err == nil && validAESKeyLength(len(decoded)) {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("%s must contain or encode a 16, 24, or 32-byte AES key", encryptionKeyVariable)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create AES-GCM: %w", err)
	}
	return gcm, nil
}

func encryptPrivateKey(key, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate encryption nonce: %w", err)
	}
	result := make([]byte, 0, len(encryptedKeyPrefix)+len(nonce)+len(plaintext)+gcm.Overhead())
	result = append(result, encryptedKeyPrefix...)
	result = append(result, nonce...)
	return gcm.Seal(result, nonce, plaintext, nil), nil
}

func decryptPrivateKey(key, encoded []byte) ([]byte, error) {
	if len(encoded) < len(encryptedKeyPrefix) || string(encoded[:len(encryptedKeyPrefix)]) != string(encryptedKeyPrefix) {
		return nil, errors.New("private key record is not recognized AES-GCM ciphertext")
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	encoded = encoded[len(encryptedKeyPrefix):]
	if len(encoded) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("encrypted private key record is truncated")
	}
	nonce := encoded[:gcm.NonceSize()]
	ciphertext := encoded[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("private key authentication failed")
	}
	return plaintext, nil
}

func generateUUIDv4() (string, error) {
	value := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLength)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash)), nil
}

func verifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var memory, iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false
	}
	if memory == 0 || iterations == 0 || parallelism == 0 || memory > 1024*1024 || iterations > 10 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(expected) == 0 {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}
