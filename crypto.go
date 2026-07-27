package configs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

func GenerateOTP(length int) (string, error) {
	charSet := "0123456789"
	code := make([]byte, length)

	for i := range code {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charSet))))
		if err != nil {
			return "", err // Handle error if crypto/rand fails
		}
		code[i] = charSet[num.Int64()]
	}

	return string(code), nil
}

const systemErrorMsg = "terjadi kesalahan pada sistem"

func GenerateDefaultPassword() (string, error) {
	// Create a byte slice to store the random bytes
	makeByte := make([]byte, 7)

	// Read random bytes from the crypto/rand package
	_, err := rand.Read(makeByte)
	if err != nil {
		return "", err
	}

	// Convert the random bytes to a hexadecimal string
	defaultPwd := hex.EncodeToString(makeByte)
	return "BBO-" + defaultPwd, nil
}

func GenerateToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// Encrypt encrypts plaintext using AES-256 in GCM mode
func Encrypt(plaintext []byte) (string, error) {
	block, err := aes.NewCipher([]byte(CRYPTO_ENCRYPTION_KEY))
	if err != nil {
		return "", err
	}

	nonce := make([]byte, 12) // GCM standard nonce length
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts ciphertext using AES-256 in GCM mode
func Decrypt(ciphertextStr string) (string, error) {
	if ciphertextStr == "" {
		return "", fmt.Errorf("empty content")
	}

	ciphertext, err := hex.DecodeString(ciphertextStr)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < 13 {
		return "", fmt.Errorf("invalid content")
	}

	block, err := aes.NewCipher([]byte(CRYPTO_ENCRYPTION_KEY))
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce, ciphertext := ciphertext[:12], ciphertext[12:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// Argon2id parameters (OWASP-recommended)
const (
	argon2Time    = 3         // iterations
	argon2Memory  = 64 * 1024 // 64 MiB in KiB
	argon2Threads = 2         // parallelism (lanes)
	argon2KeyLen  = 32        // derived key length in bytes
	argon2SaltLen = 16        // salt length in bytes
)

// GeneratePassword hashes a password using Argon2id with a per-user random
// salt. The returned string is in PHC string format:
// "$argon2id$v=19$m=65536,t=3,p=2$<base64-salt>$<base64-key>".
// This replaces the previous static-salt implementation.
func GeneratePassword(pwd string) (string, error) {
	if pwd == "" {
		return "", errors.New("password must not be empty")
	}

	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(pwd), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argon2Memory,
		argon2Time,
		argon2Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash)), nil
}

// VerifyPassword checks a password against an encoded hash. It supports two
// formats:
//   - New PHC format: "$argon2id$v=19$m=...,t=...,p=...$<salt>$<key>"
//   - Legacy hex format: plain hexadecimal hash (static salt, no "$" delimiter)
//
// Legacy hashes are verified with constant-time comparison and flagged for
// rehashing on next password change. New hashes always use per-user random
// salt and constant-time comparison.
func VerifyPassword(pwd, hashedPwd string) (bool, error) {
	if strings.HasPrefix(hashedPwd, "$argon2id$") {
		return verifyArgon2idPHC(pwd, hashedPwd)
	}
	return verifyLegacyHash(pwd, hashedPwd)
}

// verifyArgon2idPHC parses a PHC-string-format Argon2id hash and verifies the
// password using constant-time comparison.
func verifyArgon2idPHC(pwd, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("invalid argon2id hash format")
	}

	var (
		memory      uint32
		iterations  uint32
		parallelism uint8
	)

	for _, kv := range strings.Split(parts[3], ",") {
		idx := strings.IndexByte(kv, '=')
		if idx < 0 {
			return false, fmt.Errorf("invalid param %q", kv)
		}
		k, v := kv[:idx], kv[idx+1:]
		num, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return false, fmt.Errorf("invalid param value %q: %w", kv, err)
		}
		switch k {
		case "m":
			memory = uint32(num)
		case "t":
			iterations = uint32(num)
		case "p":
			parallelism = uint8(num)
		default:
			return false, fmt.Errorf("unknown param %q", k)
		}
	}

	if memory == 0 || iterations == 0 || parallelism == 0 {
		return false, errors.New("missing argon2id parameters")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("invalid salt encoding: %w", err)
	}

	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("invalid key encoding: %w", err)
	}

	if len(salt) == 0 || len(key) == 0 {
		return false, errors.New("empty salt or key")
	}

	testHash := argon2.IDKey([]byte(pwd), salt, iterations, memory, parallelism, uint32(len(key)))

	if subtle.ConstantTimeCompare(testHash, key) == 1 {
		return true, nil
	}
	return false, nil
}

// verifyLegacyHash verifies old-format hashes (plain hex, static salt) using
// constant-time comparison. This maintains backward compatibility with
// existing password hashes until users change their passwords.
func verifyLegacyHash(pwd, hashedPwd string) (bool, error) {
	storedHash, err := hex.DecodeString(hashedPwd)
	if err != nil {
		return false, fmt.Errorf("invalid legacy hash format: %w", err)
	}

	const (
		legacyTime    = 5
		legacyMemory  = 64 * 1024
		legacyThreads = 4
	)

	testHash := argon2.IDKey([]byte(pwd), []byte(CRYPTO_ENCRYPTION_KEY), legacyTime, legacyMemory, legacyThreads, uint32(len(storedHash)))

	if subtle.ConstantTimeCompare(testHash, storedHash) == 1 {
		return true, nil
	}
	return false, nil
}

// EncryptReqBody encrypts a request body using AES-GCM with a random nonce.
// The output is base64(nonce || ciphertext || tag).
func EncryptReqBody(input string) (string, error) {
	key := []byte(PAYLOAD_ENCRYPTION_KEY)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", errors.New(systemErrorMsg)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.New(systemErrorMsg)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", errors.New(systemErrorMsg)
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(input), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptReqBody decrypts a request body produced by EncryptReqBody.
// Input is base64-encoded (URL-safe "-" are converted to "/").
func DecryptReqBody(encoded string) ([]byte, error) {
	encoded = strings.ReplaceAll(encoded, "-", "/")

	key := []byte(PAYLOAD_ENCRYPTION_KEY)

	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return []byte{}, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return []byte{}, errors.New(systemErrorMsg)
	}

	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ct, nil)
	if err != nil {
		return []byte{}, err
	}

	return plaintext, nil
}
