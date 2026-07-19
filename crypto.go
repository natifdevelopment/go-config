package configs

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
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

func GeneratePassword(pwd string) (string, error) {
	// Argon2 parameters
	const (
		time    = 5         // Time cost (number of iterations)
		memory  = 64 * 1024 // Memory cost (in KB)
		threads = 4         // Parallelism (number of threads)
		keyLen  = 32        // Desired length of the derived key
	)

	// Hash the password with Argon2
	hash := argon2.IDKey([]byte(pwd), []byte(CRYPTO_ENCRYPTION_KEY), time, memory, threads, keyLen)

	// Encode the hash to a hexadecimal string
	return hex.EncodeToString(hash), nil
}

func VerifyPassword(pwd, hashedPwd string) (bool, error) {
	// Rehash the password with the same salt
	rehashedPassword, err := GeneratePassword(pwd)
	if err != nil {
		return false, err
	}

	// Compare the hashed password
	return rehashedPassword == hashedPwd, nil
}

// // Parameter Argon2
// const (
// 	time    = 3         // iterations
// 	memory  = 64 * 1024 // 64 MB
// 	threads = 4
// 	keyLen  = 32
// 	saltLen = 16
// )

// func GeneratePassword(pwd string) (string, error) {

// 	// Generate random salt
// 	salt := make([]byte, saltLen)
// 	if _, err := rand.Read(salt); err != nil {
// 		return "", err
// 	}

// 	// Hash
// 	hash := argon2.IDKey([]byte(pwd), salt, time, memory, threads, keyLen)

// 	// Simpan dengan format: base64(salt)$base64(hash)
// 	encoded := fmt.Sprintf("%s$%s",
// 		base64.RawStdEncoding.EncodeToString(salt),
// 		base64.RawStdEncoding.EncodeToString(hash))

// 	return encoded, nil
// }

// func VerifyPassword(pwd, encoded string) (bool, error) {
// 	// Format encoded: "base64(salt)$base64(hash)"
// 	parts := strings.Split(encoded, "$")
// 	if len(parts) != 2 {
// 		return false, errors.New("invalid encoded hash format")
// 	}

// 	// Decode salt
// 	salt, err := base64.RawStdEncoding.DecodeString(parts[0])
// 	if err != nil {
// 		return false, err
// 	}

// 	// Decode hash
// 	hash, err := base64.RawStdEncoding.DecodeString(parts[1])
// 	if err != nil {
// 		return false, err
// 	}

// 	// Generate hash dari password yang diinput
// 	testHash := argon2.IDKey([]byte(pwd), salt, time, memory, threads, uint32(len(hash)))

// 	// Constant time compare
// 	if subtle.ConstantTimeCompare(hash, testHash) == 1 {
// 		return true, nil
// 	}

// 	return false, nil
// }

func EncryptReqBody(input string) (string, error) {
	key := []byte(PAYLOAD_ENCRYPTION_KEY)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", errors.New(systemErrorMsg)
	}

	// Pad the input to the block size
	padSize := aes.BlockSize - (len(input) % aes.BlockSize)
	padding := bytes.Repeat([]byte{byte(padSize)}, padSize)
	paddedInput := append([]byte(input), padding...)

	// Encrypt each block separately
	ciphertext := make([]byte, len(paddedInput))
	for i := 0; i < len(paddedInput); i += aes.BlockSize {
		block.Encrypt(ciphertext[i:i+aes.BlockSize], paddedInput[i:i+aes.BlockSize])
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

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

	if len(ciphertext)%aes.BlockSize != 0 {
		return []byte{}, err
	}

	// Decrypt each block separately
	for i := 0; i < len(ciphertext); i += aes.BlockSize {
		block.Decrypt(ciphertext[i:i+aes.BlockSize], ciphertext[i:i+aes.BlockSize])
	}

	// Remove PKCS7 padding
	plaintext, err := pkcs7Unpad(ciphertext)
	if err != nil {
		return []byte{}, err
	}

	return plaintext, nil
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New(systemErrorMsg)
	}

	padding := int(data[len(data)-1])
	if padding > aes.BlockSize || padding == 0 {
		return nil, errors.New(systemErrorMsg)
	}

	for i := len(data) - 1; i >= len(data)-padding; i-- {
		if int(data[i]) != padding {
			return nil, errors.New(systemErrorMsg)
		}
	}

	return data[:len(data)-padding], nil
}
