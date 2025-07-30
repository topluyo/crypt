package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// Encrypt encrypts data with password using AES-256-CBC with checksum
func Encrypt(data, password string) (string, error) {
	// Create password hash using SHA256
	hasher := sha256.New()
	hasher.Write([]byte(password))
	passwordHash := hasher.Sum(nil)

	// Create 16-byte zero IV
	iv := make([]byte, 16)

	// Create checksum (first 4 characters of MD5 hash)
	md5Hasher := md5.New()
	md5Hasher.Write([]byte(data))
	checksum := hex.EncodeToString(md5Hasher.Sum(nil))[:4]
	dataWithChecksum := checksum + data

	// Create AES cipher
	block, err := aes.NewCipher(passwordHash)
	if err != nil {
		return "", err
	}

	// Pad data to be multiple of block size
	dataBytes := []byte(dataWithChecksum)
	padding := aes.BlockSize - len(dataBytes)%aes.BlockSize
	for i := 0; i < padding; i++ {
		dataBytes = append(dataBytes, byte(padding))
	}

	// Create CBC mode
	mode := cipher.NewCBCEncrypter(block, iv)

	// Encrypt
	encrypted := make([]byte, len(dataBytes))
	mode.CryptBlocks(encrypted, dataBytes)

	// Return base64 encoded result
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// Decrypt decrypts data with password using AES-256-CBC with checksum verification
func Decrypt(data, password string) (string, error) {
	// Create password hash using SHA256
	hasher := sha256.New()
	hasher.Write([]byte(password))
	passwordHash := hasher.Sum(nil)

	// Create 16-byte zero IV
	iv := make([]byte, 16)

	// Decode base64 data
	encryptedData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}

	// Create AES cipher
	block, err := aes.NewCipher(passwordHash)
	if err != nil {
		return "", err
	}

	// Create CBC mode
	mode := cipher.NewCBCDecrypter(block, iv)

	// Decrypt
	decrypted := make([]byte, len(encryptedData))
	mode.CryptBlocks(decrypted, encryptedData)

	// Remove padding
	if len(decrypted) == 0 {
		return "", fmt.Errorf("decrypted data is empty")
	}

	padding := int(decrypted[len(decrypted)-1])
	if padding > len(decrypted) || padding == 0 {
		return "", fmt.Errorf("invalid padding")
	}

	decrypted = decrypted[:len(decrypted)-padding]

	// Extract checksum and message
	if len(decrypted) < 4 {
		return "", fmt.Errorf("decrypted data too short")
	}

	checksum := string(decrypted[:4])
	message := string(decrypted[4:])

	// Verify checksum
	md5Hasher := md5.New()
	md5Hasher.Write([]byte(message))
	expectedChecksum := hex.EncodeToString(md5Hasher.Sum(nil))[:4]

	if checksum != expectedChecksum {
		return "", fmt.Errorf("checksum verification failed")
	}

	return message, nil
}

// func main() {
// 	// Test the encryption and decryption
// 	data := "Hello World"
// 	password := "password"

// 	encrypted, err := Encrypt(data, password)
// 	if err != nil {
// 		fmt.Printf("Encryption error: %v\n", err)
// 		return
// 	}
// 	fmt.Printf("Encrypted: %s\n", encrypted)

// 	decrypted, err := Decrypt(encrypted, password)
// 	if err != nil {
// 		fmt.Printf("Decryption error: %v\n", err)
// 		return
// 	}
// 	fmt.Printf("Decrypted: %s\n", decrypted)
// }
