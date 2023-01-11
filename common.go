package main

import (
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword hashes the given password using SHA-256
func HashPassword(password string) (string, error) {
	hash := sha256.Sum256([]byte(password))
	return fmt.Sprintf("%x", hash), nil
}

// CompareHashAndPassword compares the given hashed password and plaintext password
func CompareHashAndPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}
