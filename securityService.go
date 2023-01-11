package main

import (
	"context"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis/v8"
)

// Secret key for signing JWTs
const jwtSecret = "mysecret"

// Claims represents the data stored in a JWT
type Claims struct {
	Email string `json:"email"`
	jwt.StandardClaims
}

// GenerateJWT generates a new JWT for the given email address
func GenerateJWT(email string) (string, error) {
	// Set the expiration time for the JWT
	expirationTime := time.Now().Add(24 * time.Hour)
	// Create the claims object
	claims := &Claims{
		Email: email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	// Create the JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Sign the JWT and return it as a string
	return token.SignedString([]byte(jwtSecret))
}

// VerifyJWT verifies the given JWT and returns the email address if it is valid
func VerifyJWT(tokenString string) (string, error) {
	// Parse the JWT
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	})
	if err != nil {
		return "", err
	}
	// Check if the token is valid
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		// Return the email address of the user
		return claims.Email, nil
	}
	return "", fmt.Errorf("invalid token")
}

// Cache the JWT for the given email address for a specified duration
func cacheJWT(email string, token string, duration time.Duration) error {
	// Connect to Redis
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	// Set the key-value pair in Redis
	if err := client.Set(context.Background(), email, token, duration).Err(); err != nil {
		return err
	}
	return nil
}

// Retrieve the cached JWT for the given email address
func getCachedJWT(email string) (string, error) {
	// Connect to Redis
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	// Get the value from Redis
	token, err := client.Get(context.Background(), email).Result()
	if err != nil {
		return "", err
	}
	return token, nil
}
