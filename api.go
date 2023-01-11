package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"time"

	_ "github.com/lib/pq"
)

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token string `json:"token"`
}

var db *sql.DB

func init() {
	var err error
	// Connect to the database
	db, err = sql.Open("postgres", "postgres://user:password@localhost?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	// Set the maximum number of connections in the connection pool
	db.SetMaxOpenConns(100)
	// Set the maximum lifetime of a connection
	db.SetConnMaxLifetime(time.Minute)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the request body
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()
	// Validate the request
	if req.Email == "" || req.Password == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// Hash the password
	hashedPassword, err := HashPassword(req.Password)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	// Insert the user into the database
	_, err = db.ExecContext(context.Background(), "INSERT INTO security.users (email, password) VALUES ($1, $2)", req.Email, hashedPassword)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	// Return the result
	res := map[string]string{"result": "success"}
	if err := json.NewEncoder(w).Encode(res); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the request body
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()
	// Validate the request
	if req.Email == "" || req.Password == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// Get the hashed password for the user from the database
	var hashedPassword string
	err := db.QueryRowContext(context.Background(), "SELECT password FROM security.users WHERE email=$1", req.Email).Scan(&hashedPassword)
	if err == sql.ErrNoRows {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := CompareHashAndPassword(hashedPassword, req.Password); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Generate a JWT for the user
	token, err := GenerateJWT(req.Email)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	// Cache the JWT
	if err := cacheJWT(req.Email, token, time.Hour); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	// Return the result
	res := map[string]string{"token": token}
	if err := json.NewEncoder(w).Encode(res); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}

func getUsersHandler(w http.ResponseWriter, r *http.Request) {
	// Get the user emails from the database
	rows, err := db.QueryContext(context.Background(), "SELECT email FROM users")
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	// Process the rows
	emails := make([]string, 0)
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		emails = append(emails, email)
	}
	// Return the result
	res := map[string][]string{"emails": emails}
	if err := json.NewEncoder(w).Encode(res); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}

func authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the token from the request header
		token := r.Header.Get("Authorization")
		if token == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// Verify the token
		email, err := VerifyJWT(token)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// Check if the token is cached
		cachedToken, err := getCachedJWT(email)
		if err != nil || cachedToken != token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// Call the next handler
		next.ServeHTTP(w, r)
	})
}
