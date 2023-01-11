package main

import (
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	// Create a new router
	router := mux.NewRouter()
	// Add the login endpoint
	router.HandleFunc("/login", loginHandler).Methods("POST")
	router.HandleFunc("/register", loginHandler).Methods("POST")
	router.HandleFunc("/users", getUsersHandler).Methods("GET").Use(authorize)

	// if you want to use a subrouter
	// subrouter := router.PathPrefix("/api").Subrouter()
	// subrouter.Use(authorize)
	// subrouter.HandleFunc("/users", usersHandler).Methods("GET")
	// subrouter.HandleFunc("/messages", messagesHandler).Methods("POST")

	// Start the server
	http.ListenAndServe(":8080", router)
}
