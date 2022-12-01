package main

import (
	"log"
	"net/http"
)

func main() {
	// routes for handling network requests
	http.HandleFunc("/signin", Signin)
	http.HandleFunc("/welcome", Welcome)
	http.HandleFunc("/refresh", Refresh)
	http.HandleFunc("/logout", Logout)

	log.Fatal(http.ListenAndServe("localhost:8080", nil))
}
