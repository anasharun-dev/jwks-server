package main

import (
	"log"
	"net/http"
)

func main() {
	srv, err := newServer()
	if err != nil {
		log.Fatalf("could not initialize server: %v", err)
	}

	log.Println("JWKS server listening on http://localhost:8080")
	if err := http.ListenAndServe(":8080", srv.routes()); err != nil {
		log.Fatal(err)
	}
}
