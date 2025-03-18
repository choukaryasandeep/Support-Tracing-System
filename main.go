package main

import (
	"log"
	"net/http"

	"github.com/choukaryasandeep/support-ticket-system/config"
	"github.com/choukaryasandeep/support-ticket-system/routes"
)

func main() {
	// Initialize MongoDB
	config.ConnectMongoDB()

	// Initialize router
	r := routes.SetupRouter()

	// Start Server
	log.Println("Server starting on http://localhost:8080")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatal("Error starting server:", err)
	}
}
