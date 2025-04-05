package main

import (
	"log"
	"net/http"

	"github.com/choukaryasandeep/support-ticket-system/config"
	"github.com/choukaryasandeep/support-ticket-system/controllers"
	"github.com/choukaryasandeep/support-ticket-system/routes"
)

func main() {
	// Initialize MongoDB
	config.ConnectMongoDB()

	// Initialize controllers
	controllers.InitControllers(config.GetDB())

	// Initialize router
	router := routes.SetupRouter()

	// Start server
	log.Println("Server starting on :8081")
	if err := http.ListenAndServe(":8081", router); err != nil {
		log.Fatal(err)
	}
}
