package main

import (
	"github.com/choukaryasandeep/support-ticket-system/config"
	"github.com/choukaryasandeep/support-ticket-system/routes"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// Load env
	err := godotenv.Load(".env")
	if err != nil {
		panic("Error loading .env file")
	}

	// Initialize DB
	config.ConnectDB()

	// Init Gin Router
	r := gin.Default()

	// Load Routes
	routes.AuthRoutes(r)
	routes.TicketRoutes(r)

	// Start Server
	r.Run(":8080")
}
