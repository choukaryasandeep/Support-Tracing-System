package config

import (
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var db *mongo.Database

// ConnectMongoDB establishes connection to MongoDB
func ConnectMongoDB() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Connect to MongoDB
	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatal("Error connecting to MongoDB:", err)
	}

	// Ping the database
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal("Error pinging MongoDB:", err)
	}

	// Set the database
	db = client.Database("support_tickets")
	log.Println("Connected to MongoDB!")
}

// GetCollection returns a MongoDB collection
func GetCollection(name string) *mongo.Collection {
	return db.Collection(name)
}

// GetDB returns the MongoDB database instance
func GetDB() *mongo.Database {
	return db
}
