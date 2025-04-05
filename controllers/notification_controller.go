package controllers

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/choukaryasandeep/support-ticket-system/config"
	"github.com/choukaryasandeep/support-ticket-system/models"
	"github.com/go-chi/chi/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type NotificationController struct{}

var NotificationAPI = &NotificationController{}

// GetUserNotifications returns all notifications for the current user
func (c *NotificationController) GetUserNotifications(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	userID, err := primitive.ObjectIDFromHex(r.Context().Value("user_id").(string))
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Get query parameters
	read := r.URL.Query().Get("read")
	limit := r.URL.Query().Get("limit")

	// Build query
	query := bson.M{"user_id": userID}
	if read != "" {
		query["read"] = read == "true"
	}

	// Set options
	opts := options.Find()
	if limit != "" {
		opts.SetLimit(50) // Default limit
	}
	opts.SetSort(bson.D{{"created_at", -1}})

	// Find notifications
	cursor, err := config.GetCollection("notifications").Find(r.Context(), query, opts)
	if err != nil {
		log.Printf("Error fetching notifications: %v\n", err)
		http.Error(w, "Error fetching notifications", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(r.Context())

	var notifications []models.Notification
	if err := cursor.All(r.Context(), &notifications); err != nil {
		log.Printf("Error decoding notifications: %v\n", err)
		http.Error(w, "Error decoding notifications", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(notifications)
}

// MarkNotificationAsRead marks a notification as read
func (c *NotificationController) MarkNotificationAsRead(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	notificationID, err := primitive.ObjectIDFromHex(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid notification ID", http.StatusBadRequest)
		return
	}

	userID, err := primitive.ObjectIDFromHex(r.Context().Value("user_id").(string))
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Update notification
	result, err := config.GetCollection("notifications").UpdateOne(
		r.Context(),
		bson.M{
			"_id":     notificationID,
			"user_id": userID,
		},
		bson.M{
			"$set": bson.M{
				"read": true,
			},
		},
	)
	if err != nil {
		log.Printf("Error updating notification: %v\n", err)
		http.Error(w, "Error updating notification", http.StatusInternalServerError)
		return
	}

	if result.MatchedCount == 0 {
		http.Error(w, "Notification not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Notification marked as read"})
}

// MarkAllNotificationsAsRead marks all notifications as read for the current user
func (c *NotificationController) MarkAllNotificationsAsRead(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	userID, err := primitive.ObjectIDFromHex(r.Context().Value("user_id").(string))
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Update all unread notifications
	result, err := config.GetCollection("notifications").UpdateMany(
		r.Context(),
		bson.M{
			"user_id": userID,
			"read":    false,
		},
		bson.M{
			"$set": bson.M{
				"read": true,
			},
		},
	)
	if err != nil {
		log.Printf("Error updating notifications: %v\n", err)
		http.Error(w, "Error updating notifications", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "All notifications marked as read",
		"count":   result.ModifiedCount,
	})
}
