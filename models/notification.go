package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// NotificationType represents the type of notification
type NotificationType string

const (
	NotificationTypeStatusUpdate   NotificationType = "status_update"
	NotificationTypeNewComment     NotificationType = "new_comment"
	NotificationTypeNewTicket      NotificationType = "new_ticket"
	NotificationTypeAdminComment   NotificationType = "admin_comment"
	NotificationTypeTicketAssigned NotificationType = "ticket_assigned"
)

// Notification represents a notification in the system
type Notification struct {
	ID          primitive.ObjectID `bson:"_id" json:"id"`
	UserID      primitive.ObjectID `bson:"user_id" json:"user_id"`
	Type        NotificationType   `bson:"type" json:"type"`
	Title       string             `bson:"title" json:"title"`
	Message     string             `bson:"message" json:"message"`
	TicketID    primitive.ObjectID `bson:"ticket_id" json:"ticket_id"`
	TicketTitle string             `bson:"ticket_title" json:"ticket_title"`
	Read        bool               `bson:"read" json:"read"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
}
