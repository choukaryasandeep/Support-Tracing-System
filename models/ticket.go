package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Priority represents the ticket priority level
type Priority string

const (
	PriorityLow    Priority = "low"
	PriorityMedium Priority = "medium"
	PriorityHigh   Priority = "high"
)

// Status represents the ticket status
type Status string

const (
	StatusOpen       Status = "open"
	StatusInProgress Status = "in_progress"
	StatusResolved   Status = "resolved"
	StatusClosed     Status = "closed"
)

// Category represents the ticket category
type Category string

const (
	CategoryTechnical Category = "technical"
	CategoryBilling   Category = "billing"
	CategoryGeneral   Category = "general"
	CategoryOther     Category = "other"
)

// Ticket represents a support ticket
type Ticket struct {
	ID          primitive.ObjectID  `bson:"_id,omitempty" json:"id"`
	Title       string              `bson:"title" json:"title"`
	Description string              `bson:"description" json:"description"`
	Category    Category            `bson:"category" json:"category"`
	Priority    Priority            `bson:"priority" json:"priority"`
	Status      Status              `bson:"status" json:"status"`
	CreatedBy   primitive.ObjectID  `bson:"created_by" json:"created_by"`
	AssignedTo  *primitive.ObjectID `bson:"assigned_to,omitempty" json:"assigned_to,omitempty"`
	CreatedAt   time.Time           `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time           `bson:"updated_at" json:"updated_at"`
	ClosedAt    *time.Time          `bson:"closed_at,omitempty" json:"closed_at,omitempty"`
	Comments    []Comment           `bson:"comments" json:"comments"`
}

// Comment represents a comment on a ticket
type Comment struct {
	ID        primitive.ObjectID `json:"id" bson:"_id"`
	TicketID  primitive.ObjectID `json:"ticket_id" bson:"ticket_id"`
	UserID    primitive.ObjectID `json:"user_id" bson:"user_id"`
	UserName  string             `json:"user_name" bson:"user_name"`
	Content   string             `json:"content" bson:"content"`
	CreatedAt time.Time          `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time          `json:"updated_at" bson:"updated_at"`
	Role      string              `json: "role"       bson:"role"`    
}
