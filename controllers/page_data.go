package controllers

import "github.com/choukaryasandeep/support-ticket-system/models"

// PageData represents the data passed to templates
type PageData struct {
	IsAuthenticated bool             `json:"is_authenticated"`
	User            *models.User     `json:"user,omitempty"`
	Error           string           `json:"error,omitempty"`
	Tickets         []models.Ticket  `json:"tickets,omitempty"`
	Ticket          *models.Ticket   `json:"ticket,omitempty"`
	Comments        []models.Comment `json:"comments,omitempty"`
}
