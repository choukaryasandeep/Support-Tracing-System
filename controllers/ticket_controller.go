package controllers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/choukaryasandeep/support-ticket-system/config"
	"github.com/choukaryasandeep/support-ticket-system/models"
	"github.com/go-chi/chi/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type TicketController struct {
	db *mongo.Database
}

var TicketAPI TicketController

type CreateTicketRequest struct {
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Category    models.Category `json:"category"`
	Priority    models.Priority `json:"priority"`
}

type CommentRequest struct {
	Content string `json:"content"`
}

type UpdateStatusRequest struct {
	Status string `json:"status"`
}

type UpdatePriorityRequest struct {
	Priority string `json:"priority"`
}

type AssignTicketRequest struct {
	AgentID string `json:"agent_id"`
}

type AddCommentRequest struct {
	Content string `json:"content"`
}

const (
	maxFileSize = 10 << 20 // 10 MB
	uploadDir   = "uploads"
)

func init() {
	// Create uploads directory if it doesn't exist
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		panic(fmt.Sprintf("Failed to create upload directory: %v", err))
	}
}

// createNotification creates a new notification in the database
func createNotification(ctx context.Context, notification models.Notification) error {
	_, err := config.GetCollection("notifications").InsertOne(ctx, notification)
	return err
}

// GetUserTickets returns all tickets for the current user
func (c *TicketController) GetUserTickets(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Convert string user ID to ObjectID
	userIDStr := r.Context().Value("user_id").(string)
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		log.Printf("Error converting user ID: %v\n", err)
		http.Error(w, "Invalid user ID", http.StatusInternalServerError)
		return
	}

	userRole := r.Context().Value("user_role").(string)
	log.Printf("Fetching tickets for user ID: %s with role: %s\n", userID.Hex(), userRole)

	var filter bson.M
	switch userRole {
	case "user":
		// Regular users can only see their own tickets
		filter = bson.M{"created_by": userID}
	case "agent":
		// Agents can see tickets they created OR tickets assigned to them
		filter = bson.M{
			"$or": []bson.M{
				{"created_by": userID},  // Tickets created by the agent
				{"assigned_to": userID}, // Tickets assigned to the agent
			},
		}
	case "admin":
		// Admins can see all tickets
		filter = bson.M{}
	default:
		log.Printf("Invalid user role: %s\n", userRole)
		http.Error(w, "Invalid user role", http.StatusForbidden)
		return
	}

	// Apply status filter if provided
	if status := r.URL.Query().Get("status"); status != "" {
		filter["status"] = status
	}

	// Apply priority filter if provided
	if priority := r.URL.Query().Get("priority"); priority != "" {
		filter["priority"] = priority
	}

	log.Printf("Fetching tickets with filter: %+v\n", filter)
	cursor, err := config.GetCollection("tickets").Find(r.Context(), filter)
	if err != nil {
		log.Printf("Error fetching tickets: %v\n", err)
		http.Error(w, "Error fetching tickets", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(r.Context())

	var tickets []models.Ticket
	if err := cursor.All(r.Context(), &tickets); err != nil {
		log.Printf("Error decoding tickets: %v\n", err)
		http.Error(w, "Error decoding tickets", http.StatusInternalServerError)
		return
	}

	// Create a map to store user information
	userMap := make(map[string]models.User)

	// Collect all user IDs we need to look up
	var userIDs []primitive.ObjectID
	for _, ticket := range tickets {
		userIDs = append(userIDs, ticket.CreatedBy)
		if ticket.AssignedTo != nil {
			userIDs = append(userIDs, *ticket.AssignedTo)
		}
	}

	// Look up all users at once
	if len(userIDs) > 0 {
		userCursor, err := config.GetCollection("users").Find(r.Context(), bson.M{
			"_id": bson.M{"$in": userIDs},
		})
		if err != nil {
			log.Printf("Error fetching users: %v\n", err)
		} else {
			defer userCursor.Close(r.Context())
			var users []models.User
			if err := userCursor.All(r.Context(), &users); err != nil {
				log.Printf("Error decoding users: %v\n", err)
			} else {
				for _, user := range users {
					userMap[user.ID.Hex()] = user
				}
			}
		}
	}

	// Create response with additional user information
	type TicketResponse struct {
		models.Ticket
		CreatedByName  string `json:"created_by_name"`
		AssignedToName string `json:"assigned_to_name,omitempty"`
	}

	var response []TicketResponse
	for _, ticket := range tickets {
		tr := TicketResponse{
			Ticket: ticket,
		}

		// Add creator's name
		if creator, ok := userMap[ticket.CreatedBy.Hex()]; ok {
			tr.CreatedByName = creator.Name
		}

		// Add assignee's name if ticket is assigned
		if ticket.AssignedTo != nil {
			if assignee, ok := userMap[ticket.AssignedTo.Hex()]; ok {
				tr.AssignedToName = assignee.Name
			}
		}

		response = append(response, tr)
	}

	json.NewEncoder(w).Encode(response)
}

// GetTicketDetails returns detailed information about a specific ticket
func (c *TicketController) GetTicketDetails(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	ticketID, err := primitive.ObjectIDFromHex(chi.URLParam(r, "id"))
	if err != nil {
		log.Printf("Error converting ticket ID: %v\n", err)
		http.Error(w, "Invalid ticket ID", http.StatusBadRequest)
		return
	}

	// Get user information from context
	userIDStr, ok := r.Context().Value("user_id").(string)
	if !ok {
		log.Printf("Error: user_id not found in context\n")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		log.Printf("Error converting user ID: %v\n", err)
		http.Error(w, "Invalid user ID", http.StatusUnauthorized)
		return
	}
	userRole, ok := r.Context().Value("user_role").(string)
	if !ok {
		log.Printf("Error: user_role not found in context\n")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Find the ticket
	var ticket models.Ticket
	if err := config.GetCollection("tickets").FindOne(r.Context(), bson.M{"_id": ticketID}).Decode(&ticket); err != nil {
		log.Printf("Ticket not found: %v\n", err)
		http.Error(w, "Ticket not found", http.StatusNotFound)
		return
	}

	// Check access permissions based on role
	switch userRole {
	case "admin":
		// Admins can view all tickets
	case "agent":
		// Agents can view tickets they created or are assigned to
		if ticket.CreatedBy != userID && (ticket.AssignedTo == nil || *ticket.AssignedTo != userID) {
			log.Printf("Agent %s attempted to access ticket %s without permission\n", userID.Hex(), ticketID.Hex())
			http.Error(w, "Unauthorized access to ticket details", http.StatusForbidden)
			return
		}
	case "user":
		// Users can only view their own tickets
		if ticket.CreatedBy != userID {
			log.Printf("User %s attempted to access ticket %s without permission\n", userID.Hex(), ticketID.Hex())
			http.Error(w, "Unauthorized access to ticket details", http.StatusForbidden)
			return
		}
	default:
		log.Printf("Invalid user role: %s\n", userRole)
		http.Error(w, "Invalid user role", http.StatusForbidden)
		return
	}

	// Create response struct with additional user information
	type TicketResponse struct {
		models.Ticket
		CreatedByName  string `json:"created_by_name"`
		AssignedToName string `json:"assigned_to_name,omitempty"`
	}

	response := TicketResponse{
		Ticket: ticket,
	}

	// Get creator's information
	var creator models.User
	if err := config.GetCollection("users").FindOne(r.Context(), bson.M{"_id": ticket.CreatedBy}).Decode(&creator); err == nil {
		response.CreatedByName = creator.Name
	}

	// Get assignee's information if ticket is assigned
	if ticket.AssignedTo != nil {
		var assignee models.User
		if err := config.GetCollection("users").FindOne(r.Context(), bson.M{"_id": ticket.AssignedTo}).Decode(&assignee); err == nil {
			response.AssignedToName = assignee.Name
		}
	}

	log.Printf("Returning ticket details for ticket %s to user %s with role %s\n", ticketID.Hex(), userID.Hex(), userRole)
	json.NewEncoder(w).Encode(response)
}

// GetTicketComments returns all comments for a specific ticket
func (c *TicketController) GetTicketComments(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	ticketID, err := primitive.ObjectIDFromHex(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid ticket ID", http.StatusBadRequest)
		return
	}

	cursor, err := config.GetCollection("comments").Find(r.Context(), bson.M{"ticket_id": ticketID})
	if err != nil {
		http.Error(w, "Error fetching comments", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(r.Context())

	var comments []models.Comment
	if err := cursor.All(r.Context(), &comments); err != nil {
		http.Error(w, "Error decoding comments", http.StatusInternalServerError)
		return
	}

	// Fetch user information for each comment
	for i := range comments {
		var user models.User
		if err := config.GetCollection("users").FindOne(r.Context(), bson.M{"_id": comments[i].UserID}).Decode(&user); err == nil {
			comments[i].UserName = user.Name
		}
	}

	json.NewEncoder(w).Encode(comments)
}

// AddComment adds a new comment to a ticket
func (c *TicketController) AddComment(w http.ResponseWriter, r *http.Request) {
	ticketID := chi.URLParam(r, "id")
	var comment struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&comment); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get user information from context
	userIDStr := r.Context().Value("user_id").(string)
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		log.Printf("Error converting user ID: %v\n", err)
		http.Error(w, "Invalid user ID", http.StatusUnauthorized)
		return
	}

	userRole := r.Context().Value("user_role").(string)

	// First check if the ticket exists and user has access
	var ticket models.Ticket
	objID, err := primitive.ObjectIDFromHex(ticketID)
	if err != nil {
		http.Error(w, "Invalid ticket ID", http.StatusBadRequest)
		return
	}

	if err := config.GetCollection("tickets").FindOne(r.Context(), bson.M{"_id": objID}).Decode(&ticket); err != nil {
		http.Error(w, "Ticket not found", http.StatusNotFound)
		return
	}

	// Check access permissions based on role
	switch userRole {
	case "admin":
		// Admins can comment on all tickets
	case "agent":
		// Agents can comment on tickets they created or are assigned to
		if ticket.CreatedBy != userID && (ticket.AssignedTo == nil || *ticket.AssignedTo != userID) {
			log.Printf("Agent %s attempted to comment on ticket %s without permission\n", userID.Hex(), ticketID)
			http.Error(w, "Unauthorized to comment on this ticket", http.StatusForbidden)
			return
		}
	case "user":
		// Users can only comment on their own tickets
		if ticket.CreatedBy != userID {
			log.Printf("User %s attempted to comment on ticket %s without permission\n", userID.Hex(), ticketID)
			http.Error(w, "Unauthorized to comment on this ticket", http.StatusForbidden)
			return
		}
	default:
		log.Printf("Invalid user role: %s\n", userRole)
		http.Error(w, "Invalid user role", http.StatusForbidden)
		return
	}

	// Get user's name
	var user models.User
	if err := config.GetCollection("users").FindOne(r.Context(), bson.M{"_id": userID}).Decode(&user); err != nil {
		log.Printf("Error fetching user: %v\n", err)
		http.Error(w, "Error fetching user information", http.StatusInternalServerError)
		return
	}

	// Create new comment
	newComment := models.Comment{
		ID:        primitive.NewObjectID(),
		Content:   comment.Content,
		UserID:    userID,
		UserName:  user.Name,
		CreatedAt: time.Now(),
	}

	result, err := config.GetCollection("tickets").UpdateOne(
		r.Context(),
		bson.M{"_id": objID},
		bson.M{
			"$push": bson.M{"comments": newComment},
			"$set":  bson.M{"updated_at": time.Now()},
		},
	)
	if err != nil {
		http.Error(w, "Failed to add comment", http.StatusInternalServerError)
		return
	}

	if result.ModifiedCount == 0 {
		http.Error(w, "Ticket not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(newComment)
}

// UpdateTicketStatus updates the status of a ticket
func (c *TicketController) UpdateTicketStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Log the request details
	log.Printf("Received status update request for ticket: %s\n", chi.URLParam(r, "id"))
	log.Printf("Request headers: %+v\n", r.Header)

	// Read and restore request body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body: %v\n", err)
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	log.Printf("Request body: %s\n", string(bodyBytes))

	ticketID, err := primitive.ObjectIDFromHex(chi.URLParam(r, "id"))
	if err != nil {
		log.Printf("Error converting ticket ID: %v\n", err)
		http.Error(w, "Invalid ticket ID", http.StatusBadRequest)
		return
	}

	// Get user information from context
	userIDStr, ok := r.Context().Value("user_id").(string)
	if !ok {
		log.Printf("Error: user_id not found in context\n")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	log.Printf("User ID from context: %s\n", userIDStr)

	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		log.Printf("Error converting user ID: %v\n", err)
		http.Error(w, "Invalid user ID", http.StatusUnauthorized)
		return
	}

	userRole, ok := r.Context().Value("user_role").(string)
	if !ok {
		log.Printf("Error: user_role not found in context\n")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	log.Printf("User role from context: %s\n", userRole)

	var req struct {
		Status models.Status `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Error decoding request body: %v\n", err)
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		return
	}
	log.Printf("Requested status: %s\n", req.Status)

	// Validate status value
	validStatuses := map[models.Status]bool{
		models.StatusOpen:       true,
		models.StatusInProgress: true,
		models.StatusResolved:   true,
		models.StatusClosed:     true,
	}

	if !validStatuses[req.Status] {
		log.Printf("Invalid status value: %s\n", req.Status)
		http.Error(w, "Invalid status value. Must be one of: open, in_progress, resolved, closed", http.StatusBadRequest)
		return
	}

	// First check if the ticket exists and user has access
	var ticket models.Ticket
	if err := config.GetCollection("tickets").FindOne(r.Context(), bson.M{"_id": ticketID}).Decode(&ticket); err != nil {
		log.Printf("Ticket not found: %v\n", err)
		http.Error(w, "Ticket not found", http.StatusNotFound)
		return
	}

	log.Printf("Found ticket: %s, created by: %s, assigned to: %v\n",
		ticket.ID.Hex(), ticket.CreatedBy.Hex(), ticket.AssignedTo)

	// Check access permissions based on role
	switch userRole {
	case "admin":
		// Admins can update any ticket status
		log.Printf("Admin %s updating ticket %s status\n", userID.Hex(), ticketID.Hex())
	case "agent":
		// Agents can only update tickets they created or are assigned to
		if ticket.CreatedBy != userID && (ticket.AssignedTo == nil || *ticket.AssignedTo != userID) {
			log.Printf("Agent %s attempted to update ticket %s without permission\n", userID.Hex(), ticketID.Hex())
			http.Error(w, "Unauthorized to update this ticket", http.StatusForbidden)
			return
		}
		log.Printf("Agent %s updating ticket %s\n", userID.Hex(), ticketID.Hex())
	case "user":
		// Users can only update their own tickets
		if ticket.CreatedBy != userID {
			log.Printf("User %s attempted to update ticket %s without permission\n", userID.Hex(), ticketID.Hex())
			http.Error(w, "Unauthorized to update this ticket", http.StatusForbidden)
			return
		}
		log.Printf("User %s updating ticket %s\n", userID.Hex(), ticketID.Hex())
	default:
		log.Printf("Invalid user role: %s\n", userRole)
		http.Error(w, "Invalid user role", http.StatusForbidden)
		return
	}

	// Update ticket status
	update := bson.M{
		"status":     req.Status,
		"updated_at": time.Now(),
	}

	// Set closed_at if status is resolved or closed
	if req.Status == models.StatusResolved || req.Status == models.StatusClosed {
		update["closed_at"] = time.Now()
	}

	result, err := config.GetCollection("tickets").UpdateOne(
		r.Context(),
		bson.M{"_id": ticketID},
		bson.M{"$set": update},
	)
	if err != nil {
		log.Printf("Error updating ticket status: %v\n", err)
		http.Error(w, "Error updating ticket status", http.StatusInternalServerError)
		return
	}

	if result.MatchedCount == 0 {
		log.Printf("No ticket found with ID: %s\n", ticketID.Hex())
		http.Error(w, "Ticket not found", http.StatusNotFound)
		return
	}

	// Create notification for status update
	notification := models.Notification{
		UserID:    ticket.CreatedBy,
		Type:      models.NotificationTypeStatusUpdate,
		Title:     "Ticket Status Updated",
		Message:   fmt.Sprintf("Ticket #%s status has been updated to %s", ticket.ID.Hex(), req.Status),
		Read:      false,
		CreatedAt: time.Now(),
		TicketID:  ticket.ID,
	}

	_, err = config.GetCollection("notifications").InsertOne(r.Context(), notification)
	if err != nil {
		log.Printf("Error creating notification: %v\n", err)
		// Don't return error here, as the status update was successful
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Ticket status updated successfully"})
}

// Create creates a new ticket
func (c *TicketController) Create(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Get user ID from context and convert from string to ObjectID
	userIDStr := r.Context().Value("user_id").(string)
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		log.Printf("Error converting user ID: %v\n", err)
		http.Error(w, "Invalid user ID", http.StatusInternalServerError)
		return
	}

	var req CreateTicketRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Error decoding request: %v\n", err)
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Title == "" || req.Description == "" {
		http.Error(w, "Title and description are required", http.StatusBadRequest)
		return
	}

	// Create ticket
	now := time.Now()
	ticket := models.Ticket{
		ID:          primitive.NewObjectID(),
		Title:       req.Title,
		Description: req.Description,
		Category:    req.Category,
		Priority:    req.Priority,
		Status:      models.StatusOpen,
		CreatedBy:   userID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	log.Printf("Creating ticket: %+v\n", ticket)

	// Save ticket to database
	if _, err := config.GetCollection("tickets").InsertOne(r.Context(), ticket); err != nil {
		log.Printf("Error creating ticket: %v\n", err)
		http.Error(w, "Error creating ticket", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(ticket)
}

// AssignTicket assigns a ticket to an agent
func (c *TicketController) AssignTicket(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Only agents and admins can assign tickets
	userRole := r.Context().Value("user_role").(string)
	if userRole != "agent" && userRole != "admin" {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	// Get user ID from context
	userIDStr := r.Context().Value("user_id").(string)
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		log.Printf("Error converting user ID: %v\n", err)
		http.Error(w, "Invalid user ID", http.StatusInternalServerError)
		return
	}

	ticketID, err := primitive.ObjectIDFromHex(chi.URLParam(r, "id"))
	if err != nil {
		log.Printf("Error converting ticket ID: %v\n", err)
		http.Error(w, "Invalid ticket ID", http.StatusBadRequest)
		return
	}

	var req struct {
		AgentID string `json:"agent_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Error decoding request: %v\n", err)
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		return
	}

	agentID, err := primitive.ObjectIDFromHex(req.AgentID)
	if err != nil {
		log.Printf("Error converting agent ID: %v\n", err)
		http.Error(w, "Invalid agent ID", http.StatusBadRequest)
		return
	}

	// Verify agent exists and is an agent/admin
	var agent models.User
	if err := config.GetCollection("users").FindOne(r.Context(), bson.M{
		"_id":  agentID,
		"role": bson.M{"$in": []string{"agent", "admin"}},
	}).Decode(&agent); err != nil {
		log.Printf("Error finding agent: %v\n", err)
		http.Error(w, "Invalid agent ID", http.StatusBadRequest)
		return
	}

	// First check if the ticket exists
	var ticket models.Ticket
	if err := config.GetCollection("tickets").FindOne(r.Context(), bson.M{"_id": ticketID}).Decode(&ticket); err != nil {
		log.Printf("Error finding ticket: %v\n", err)
		http.Error(w, "Ticket not found", http.StatusNotFound)
		return
	}

	update := bson.M{
		"$set": bson.M{
			"assigned_to": agentID,
			"status":      "in_progress", // Update status when assigned
			"updated_at":  time.Now(),
		},
	}

	result, err := config.GetCollection("tickets").UpdateOne(
		r.Context(),
		bson.M{"_id": ticketID},
		update,
	)
	if err != nil {
		log.Printf("Error updating ticket: %v\n", err)
		http.Error(w, "Error updating ticket", http.StatusInternalServerError)
		return
	}

	if result.MatchedCount == 0 {
		log.Printf("No ticket found with ID: %s\n", ticketID.Hex())
		http.Error(w, "Ticket not found", http.StatusNotFound)
		return
	}

	// Add a system comment about the assignment
	comment := models.Comment{
		ID:        primitive.NewObjectID(),
		TicketID:  ticketID,
		UserID:    userID,
		Content:   fmt.Sprintf("Ticket assigned to %s", agent.Name),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if _, err := config.GetCollection("comments").InsertOne(r.Context(), comment); err != nil {
		log.Printf("Error adding assignment comment: %v\n", err)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Ticket assigned successfully"})
}

// UpdateTicketPriority updates the priority of a ticket
func (c *TicketController) UpdateTicketPriority(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Only agents and admins can update priority
	userRole := r.Context().Value("user_role").(string)
	if userRole != "agent" && userRole != "admin" {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	ticketID, err := primitive.ObjectIDFromHex(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid ticket ID", http.StatusBadRequest)
		return
	}

	var req struct {
		Priority models.Priority `json:"priority"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		return
	}

	update := bson.M{
		"$set": bson.M{
			"priority":   req.Priority,
			"updated_at": time.Now(),
		},
	}

	result, err := config.GetCollection("tickets").UpdateOne(
		r.Context(),
		bson.M{"_id": ticketID},
		update,
	)
	if err != nil {
		http.Error(w, "Error updating ticket", http.StatusInternalServerError)
		return
	}

	if result.MatchedCount == 0 {
		http.Error(w, "Ticket not found", http.StatusNotFound)
		return
	}

	// Add a system comment about the priority change
	comment := models.Comment{
		ID:        primitive.NewObjectID(),
		TicketID:  ticketID,
		UserID:    r.Context().Value("user_id").(primitive.ObjectID),
		Content:   fmt.Sprintf("Ticket priority updated to %s", req.Priority),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if _, err := config.GetCollection("comments").InsertOne(r.Context(), comment); err != nil {
		// Log error but don't return it to client
		fmt.Printf("Error adding priority update comment: %v\n", err)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Ticket priority updated successfully"})
}

func (tc *TicketController) DeleteAttachment(w http.ResponseWriter, r *http.Request) {
	// ... existing code ...
}

func InitControllers(db *mongo.Database) {
	TicketAPI = TicketController{db: db}
}
