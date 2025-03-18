package controllers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/choukaryasandeep/support-ticket-system/config"
	"github.com/choukaryasandeep/support-ticket-system/models"
	"github.com/go-chi/chi/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type TicketController struct{}

var TicketAPI = &TicketController{}

type CreateTicketRequest struct {
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Category    models.Category `json:"category"`
	Priority    models.Priority `json:"priority"`
}

type CommentRequest struct {
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
	userIDStr := r.Context().Value("user_id").(string)
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		log.Printf("Error converting user ID: %v\n", err)
		http.Error(w, "Invalid user ID", http.StatusInternalServerError)
		return
	}
	userRole := r.Context().Value("user_role").(string)

	// Only allow admin users to view ticket details
	if userRole != "admin" {
		log.Printf("User %s with role %s attempted to access ticket details\n", userID.Hex(), userRole)
		http.Error(w, "Unauthorized access to ticket details", http.StatusForbidden)
		return
	}

	// Find the ticket
	var ticket models.Ticket
	if err := config.GetCollection("tickets").FindOne(r.Context(), bson.M{"_id": ticketID}).Decode(&ticket); err != nil {
		log.Printf("Ticket not found: %v\n", err)
		http.Error(w, "Ticket not found", http.StatusNotFound)
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

	log.Printf("Returning ticket details for ticket %s to admin user %s\n", ticketID.Hex(), userID.Hex())
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
	w.Header().Set("Content-Type", "application/json")

	ticketID, err := primitive.ObjectIDFromHex(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid ticket ID", http.StatusBadRequest)
		return
	}

	var req CommentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		return
	}

	if req.Content == "" {
		http.Error(w, "Comment content is required", http.StatusBadRequest)
		return
	}

	userID := r.Context().Value("user_id").(primitive.ObjectID)
	now := time.Now()

	comment := models.Comment{
		ID:        primitive.NewObjectID(),
		TicketID:  ticketID,
		UserID:    userID,
		Content:   req.Content,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if _, err := config.GetCollection("comments").InsertOne(r.Context(), comment); err != nil {
		http.Error(w, "Error creating comment", http.StatusInternalServerError)
		return
	}

	// Update ticket's updated_at timestamp
	_, err = config.GetCollection("tickets").UpdateOne(
		r.Context(),
		bson.M{"_id": ticketID},
		bson.M{"$set": bson.M{"updated_at": now}},
	)
	if err != nil {
		// Log the error but don't return it to the client
		fmt.Printf("Error updating ticket timestamp: %v\n", err)
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(comment)
}

// UpdateTicketStatus updates the status of a ticket
func (c *TicketController) UpdateTicketStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	ticketID, err := primitive.ObjectIDFromHex(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid ticket ID", http.StatusBadRequest)
		return
	}

	var req struct {
		Status models.Status `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		return
	}

	update := bson.M{
		"$set": bson.M{
			"status":     req.Status,
			"updated_at": time.Now(),
		},
	}

	// If status is "closed", set closed_at timestamp
	if req.Status == models.StatusClosed {
		now := time.Now()
		update["$set"].(bson.M)["closed_at"] = now
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

func (c *TicketController) saveAttachment(fileHeader *multipart.FileHeader) (models.Attachment, error) {
	// Validate file size
	if fileHeader.Size > maxFileSize {
		return models.Attachment{}, fmt.Errorf("file size exceeds maximum limit of 10 MB")
	}

	// Open uploaded file
	file, err := fileHeader.Open()
	if err != nil {
		return models.Attachment{}, err
	}
	defer file.Close()

	// Create unique filename
	filename := primitive.NewObjectID().Hex() + filepath.Ext(fileHeader.Filename)
	filepath := filepath.Join(uploadDir, filename)

	// Create destination file
	dst, err := os.Create(filepath)
	if err != nil {
		return models.Attachment{}, err
	}
	defer dst.Close()

	// Copy file contents
	if _, err := io.Copy(dst, file); err != nil {
		return models.Attachment{}, err
	}

	// Create attachment record
	attachment := models.Attachment{
		ID:         primitive.NewObjectID(),
		FileName:   fileHeader.Filename,
		FileType:   fileHeader.Header.Get("Content-Type"),
		FilePath:   filepath,
		FileSize:   fileHeader.Size,
		UploadedAt: time.Now(),
	}

	return attachment, nil
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
