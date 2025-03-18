package controllers

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/choukaryasandeep/support-ticket-system/config"
	"github.com/choukaryasandeep/support-ticket-system/middleware"
	"github.com/choukaryasandeep/support-ticket-system/models"
	"github.com/go-chi/chi"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type AuthAPIController struct{}

var AuthAPI = &AuthAPIController{}

type AuthRequest struct {
	Name     string `json:"name,omitempty"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role,omitempty"`
}

type AuthResponse struct {
	Error string `json:"error,omitempty"`
}

// ValidateRole checks if the provided role is valid
func (c *AuthAPIController) ValidateRole(role string) bool {
	validRoles := map[string]bool{
		"admin": true,
		"agent": true,
		"user":  true,
	}
	return validRoles[role]
}

func (c *AuthAPIController) Register(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Error decoding request body: %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(AuthResponse{Error: "Invalid request data"})
		return
	}

	log.Printf("Received registration request for email: %s, role: %s\n", req.Email, req.Role)

	if req.Name == "" || req.Email == "" || req.Password == "" || req.Role == "" {
		log.Printf("Missing required fields - name: %v, email: %v, password: %v, role: %v\n",
			req.Name != "", req.Email != "", req.Password != "", req.Role != "")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(AuthResponse{Error: "All fields are required"})
		return
	}

	// Validate role
	if !c.ValidateRole(req.Role) {
		log.Printf("Invalid role selected: %s\n", req.Role)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(AuthResponse{Error: "Invalid role selected"})
		return
	}

	// Check if admin exists when registering as admin
	if req.Role == "admin" {
		var existingAdmin models.User
		if err := config.GetCollection("users").FindOne(r.Context(), bson.M{"role": "admin"}).Decode(&existingAdmin); err == nil {
			log.Println("Attempt to register as admin when admin already exists")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(AuthResponse{Error: "Administrator already exists"})
			return
		} else {
			log.Printf("Admin check error (expected if no admin exists): %v\n", err)
		}
	}

	// Check if email already exists
	var existingUser models.User
	if err := config.GetCollection("users").FindOne(r.Context(), bson.M{"email": req.Email}).Decode(&existingUser); err == nil {
		log.Printf("Attempt to register with existing email: %s\n", req.Email)
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(AuthResponse{Error: "Email already registered"})
		return
	} else {
		log.Printf("Email check error (expected if email doesn't exist): %v\n", err)
	}

	hashedPassword, err := middleware.HashPassword(req.Password)
	if err != nil {
		log.Printf("Error hashing password: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(AuthResponse{Error: "Error processing registration"})
		return
	}

	now := time.Now()
	user := models.User{
		ID:        primitive.NewObjectID(),
		Name:      req.Name,
		Email:     req.Email,
		Password:  hashedPassword,
		Role:      req.Role,
		CreatedAt: now,
		UpdatedAt: now,
	}

	log.Printf("Attempting to insert user with email: %s and role: %s\n", user.Email, user.Role)
	if _, err := config.GetCollection("users").InsertOne(r.Context(), user); err != nil {
		log.Printf("Error inserting user into database: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(AuthResponse{Error: "Error creating user"})
		return
	}
	log.Println("User successfully inserted into database")

	token, err := middleware.GenerateJWT(user)
	if err != nil {
		log.Printf("Error generating JWT token: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(AuthResponse{Error: "Error generating token"})
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		Path:     "/",
		MaxAge:   3600 * 24,
		HttpOnly: true,
	})

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(struct {
		Message string `json:"message"`
		Role    string `json:"role"`
	}{
		Message: "Registration successful",
		Role:    user.Role,
	})
	log.Printf("Registration successful for user: %s with role: %s\n", user.Email, user.Role)
}

func (c *AuthAPIController) Login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Error decoding login request: %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(AuthResponse{Error: "Invalid request data"})
		return
	}

	log.Printf("Login attempt for email: %s\n", req.Email)

	// Try to find the user
	var user models.User
	err := config.GetCollection("users").FindOne(r.Context(), bson.M{"email": req.Email}).Decode(&user)
	if err != nil {
		log.Printf("Database error or user not found: %v\n", err)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(AuthResponse{Error: "Invalid email or password"})
		return
	}

	log.Printf("Found user with ID: %s and role: %s\n", user.ID.Hex(), user.Role)

	// Check password
	if !middleware.CheckPasswordHash(req.Password, user.Password) {
		log.Printf("Invalid password for user: %s\n", req.Email)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(AuthResponse{Error: "Invalid email or password"})
		return
	}

	log.Printf("Password verified for user: %s\n", req.Email)

	// Generate JWT token
	token, err := middleware.GenerateJWT(user)
	if err != nil {
		log.Printf("Error generating JWT token: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(AuthResponse{Error: "Error generating token"})
		return
	}

	log.Printf("Generated JWT token for user: %s\n", req.Email)

	// Set cookie with appropriate attributes
	cookie := &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		Path:     "/",
		MaxAge:   3600 * 24, // 24 hours
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   false, // Set to true if using HTTPS
	}
	http.SetCookie(w, cookie)
	log.Printf("Set auth_token cookie for user: %s\n", req.Email)

	// Return success response with user info
	response := struct {
		Message string `json:"message"`
		Role    string `json:"role"`
		User    struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Email string `json:"email"`
			Role  string `json:"role"`
		} `json:"user"`
	}{
		Message: "Login successful",
		Role:    user.Role,
		User: struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Email string `json:"email"`
			Role  string `json:"role"`
		}{
			ID:    user.ID.Hex(),
			Name:  user.Name,
			Email: user.Email,
			Role:  user.Role,
		},
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v\n", err)
	} else {
		log.Printf("Login successful for user: %s with role: %s\n", user.Email, user.Role)
	}
}

func (c *AuthAPIController) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(struct {
		Message string `json:"message"`
	}{
		Message: "Logged out successfully",
	})
}

func (c *AuthAPIController) CheckAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Get user ID from context
	userIDStr := r.Context().Value("user_id").(string)
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusInternalServerError)
		return
	}

	// Find user in database
	var user models.User
	err = config.GetCollection("users").FindOne(r.Context(), bson.M{"_id": userID}).Decode(&user)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Return user info
	json.NewEncoder(w).Encode(struct {
		Message string `json:"message"`
		User    struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Email string `json:"email"`
			Role  string `json:"role"`
		} `json:"user"`
	}{
		Message: "Authenticated",
		User: struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Email string `json:"email"`
			Role  string `json:"role"`
		}{
			ID:    user.ID.Hex(),
			Name:  user.Name,
			Email: user.Email,
			Role:  user.Role,
		},
	})
}

// GetUser returns the current user's information
func (c *AuthAPIController) GetUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Get user ID from context
	userIDStr := r.Context().Value("user_id").(string)
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusInternalServerError)
		return
	}

	// Find user in database
	var user models.User
	err = config.GetCollection("users").FindOne(r.Context(), bson.M{"_id": userID}).Decode(&user)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Return user info without sensitive data
	json.NewEncoder(w).Encode(struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
		Role  string `json:"role"`
	}{
		ID:    user.ID.Hex(),
		Name:  user.Name,
		Email: user.Email,
		Role:  user.Role,
	})
}

// GetAgents returns all users with the role "agent"
func (c *AuthAPIController) GetAgents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Only admins can fetch agent list
	userRole := r.Context().Value("user_role").(string)
	if userRole != "admin" {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	// Find all users with role "agent"
	cursor, err := config.GetCollection("users").Find(r.Context(), bson.M{"role": "agent"})
	if err != nil {
		log.Printf("Error fetching agents: %v\n", err)
		http.Error(w, "Error fetching agents", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(r.Context())

	var agents []struct {
		ID    string `json:"id" bson:"_id"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}

	if err := cursor.All(r.Context(), &agents); err != nil {
		log.Printf("Error decoding agents: %v\n", err)
		http.Error(w, "Error decoding agents", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(agents)
}

// GetUserByID returns a user's information by their ID
func (c *AuthAPIController) GetUserByID(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Get user ID from URL parameter
	userIDStr := chi.URLParam(r, "id")
	log.Printf("GetUserByID: Received ID: %s\n", userIDStr)

	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		log.Printf("GetUserByID: Error converting ID to ObjectID: %v\n", err)
		http.Error(w, "Invalid user ID format", http.StatusBadRequest)
		return
	}

	// Find user in database
	var user models.User
	err = config.GetCollection("users").FindOne(r.Context(), bson.M{"_id": userID}).Decode(&user)
	if err != nil {
		log.Printf("GetUserByID: Error finding user: %v\n", err)
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	log.Printf("GetUserByID: Found user: %s (%s)\n", user.Name, user.ID.Hex())

	// Return user info without sensitive data
	json.NewEncoder(w).Encode(struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
		Role  string `json:"role"`
	}{
		ID:    user.ID.Hex(),
		Name:  user.Name,
		Email: user.Email,
		Role:  user.Role,
	})
}
