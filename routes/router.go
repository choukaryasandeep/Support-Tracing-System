package routes

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/choukaryasandeep/support-ticket-system/config"
	"github.com/choukaryasandeep/support-ticket-system/controllers"
	"github.com/choukaryasandeep/support-ticket-system/middleware"
	"github.com/choukaryasandeep/support-ticket-system/models"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// serveStaticFile serves a static HTML file
func serveStaticFile(w http.ResponseWriter, r *http.Request, filename string) {
	http.ServeFile(w, r, filename)
}

func SetupRouter() http.Handler {
	r := chi.NewRouter()

	// Global middleware
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)

	// Serve static files without authentication
	fileServer := http.FileServer(http.Dir("static"))
	r.Handle("/static/*", http.StripPrefix("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only allow specific file types and paths
		allowedPaths := map[string]bool{
			"css/":          true,
			"js/":           true,
			"images/":       true,
			"login.html":    true,
			"register.html": true,
		}

		// Check if path is allowed
		isAllowed := false
		for path := range allowedPaths {
			if strings.HasPrefix(r.URL.Path, path) {
				isAllowed = true
				break
			}
		}

		if !isAllowed {
			log.Printf("Blocked unauthorized access to file: %s\n", r.URL.Path)
			http.Error(w, "Unauthorized", http.StatusForbidden)
			return
		}

		fileServer.ServeHTTP(w, r)
	})))
	r.Handle("/uploads/*", http.StripPrefix("/uploads/", http.FileServer(http.Dir("uploads"))))

	// Public routes (no auth required)
	r.Group(func(r chi.Router) {
		// Redirect root to login
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/login", http.StatusFound)
		})

		// Auth pages
		r.Get("/login", func(w http.ResponseWriter, r *http.Request) {
			// Check if user is already logged in
			if cookie, err := r.Cookie("auth_token"); err == nil && cookie.Value != "" {
				http.Redirect(w, r, "/dashboard", http.StatusFound)
				return
			}
			serveStaticFile(w, r, "static/login.html")
		})

		r.Get("/register", func(w http.ResponseWriter, r *http.Request) {
			// Check if user is already logged in
			if cookie, err := r.Cookie("auth_token"); err == nil && cookie.Value != "" {
				http.Redirect(w, r, "/dashboard", http.StatusFound)
				return
			}
			serveStaticFile(w, r, "static/register.html")
		})

		// Auth API endpoints
		r.Post("/api/auth/register", controllers.AuthAPI.Register)
		r.Post("/api/auth/login", controllers.AuthAPI.Login)
	})

	// Protected routes (auth required)
	r.Group(func(r chi.Router) {
		r.Use(middleware.AuthMiddleware)

		// Auth endpoints that require authentication
		r.Post("/api/auth/logout", controllers.AuthAPI.Logout)
		r.Get("/api/auth/check", controllers.AuthAPI.CheckAuth)
		r.Get("/api/auth/user", controllers.AuthAPI.GetUser)
		r.Get("/api/auth/user/{id}", controllers.AuthAPI.GetUserByID)
		r.Get("/api/users/agents", controllers.AuthAPI.GetAgents)

		// Dashboard routes based on role
		r.Get("/dashboard", func(w http.ResponseWriter, r *http.Request) {
			userRole := r.Context().Value("user_role").(string)
			userID := r.Context().Value("user_id").(string)
			userEmail := r.Context().Value("email").(string)

			log.Printf("Dashboard request - Initial role from context: %s, User ID: %s, Email: %s\n", userRole, userID, userEmail)

			// Double check user role from database
			var user models.User
			userObjID, err := primitive.ObjectIDFromHex(userID)
			if err != nil {
				log.Printf("Error converting user ID: %v\n", err)
				http.Error(w, "Invalid user ID", http.StatusBadRequest)
				return
			}

			err = config.GetCollection("users").FindOne(r.Context(), bson.M{"_id": userObjID}).Decode(&user)
			if err != nil {
				log.Printf("Error fetching user from database: %v\n", err)
				http.Error(w, "User not found", http.StatusNotFound)
				return
			}

			log.Printf("User data from database - ID: %s, Email: %s, Role: %s\n", user.ID.Hex(), user.Email, user.Role)
			log.Printf("Role comparison - Context: %s, Database: %s\n", userRole, user.Role)

			// Validate role
			if !controllers.AuthAPI.ValidateRole(user.Role) {
				log.Printf("Invalid role in database: %s\n", user.Role)
				http.Error(w, "Invalid user role", http.StatusForbidden)
				return
			}

			// If roles don't match, clear auth and redirect to login
			if user.Role != userRole {
				log.Printf("Role mismatch detected - DB: %s, JWT: %s\n", user.Role, userRole)
				// Clear auth cookie
				http.SetCookie(w, &http.Cookie{
					Name:     "auth_token",
					Value:    "",
					Path:     "/",
					MaxAge:   -1,
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
				})
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			// Use the role from database for dashboard selection
			var dashboardFile string
			currentDir, err := os.Getwd()
			if err != nil {
				log.Printf("Error getting current directory: %v\n", err)
				http.Error(w, "Server error", http.StatusInternalServerError)
				return
			}

			log.Printf("Current directory: %s\n", currentDir)

			// Force role check and dashboard selection
			dashboardPath := ""
			switch user.Role {
			case "admin":
				dashboardPath = "admin-dashboard.html"
			case "agent":
				dashboardPath = "agent-dashboard.html"
			case "user":
				dashboardPath = "user-dashboard.html"
			default:
				log.Printf("Invalid role %s for user %s\n", user.Role, userEmail)
				http.Error(w, "Invalid user role", http.StatusForbidden)
				return
			}

			// Construct full path
			dashboardFile = filepath.Join(currentDir, "static", dashboardPath)
			log.Printf("Selected dashboard file: %s for user: %s with role: %s\n", dashboardFile, userEmail, user.Role)

			// Verify file exists
			fileInfo, err := os.Stat(dashboardFile)
			if err != nil {
				if os.IsNotExist(err) {
					log.Printf("Dashboard file not found: %s\n", dashboardFile)
					http.Error(w, "Dashboard file not found", http.StatusNotFound)
				} else {
					log.Printf("Error accessing dashboard file: %v\n", err)
					http.Error(w, "Error accessing dashboard file", http.StatusInternalServerError)
				}
				return
			}

			log.Printf("Dashboard file exists: %s, size: %d bytes\n", dashboardFile, fileInfo.Size())

			// Set strict headers
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-Content-Type-Options", "nosniff")

			// Read file content
			content, err := os.ReadFile(dashboardFile)
			if err != nil {
				log.Printf("Error reading dashboard file: %v\n", err)
				http.Error(w, "Error reading dashboard file", http.StatusInternalServerError)
				return
			}

			// Write response
			if _, err := w.Write(content); err != nil {
				log.Printf("Error writing response: %v\n", err)
				return
			}

			log.Printf("Successfully served dashboard file: %s for role: %s\n", dashboardFile, user.Role)
		})

		// Tickets UI routes
		r.Get("/tickets", func(w http.ResponseWriter, r *http.Request) {
			serveStaticFile(w, r, "static/tickets.html")
		})
		r.Get("/tickets/create", func(w http.ResponseWriter, r *http.Request) {
			serveStaticFile(w, r, "static/create-ticket.html")
		})
		r.Get("/tickets/{id}", func(w http.ResponseWriter, r *http.Request) {
			serveStaticFile(w, r, "static/ticket-details.html")
		})

		// API routes for tickets
		r.Route("/api/tickets", func(r chi.Router) {
			r.Get("/", controllers.TicketAPI.GetUserTickets)
			r.Post("/", controllers.TicketAPI.Create)
			r.Get("/{id}", controllers.TicketAPI.GetTicketDetails)
			r.Put("/{id}/status", controllers.TicketAPI.UpdateTicketStatus)
			r.Put("/{id}/assign", controllers.TicketAPI.AssignTicket)
			r.Put("/{id}/priority", controllers.TicketAPI.UpdateTicketPriority)
			r.Get("/{id}/comments", controllers.TicketAPI.GetTicketComments)
			r.Post("/{id}/comments", controllers.TicketAPI.AddComment)
		})

		// API routes for notifications
		r.Route("/api/notifications", func(r chi.Router) {
			r.Get("/", controllers.NotificationAPI.GetUserNotifications)
			r.Put("/{id}/read", controllers.NotificationAPI.MarkNotificationAsRead)
			r.Put("/read-all", controllers.NotificationAPI.MarkAllNotificationsAsRead)
		})

		// Profile route - redirect to dashboard
		r.Get("/profile", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
		})
	})

	return r
}
