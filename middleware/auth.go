package middleware

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/choukaryasandeep/support-ticket-system/models"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte("xJ8f9K!mP@3zT$yV6qB&dW#nG2rL*oC1") // In production, use environment variable

type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// GenerateJWT generates a JWT token for a user
func GenerateJWT(user models.User) (string, error) {
	claims := &Claims{
		UserID: user.ID.Hex(),
		Email:  user.Email,
		Role:   user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

// HashPassword hashes a password using bcrypt
// it is used while register the user 
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// CheckPasswordHash compares a password with a hash
// it is used while login the user
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// handleUnauthorized handles unauthorized requests
func handleUnauthorized(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	} else {
		http.Redirect(w, r, "/login?redirected=true", http.StatusSeeOther)
	}
}

// clearAuthCookie clears the auth cookie
func clearAuthCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// AuthMiddleware checks for valid JWT token
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("AuthMiddleware: Processing request for path: %s\n", r.URL.Path)

		// Get token from cookie
		cookie, err := r.Cookie("auth_token")
		if err != nil {
			log.Printf("AuthMiddleware: No auth_token cookie found: %v\n", err)
			handleUnauthorized(w, r)
			return
		}

		tokenStr := cookie.Value
		if tokenStr == "" {
			log.Printf("AuthMiddleware: Empty auth_token cookie\n")
			handleUnauthorized(w, r)
			return
		}

		// Parse token
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return jwtKey, nil
		})

		if err != nil {
			log.Printf("AuthMiddleware: Error parsing token: %v\n", err)
			clearAuthCookie(w)
			handleUnauthorized(w, r)
			return
		}

		if !token.Valid {
			log.Printf("AuthMiddleware: Invalid token\n")
			clearAuthCookie(w)
			handleUnauthorized(w, r)
			return
		}

		// Check token expiration
		if time.Now().After(claims.ExpiresAt.Time) {
			log.Printf("AuthMiddleware: Token expired\n")
			clearAuthCookie(w)
			handleUnauthorized(w, r)
			return
		}

		log.Printf("AuthMiddleware: Valid token for user ID: %s, role: %s\n", claims.UserID, claims.Role)

		// Add claims to context
		ctx := context.WithValue(r.Context(), "user_id", claims.UserID)
		ctx = context.WithValue(ctx, "email", claims.Email)
		ctx = context.WithValue(ctx, "user_role", claims.Role)

		// Verify the role is set correctly
		roleFromCtx := ctx.Value("user_role").(string)
		log.Printf("AuthMiddleware: Role set in context: %s for path: %s\n", roleFromCtx, r.URL.Path)

		// Call next handler with updated context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
