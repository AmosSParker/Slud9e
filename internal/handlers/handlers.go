package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/AmosSParker/Slud9e/internal/config"
	"github.com/AmosSParker/Slud9e/internal/db"
	"github.com/dgrijalva/jwt-go"
)

// Handlers represents the set of HTTP handlers for the C2 server.
type Handlers struct {
	DB     *db.DBConnection
	Config *config.Config
}

// NewHandlers initializes and returns a new instance of Handlers.
func NewHandlers(db *db.DBConnection, cfg *config.Config) *Handlers {
	return &Handlers{
		DB:     db,
		Config: cfg,
	}
}

func (h *Handlers) StaticHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Specify the directory where static files are located
		staticDir := "./static"

		// Serve static files
		http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir))).ServeHTTP(w, r)
	}
}

// APIHandler handles requests to the API endpoints.
func (h *Handlers) APIHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if r.URL.Path == "/api/data" {
			h.getDataHandler(w, r)
			return
		}
	case http.MethodPost:
		if r.URL.Path == "/api/data" {
			h.createDataHandler(w, r)
			return
		}
	}
	http.NotFound(w, r)
}

// getDataHandler handles GET requests to retrieve data.
func (h *Handlers) getDataHandler(w http.ResponseWriter, r *http.Request) {
	data := []string{"data1", "data2", "data3"}
	jsonData, err := json.Marshal(data)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", h.Config.ResponseContentType)
	w.WriteHeader(http.StatusOK)
	w.Write(jsonData)
}

// createDataHandler handles POST requests to create data.
func (h *Handlers) createDataHandler(w http.ResponseWriter, r *http.Request) {
	var data interface{}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if err := h.DB.CreateData(data); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// ErrorHandler handles HTTP errors and logs them.
func (h *Handlers) ErrorHandler(w http.ResponseWriter, err error, statusCode int) {
	w.WriteHeader(statusCode)
	fmt.Fprintf(w, "Error: %s", err.Error())
}

// MetricsHandler handles requests for server metrics.
func (h *Handlers) MetricsHandler(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(startTime).String()
	metrics := map[string]string{
		"uptime": uptime,
		"status": "ok",
	}
	respondWithJSON(w, metrics)
}

// AuthMiddleware provides JWT-based authentication middleware.
func (h *Handlers) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header is required", http.StatusUnauthorized)
			return
		}

		splitToken := strings.Split(authHeader, "Bearer ")
		if len(splitToken) != 2 {
			http.Error(w, "Malformed token", http.StatusUnauthorized)
			return
		}

		tokenString := splitToken[1]
		claims := &jwt.StandardClaims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(h.Config.JWTSecret), nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Check if the token is blacklisted
		isBlacklisted, err := h.DB.IsTokenBlacklisted(tokenString)
		if err != nil {
			http.Error(w, "Error checking token blacklist", http.StatusInternalServerError)
			return
		}

		if isBlacklisted {
			http.Error(w, "Token is blacklisted", http.StatusUnauthorized)
			return
		}

		// Token is valid and not blacklisted, proceed with the request
		ctx := context.WithValue(r.Context(), "userID", claims.Subject)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GenerateJWT generates a JWT token for the given user ID.
func (h *Handlers) GenerateJWT(userID string) (string, error) {
	expirationTime := time.Now().Add(h.Config.TokenExpirationTime)
	claims := &jwt.StandardClaims{
		ExpiresAt: expirationTime.Unix(),
		Subject:   userID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(h.Config.JWTSecret))

	return tokenString, err
}

// LoginHandler handles user login requests.
func (h *Handlers) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var userCredentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&userCredentials); err != nil {
		http.Error(w, "Decoding credentials failed", http.StatusBadRequest)
		return
	}

	userID, authErr := h.DB.AuthenticateUser(userCredentials.Username, userCredentials.Password)
	if authErr != nil {
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	token, err := h.GenerateJWT(userID)
	if err != nil {
		http.Error(w, "Error generating JWT", http.StatusInternalServerError)
		return
	}

	respondWithJSON(w, map[string]string{"token": token, "userID": userID})
}

// LogoutHandler handles user logout requests.
func (h *Handlers) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")[7:] // Assuming "Bearer " is stripped
	if tokenString == "" {
		http.Error(w, "Token is required", http.StatusBadRequest)
		return
	}

	claims := &jwt.StandardClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(h.Config.JWTSecret), nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	}

	expiration := time.Unix(claims.ExpiresAt, 0)
	remainingTime := expiration.Sub(time.Now())

	// Assuming `AddTokenToBlacklist` is a method to store the token in Redis with the remaining TTL
	if err := h.DB.AddTokenToBlacklist(tokenString, remainingTime); err != nil {
		http.Error(w, "Error adding token to blacklist", http.StatusInternalServerError)
		return
	}

	respondWithJSON(w, map[string]string{"status": "successfully logged out"})
}

// respondWithJSON writes JSON response to the HTTP response writer.
func respondWithJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
