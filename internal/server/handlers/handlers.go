package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/AmosSParker/Slud9e/internal/server/config"
	"github.com/AmosSParker/Slud9e/internal/server/db"
	"github.com/AmosSParker/Slud9e/internal/utils"
	"github.com/dgrijalva/jwt-go"
	"github.com/golang-jwt/jwt/v4"
)

var startTime = time.Now()

type Handlers struct {
	DB     *db.DBConnection
	Config *config.Config
}

type Claims struct {
	jwt.StandardClaims
	// Add custom fields here, e.g., UserID
	UserID string `json:"userId"`
}

func NewHandlers(db *db.DBConnection, cfg *config.Config) *Handlers {
	return &Handlers{
		DB:     db,
		Config: cfg,
	}
}

func (h *Handlers) StaticHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var root string
		if strings.HasPrefix(r.URL.Path, "/static/js/") {
			root = filepath.Join("internal", "web", "static", "js")
			http.ServeFile(w, r, filepath.Join(root, filepath.Clean(strings.TrimPrefix(r.URL.Path, "/static/js/"))))
		} else {
			root = filepath.Join("internal", "web", "static", "templates")
			if r.URL.Path == "/" {
				http.ServeFile(w, r, filepath.Join(root, "index.html"))
				return
			}
			http.ServeFile(w, r, filepath.Join(root, filepath.Clean(r.URL.Path)))
		}
	}
}

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

func (h *Handlers) getDataHandler(w http.ResponseWriter, r *http.Request) {
	data := []string{"data1", "data2", "data3"}
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Println("Error marshalling data:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonData)
}

func (h *Handlers) createDataHandler(w http.ResponseWriter, r *http.Request) {
	var data interface{}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		h.ErrorHandler(w, fmt.Errorf("decoding data: %w", err), http.StatusBadRequest)
		return
	}
	if err := h.DB.CreateData(data); err != nil {
		h.ErrorHandler(w, fmt.Errorf("creating data: %w", err), http.StatusInternalServerError)
		return
	}
	respondWithJSON(w, map[string]string{"status": "success"})
}

func (h *Handlers) ErrorHandler(w http.ResponseWriter, err error, statusCode int) {
	if statusCode >= 500 {
		utils.LogError("API server error", err, map[string]interface{}{"status": statusCode})
	} else {
		utils.LogInfo("API client error", map[string]interface{}{"error": err.Error(), "status": statusCode})
	}
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func (h *Handlers) MetricsHandler(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(startTime).String()
	metrics := map[string]string{
		"uptime": uptime,
		"status": "ok",
	}
	respondWithJSON(w, metrics)
}

func (h *Handlers) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			h.ErrorHandler(w, fmt.Errorf("authorization header is required"), http.StatusUnauthorized)
			return
		}

		splitToken := strings.Split(authHeader, "Bearer ")
		if len(splitToken) != 2 {
			h.ErrorHandler(w, fmt.Errorf("malformed token"), http.StatusUnauthorized)
			return
		}

		tokenString := splitToken[1]
		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(h.Config.JWTSecret), nil
		})

		if err != nil || !token.Valid {
			h.ErrorHandler(w, fmt.Errorf("invalid token: %w", err), http.StatusUnauthorized)
			return
		}

		// Check if the token is blacklisted
		isBlacklisted, err := h.DB.IsTokenBlacklisted(tokenString)
		if err != nil {
			// Handle error checking blacklist
			h.ErrorHandler(w, fmt.Errorf("error checking token blacklist: %w", err), http.StatusInternalServerError)
			return
		}

		if isBlacklisted {
			// Token is blacklisted, reject the request
			h.ErrorHandler(w, fmt.Errorf("token is blacklisted"), http.StatusUnauthorized)
			return
		}

		// Token is valid and not blacklisted, proceed with the request
		ctx := context.WithValue(r.Context(), "userID", claims.UserID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (h *Handlers) GenerateJWT(userID string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UserID: userID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(h.Config.JWTSecret))

	return tokenString, err
}

func (h *Handlers) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var userCredentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&userCredentials); err != nil {
		h.ErrorHandler(w, fmt.Errorf("decoding credentials: %w", err), http.StatusBadRequest)
		return
	}

	userID, authErr := h.DB.AuthenticateUser(userCredentials.Username, userCredentials.Password)
	if authErr != nil {
		h.ErrorHandler(w, fmt.Errorf("authentication failed: %w", authErr), http.StatusUnauthorized)
		return
	}

	token, err := h.GenerateJWT(userID)
	if err != nil {
		h.ErrorHandler(w, err, http.StatusInternalServerError)
		return
	}

	respondWithJSON(w, map[string]string{"token": token, "userID": userID})
}

func (h *Handlers) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")[7:] // Assuming "Bearer " is stripped
	if tokenString == "" {
		h.ErrorHandler(w, fmt.Errorf("Token is required"), http.StatusBadRequest)
		return
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(h.Config.JWTSecret), nil
	})

	if err != nil || !token.Valid {
		h.ErrorHandler(w, fmt.Errorf("invalid token"), http.StatusBadRequest)
		return
	}

	expiration := time.Unix(claims.ExpiresAt, 0)
	remainingTime := expiration.Sub(time.Now())

	// Assuming `AddTokenToBlacklist` is a method to store the token in Redis with the remaining TTL
	if err := h.DB.AddTokenToBlacklist(tokenString, remainingTime); err != nil {
		h.ErrorHandler(w, err, http.StatusInternalServerError)
		return
	}

	respondWithJSON(w, map[string]string{"status": "successfully logged out"})
}

func respondWithJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
