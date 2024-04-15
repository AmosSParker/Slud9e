package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/AmosSParker/Slud9e/internal/server/config"
	"github.com/AmosSParker/Slud9e/internal/server/db"
	"github.com/AmosSParker/Slud9e/internal/server/handlers"
	"github.com/AmosSParker/Slud9e/internal/server/middleware"
	"github.com/AmosSParker/Slud9e/internal/utils"
	"github.com/go-playground/validator/v10"
	"github.com/gorilla/mux"
)

func main() {
	// Configuration and Database Initialization
	cfg := config.GetInstance()
	dbConn, err := db.InitializeDatabase(cfg)
	if err != nil {
		utils.LogError("Failed to initialize database", err, nil)
		os.Exit(1)
	}

	// Validator Setup for Input Validation Middleware
	validate := validator.New()

	// Handlers Initialization with database connection
	h := handlers.NewHandlers(dbConn, cfg)

	// Setup HTTP Server and Routes using gorilla mux
	router := mux.NewRouter()

	// Global middleware
	router.Use(middleware.StructuredLoggingMiddleware)
	router.Use(middleware.GzipCompressionMiddleware)
	router.Use(middleware.SecureHeadersMiddleware)

	// Serving static files
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir(cfg.StaticFilesDir))))

	// Secure API routes with middleware
	apiRoutes := router.PathPrefix("/api").Subrouter()
	apiRoutes.Use(middleware.AuthMiddleware, middleware.RateLimitingMiddleware)

	// Adjusting the API routes to match your actual handlers
	apiRoutes.HandleFunc("/users/login", h.LoginHandler).Methods("POST")
	apiRoutes.HandleFunc("/users/logout", h.LogoutHandler).Methods("POST")
	apiRoutes.HandleFunc("/data", h.DataRetrievalHandler).Methods("GET")
	apiRoutes.HandleFunc("/data", h.DataSubmissionHandler).Methods("POST")
	// Example of a route with input validation middleware
	apiRoutes.HandleFunc("/data/submit", middleware.InputValidationMiddleware(validate)(h.DataSubmissionHandler)).Methods("POST")

	// Initialize and configure the HTTP server
	srv := &http.Server{
		Addr:         cfg.ServerAddress,
		Handler:      router,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	// Server startup and graceful shutdown handling
	go func() {
		utils.LogInfo("Server starting", map[string]interface{}{"address": srv.Addr})
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			utils.LogError("Server failed to start", err, nil)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	utils.LogInfo("Server is shutting down...", nil)

	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		utils.LogError("Server forced to shutdown", err, nil)
	}

	utils.LogInfo("Server exited gracefully", nil)
}
