package server

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/AmosSParker/Slud9e/internal/server/config"
	"github.com/AmosSParker/Slud9e/internal/utils"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int
	Username string
	Password string // should be a hashed value
}

func InitializeDatabaseWith(cfg *config.Config) (*sql.DB, error) {
	// Open database connection
	db, err := sql.Open("postgres", cfg.DBConnectionString)
	if err != nil {
		utils.LogError("Error opening database connection", err, nil)
		return nil, fmt.Errorf("error opening database connection: %w", err)
	}

	// Set database connection pool settings
	db.SetMaxOpenConns(25)                 // Adjust based on your application's requirements
	db.SetMaxIdleConns(10)                 // idle connections for performance
	db.SetConnMaxLifetime(5 * time.Minute) // Prevent stale connections

	// Verify database connection
	if err := db.Ping(); err != nil {
		utils.LogError("Error verifying connection with database", err, nil)
		return nil, fmt.Errorf("error verifying connection with database: %w", err)
	}

	// Handle migrations
	migrationPath := fmt.Sprintf("file://%s", cfg.MigrationDirectory)
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		utils.LogError("Could not create database driver for migration", err, nil)
		return nil, fmt.Errorf("could not create database driver for migration: %w", err)
	}

	m, err := migrate.NewWithDatabaseInstance(
		migrationPath,
		"postgres", driver,
	)
	if err != nil {
		utils.LogError("Could not initialize database migrations", err, map[string]interface{}{"path": migrationPath})
		return nil, fmt.Errorf("could not initialize database migrations: %w", err)
	}

	if err := m.Up(); err != nil {
		if err != migrate.ErrNoChange {
			utils.LogError("Failed to apply migrations", err, nil)
			return nil, fmt.Errorf("failed to apply migrations: %w", err)
		}
		utils.LogInfo("No new migrations to apply", nil)
	}

	utils.LogInfo("Database connection and migration successful", nil)
	return db, nil
}

func CreateUser(username, password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Insert user into the database.
	_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, string(hashedPassword))
	return err
}

func AuthenticateUser(username, password string) (bool, error) {
	var hashedPassword string

	// Retrieve hashed password from database.
	err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&hashedPassword)
	if err != nil {
		return false, err
	}

	// Compare the provided password with the hashed password in the database.
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return false, err // Password does not match
	}

	return true, nil // Password matches
}
