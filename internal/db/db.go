package db

import (
    "database/sql"
    "fmt"
    "time"

    "github.com/AmosSParker/Slud9e/internal/config"
    "github.com/AmosSParker/Slud9e/internal/utils"
    "github.com/golang-migrate/migrate/v4"
    "github.com/golang-migrate/migrate/v4/database"
    _ "github.com/golang-migrate/migrate/v4/source/file"
)

// InitializeDatabase initializes the database connection and applies migrations.
func InitializeDatabase(cfg *config.Config) (*sql.DB, error) {
    // Open database connection
    db, err := sql.Open(cfg.DB.DriverName, cfg.DBConnectionString)
    if err != nil {
        utils.LogError("Error opening database connection", err, nil)
        return nil, fmt.Errorf("error opening database connection: %w", err)
    }

    // Set database connection pool settings
    db.SetMaxOpenConns(cfg.DB.MaxOpenConns)
    db.SetMaxIdleConns(cfg.DB.MaxIdleConns)
    db.SetConnMaxLifetime(time.Duration(cfg.DB.ConnMaxLifetimeSeconds) * time.Second)

    // Verify database connection
    if err := db.Ping(); err != nil {
        utils.LogError("Error verifying connection with database", err, nil)
        return nil, fmt.Errorf("error verifying connection with database: %w", err)
    }

    // Handle migrations
    migrationPath := fmt.Sprintf("file://%s", cfg.DB.MigrationDirectory)
    driver, err := GetDatabaseDriver(cfg.DB.DriverName, db)
    if err != nil {
        utils.LogError("Could not create database driver for migration", err, nil)
        return nil, fmt.Errorf("could not create database driver for migration: %w", err)
    }

    m, err := migrate.NewWithDatabaseInstance(
        migrationPath,
        cfg.DB.DriverName, driver,
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

// GetDatabaseDriver returns the appropriate database driver based on the given driver name and database connection.
func GetDatabaseDriver(driverName string, db *sql.DB) (database.Driver, error) {
    switch driverName {
    case "postgres":
        return postgres.WithInstance(db, &postgres.Config{})
    // Add cases for other supported database drivers
    default:
        return nil, fmt.Errorf("unsupported database driver: %s", driverName)
    }
}
