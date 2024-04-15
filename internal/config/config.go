package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"sync"
	"time"
)

// Config represents the configuration settings for the server.
type Config struct {
	ServerAddress             string `json:"serverAddress"`      // Address to bind the server to
	DBConnectionString        string `json:"dbConnectionString"` // Connection string for the database
	TLSCertPath               string `json:"tlsCertPath"`        // Path to the TLS certificate file
	TLSKeyPath                string `json:"tlsKeyPath"`         // Path to the TLS key file
	LogFile                   string `json:"logFile"`            // Path to the log file
	MigrationDirectory        string `json:"migrationDirectory"` // Directory containing database migrations
	JWTSecret                 string `json:"jwtSecret"`          // Secret key for JWT authentication
	RateLimitDuration         time.Duration
	RateLimitRequests         int
	RateLimitBurst            int
	TokenExpirationTime       time.Duration
	TokenBlacklistDuration    time.Duration
	ErrorHandlingConfig       ErrorHandlingConfig
	MetricsConfig             MetricsConfig
	LoggingConfig             LoggingConfig
	CachingConfig             CachingConfig
	SessionManagementConfig   SessionManagementConfig
	SecurityHeadersConfig     SecurityHeadersConfig
	APIVersioningConfig       APIVersioningConfig
	EnvironmentSpecificConfig EnvironmentSpecificConfig
	ResponseContentType       string
	DefaultErrorMessages      map[string]string
	JWTIssuer                 string
}

// ErrorHandlingConfig represents configuration for error handling.
type ErrorHandlingConfig struct {
	ErrorCodeMappings map[string]int
}

// MetricsConfig represents configuration for metrics collection.
type MetricsConfig struct {
	Endpoint       string
	SamplingRate   float64
}

// LoggingConfig represents configuration for logging.
type LoggingConfig struct {
	LogLevel          string
	LogFileRotation   bool
	LogFileMaxSizeMB  int
	LogFormat         string
}

// CachingConfig represents configuration for caching.
type CachingConfig struct {
	CacheDuration     time.Duration
	EvictionPolicy    string
}

// SessionManagementConfig represents configuration for session management.
type SessionManagementConfig struct {
	SessionTimeout   time.Duration
	SessionStorage   string
}

// SecurityHeadersConfig represents configuration for security headers.
type SecurityHeadersConfig struct {
	CSP         string
	CORS        string
}

// APIVersioningConfig represents configuration for API versioning.
type APIVersioningConfig struct {
	DefaultAPIVersion   string
	SupportedVersions   []string
}

// EnvironmentSpecificConfig represents configuration specific to different environments.
type EnvironmentSpecificConfig struct {
	DevelopmentConfig Config
	StagingConfig     Config
	ProductionConfig  Config
}

var (
	instance *Config
	once     sync.Once
)

// LoadConfig reads the configuration from a JSON file, with optional environment variable overrides.
func LoadConfig(filePath string) (*Config, error) {
	var configError error

	once.Do(func() {
		data, err := ioutil.ReadFile(filePath)
		if err != nil {
			fmt.Printf("Failed to read config file: %v\n", err)
			configError = fmt.Errorf("failed to read config file: %w", err)
			return
		}

		instance = &Config{
			// Default values for commonly used fields
			RateLimitDuration:        1 * time.Second,
			RateLimitRequests:        100,
			RateLimitBurst:           10,
			TokenExpirationTime:      15 * time.Minute,
			TokenBlacklistDuration:   24 * time.Hour,
			ResponseContentType:      "application/json",
			DefaultErrorMessages:     map[string]string{"internal_error": "Internal Server Error"},
			JWTIssuer:                "Slud9e",
			// Default values for other fields
			ServerAddress:            "localhost:8080",
			DBConnectionString:       "postgres://user:password@localhost:5432/database",
			TLSCertPath:              "/path/to/tls/cert.pem",
			TLSKeyPath:               "/path/to/tls/key.pem",
			LogFile:                  "server.log",
			MigrationDirectory:       "./migrations",
			JWTSecret:                "your_jwt_secret",
			ErrorHandlingConfig:      ErrorHandlingConfig{ErrorCodeMappings: map[string]int{}},
			MetricsConfig:            MetricsConfig{Endpoint: "/metrics", SamplingRate: 1.0},
			LoggingConfig:            LoggingConfig{LogLevel: "info", LogFileRotation: true, LogFileMaxSizeMB: 10, LogFormat: "text"},
			CachingConfig:            CachingConfig{CacheDuration: 1 * time.Hour, EvictionPolicy: "LRU"},
			SessionManagementConfig:  SessionManagementConfig{SessionTimeout: 30 * time.Minute, SessionStorage: "memory"},
			SecurityHeadersConfig:    SecurityHeadersConfig{CSP: "default-src 'self'", CORS: ""},
			APIVersioningConfig:      APIVersioningConfig{DefaultAPIVersion: "v1", SupportedVersions: []string{"v1"}},
			EnvironmentSpecificConfig: EnvironmentSpecificConfig{},
		}
		if err := json.Unmarshal(data, instance); err != nil {
			fmt.Printf("Failed to unmarshal config data: %v\n", err)
			configError = fmt.Errorf("failed to unmarshal config data: %w", err)
			return
		}

		// Apply environment variable overrides
		overrideWithEnvVars(instance)
	})

	if instance == nil {
		return nil, configError
	}
	return instance, nil
}

// overrideWithEnvVars overrides configuration settings with environment variables.
func overrideWithEnvVars(cfg *Config) {
	if addr := os.Getenv("SERVER_ADDRESS"); addr != "" {
		cfg.ServerAddress = addr
	}
	if dbConn := os.Getenv("DB_CONNECTION_STRING"); dbConn != "" {
		cfg.DBConnectionString = dbConn
	}
	if tlsCert := os.Getenv("TLS_CERT_PATH"); tlsCert != "" {
		cfg.TLSCertPath = tlsCert
	}
	if tlsKey := os.Getenv("TLS_KEY_PATH"); tlsKey != "" {
		cfg.TLSKeyPath = tlsKey
	}
	if logFile := os.Getenv("LOG_FILE"); logFile != "" {
		cfg.LogFile = logFile
	}
	if migrationDir := os.Getenv("MIGRATION_DIRECTORY"); migrationDir != "" {
		cfg.MigrationDirectory = migrationDir
	}
	if jwtSecret := os.Getenv("JWT_SECRET"); jwtSecret != "" {
		cfg.JWTSecret = jwtSecret
	}
	// Add support for other environment variable overrides as needed
}

// GetInstance returns the singleton instance of the configuration.
func GetInstance() *Config {
	if instance == nil {
		fmt.Println("Config instance not initialized. Ensure LoadConfig is called at startup.")
		panic("configuration not initialized")
	}
	return instance
}

// UpdateConfig updates the configuration with new data.
func (c *Config) UpdateConfig(updatedConfigData []byte) error {
	c.Lock()
	defer c.Unlock()

	if err := json.Unmarshal(updatedConfigData, c); err != nil {
		fmt.Printf("Failed to update config: %v\n", err)
		return fmt.Errorf("failed to update config: %w", err)
	}

	fmt.Println("Configuration updated successfully")
	return nil
}
