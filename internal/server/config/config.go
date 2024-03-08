package config

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"sync"

	"github.com/AmosSParker/Slud9e/internal/utils"
)

type Config struct {
	ServerAddress      string `json:"serverAddress"`
	DBConnectionString string `json:"dbConnectionString"`
	TLSCertPath        string `json:"tlsCertPath"`
	TLSKeyPath         string `json:"tlsKeyPath"`
	LogFile            string `json:"logFile"`
	MigrationDirectory string `json:"migrationDirectory"`
	JWTSecret          string `json:"jwtSecret"`
	sync.RWMutex              // Ensure thread-safe access to the config fields.
}

var (
	instance *Config
	once     sync.Once
)

// LoadConfig reads and unmarshals the configuration from a JSON file, with environment variable overrides.
func LoadConfig(filePath string) (*Config, error) {
	var configError error // Define error variable outside the once.Do scope

	once.Do(func() {
		data, err := ioutil.ReadFile(filePath)
		if err != nil {
			utils.LogError("Failed to read config file", err)
			configError = err // Assign error to the outer scope variable
			return
		}
		instance = &Config{}
		if err := json.Unmarshal(data, instance); err != nil {
			utils.LogError("Failed to unmarshal config data", err)
			configError = err // Assign error to the outer scope variable
			return
		}

		// Apply environment variable overrides
		overrideWithEnvVars(instance)
	})

	if instance == nil {
		return nil, configError // Use the outer scope error variable
	}
	return instance, nil
}

func overrideWithEnvVars(cfg *Config) {
	// Environment variable overrides logic remains unchanged
	if addr := os.Getenv("SERVER_ADDRESS"); addr != "" {
		cfg.ServerAddress = addr
	}
	if dbConn := os.Getenv("DB_CONNECTION_STRING"); dbConn != "" {
		cfg.DBConnectionString = dbConn
	}
	if migrationDir := os.Getenv("MIGRATION_DIRECTORY"); migrationDir != "" {
		cfg.MigrationDirectory = migrationDir
	}
	if jwtSecret := os.Getenv("JWT_SECRET"); jwtSecret != "" {
		cfg.JWTSecret = jwtSecret
	}
	// Apply other overrides as necessary.
}

func GetInstance() *Config {
	if instance == nil {
		utils.LogError("Config instance not initialized. Ensure LoadConfig is called at startup.", nil)
		panic("configuration not initialized")
	}
	return instance
}

func (c *Config) UpdateConfig(updatedConfigData []byte) error {
	c.Lock()
	defer c.Unlock()

	if err := json.Unmarshal(updatedConfigData, c); err != nil {
		utils.LogError("Failed to update config", err)
		return err
	}

	utils.LogInfo("Configuration updated successfully", nil)
	return nil
}
