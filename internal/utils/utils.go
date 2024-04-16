package utils

import (
	"encoding/json"
	"log"
	"os"
	"time"
)

// Assume the use of a simple logging setup. For production, consider a more advanced structured logging library.
var logger = log.New(os.Stdout, "SLUD9E: ", log.Ldate|log.Ltime|log.Lshortfile)

// LogEntry defines the structure for log entries for structured logging.
type LogEntry struct {
	Level   string                 `json:"level"`
	Message string                 `json:"message"`
	Fields  map[string]interface{} `json:"fields,omitempty"`
	Time    string                 `json:"time"`
}

// LogInfo logs informational messages, utilizing structured logging.
func LogInfo(message string, fields map[string]interface{}) {
	logWithFields("INFO", message, fields)
}

// LogWarn logs warning messages, utilizing structured logging.
func LogWarn(message string, fields map[string]interface{}) {
	logWithFields("WARN", message, fields)
}

// LogError logs error messages, utilizing structured logging.
func LogError(message string, err error, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["error"] = err.Error()
	logWithFields("ERROR", message, fields)
}

// LogDebug logs debug messages, for detailed debugging information.
func LogDebug(message string, fields map[string]interface{}) {
	logWithFields("DEBUG", message, fields)
}

// logWithFields handles the creation and logging of structured log entries.
func logWithFields(level string, message string, fields map[string]interface{}) {
	entry := LogEntry{
		Level:   level,
		Message: message,
		Fields:  fields,
		Time:    time.Now().Format(time.RFC3339),
	}
	entryBytes, err := json.Marshal(entry)
	if err != nil {
		logger.Printf("Failed to marshal log entry: %v", err)
		return
	}
	logger.Println(string(entryBytes))
}

// Additional utility functions can be added here, such as error handling utilities, data processing helpers, etc.
