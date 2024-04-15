package middleware

import (
	"compress/gzip"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/AmosSParker/Slud9e/internal/utils"
	"github.com/didip/tollbooth"
	"github.com/go-playground/validator/v10"
)

// StructuredLoggingMiddleware logs each HTTP request with structured logging.
func StructuredLoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		utils.LogInfo("Request processed", map[string]interface{}{
			"method":   r.Method,
			"path":     r.URL.Path,
			"duration": time.Since(start).String(),
		})
	})
}

// GzipCompressionMiddleware applies gzip compression to HTTP responses if the client supports it.
func GzipCompressionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		gz := gzip.NewWriter(w)
		defer gz.Close()
		w.Header().Set("Content-Encoding", "gzip")
		next.ServeHTTP(gzipResponseWriter{ResponseWriter: w, Writer: gz}, r)
	})
}

// gzipResponseWriter wraps http.ResponseWriter, allowing us to overwrite the Write method.
type gzipResponseWriter struct {
	http.ResponseWriter
	Writer *gzip.Writer
}

// Write compresses data before writing it to the underlying ResponseWriter.
func (g gzipResponseWriter) Write(data []byte) (int, error) {
	return g.Writer.Write(data)
}

// InputValidationMiddleware dynamically validates request bodies based on struct tags.
func InputValidationMiddleware(v *validator.Validate) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var request interface{}

			// Example: Determine the request type based on the URL path
			switch r.URL.Path {
			case "/register":
				request = &UserRegistrationRequest{}
			// Add more cases as needed for different endpoints
			default:
				// Continue with next middleware if no validation is needed for the path
				next.ServeHTTP(w, r)
				return
			}

			// Decode and validate the request
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := v.Struct(request); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			// Continue with the next middleware
			next.ServeHTTP(w, r)
		})
	}
}

// AuthMiddleware handles JWT authentication.
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Authorization header is required", http.StatusUnauthorized)
			return
		}

		token, err := ValidateToken(tokenString)
		if err != nil {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Optionally, set the user information in the context
		ctx := context.WithValue(r.Context(), "user", token.Claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RateLimitingMiddleware limits the rate of incoming requests using the tollbooth library.
func RateLimitingMiddleware(next http.Handler) http.Handler {
	limiter := tollbooth.NewLimiter(1, nil) // 1 request per second
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpError := tollbooth.LimitByRequest(limiter, w, r)
		if httpError != nil {
			http.Error(w, httpError.Message, httpError.StatusCode)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ErrorHandlingMiddleware captures and handles panics and errors in the middleware chain.
func ErrorHandlingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				utils.LogError("Recovered from panic", err, map[string]interface{}{
					"path": r.URL.Path,
				})
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// SecureHeadersMiddleware adds security-related headers to responses.
func SecureHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		next.ServeHTTP(w, r)
	})
}
