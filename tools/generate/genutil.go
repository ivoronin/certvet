package generate

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// httpTimeout is the standard timeout for all HTTP requests.
const httpTimeout = time.Minute

// httpClient is the shared HTTP client with the standard timeout.
var httpClient = &http.Client{Timeout: httpTimeout}

// FetchURL fetches a URL and returns the response body.
// Returns an error if the request fails or returns a non-200 status.
func FetchURL(url string) ([]byte, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: status %d", url, resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", url, err)
	}

	return data, nil
}

// Logger provides simple logging for generators.
type Logger struct{}

// Log is the package-level logger instance used by all generators.
var Log = &Logger{}

// Warn prints a warning message to stderr.
func (l *Logger) Warn(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "WARNING: "+format+"\n", args...)
}
