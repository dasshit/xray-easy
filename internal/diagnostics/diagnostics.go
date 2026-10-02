package diagnostics

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Entry is one diagnostic result with a severity, message, and optional remediation.
type Entry struct {
	// At contains the At value for this object.
	At time.Time `json:"at"`
	// Component contains the Component value for this object.
	Component string `json:"component"`
	// Level contains the Level value for this object.
	Level string `json:"level"`
	// Message contains the Message value for this object.
	Message string `json:"message"`
}

// Buffer collects bounded diagnostic entries for a single report.
type Buffer struct {
	mu      sync.Mutex
	entries []Entry
	limit   int
}

// NewBuffer constructs and returns the requested value.
func NewBuffer(limit int) *Buffer {
	if limit < 1 {
		limit = 100
	}
	return &Buffer{limit: limit}
}

// Add adds the supplied value.
func (b *Buffer) Add(component, level, message string) {
	if b == nil {
		return
	}
	entry := Entry{At: time.Now().UTC(), Component: component, Level: level, Message: Redact(message)}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.entries) >= b.limit {
		copy(b.entries, b.entries[1:])
		b.entries = b.entries[:b.limit-1]
	}
	b.entries = append(b.entries, entry)
}

// Snapshot returns a snapshot of the current state.
func (b *Buffer) Snapshot(limit int) []Entry {
	if b == nil {
		return []Entry{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if limit <= 0 || limit > len(b.entries) {
		limit = len(b.entries)
	}
	start := len(b.entries) - limit
	result := append([]Entry(nil), b.entries[start:]...)
	return result
}

var (
	// secretFieldPattern is an internal package variable.
	secretFieldPattern = regexp.MustCompile(`(?i)(private[_-]?key|password|token|secret|master[_-]?key|short[_-]?id)(\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s,;}]+)`)
	// quotedSecretFieldPattern is an internal package variable.
	quotedSecretFieldPattern = regexp.MustCompile(`(?i)(["'])(private[_-]?key|password|token|secret|master[_-]?key|short[_-]?id)(["'])\s*:\s*("[^"]*"|'[^']*'|[^\s,;}]+)`)
	// uuidPattern is an internal package variable.
	uuidPattern = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b`)
	// vlessPattern is an internal package variable.
	vlessPattern = regexp.MustCompile(`(?i)vless://[^\s"']+`)
	// bearerPattern is an internal package variable.
	bearerPattern = regexp.MustCompile(`(?i)\bBearer\s+[^\s,;}]+`)
)

// Redact performs the operation represented by its name.
func Redact(value string) string {
	value = vlessPattern.ReplaceAllString(value, "vless://[REDACTED]")
	value = bearerPattern.ReplaceAllString(value, "Bearer [REDACTED]")
	value = quotedSecretFieldPattern.ReplaceAllStringFunc(value, func(match string) string {
		parts := quotedSecretFieldPattern.FindStringSubmatch(match)
		if len(parts) != 5 {
			return "[REDACTED]"
		}
		return parts[1] + parts[2] + parts[3] + ": " + parts[1] + "[REDACTED]" + parts[1]
	})
	value = secretFieldPattern.ReplaceAllStringFunc(value, func(match string) string {
		parts := secretFieldPattern.FindStringSubmatch(match)
		if len(parts) != 4 {
			return "[REDACTED]"
		}
		return parts[1] + parts[2] + "[REDACTED]"
	})
	value = uuidPattern.ReplaceAllString(value, "[REDACTED-UUID]")
	return strings.TrimSpace(value)
}

// RedactJSON parses a JSON document and masks credential-bearing values and
// identifying client fields before the document is included in a support bundle.
func RedactJSON(document []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("multiple JSON values")
		}
		return nil, err
	}
	redacted := redactJSONValue(value)
	return json.MarshalIndent(redacted, "", "  ")
}

// redactJSONValue performs the operation represented by its name.
func redactJSONValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			if sensitiveJSONKey(key) {
				typed[key] = "[REDACTED]"
				continue
			}
			typed[key] = redactJSONValue(item)
		}
		return typed
	case []any:
		for i := range typed {
			typed[i] = redactJSONValue(typed[i])
		}
		return typed
	case string:
		return Redact(typed)
	default:
		return value
	}
}

// sensitiveJSONKey performs the operation represented by its name.
func sensitiveJSONKey(key string) bool {
	key = strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(key))
	switch key {
	case "id", "uuid", "email", "name", "privatekey", "password", "token", "secret", "masterkey", "shortid", "shortids", "recoverycodes":
		return true
	default:
		return false
	}
}
