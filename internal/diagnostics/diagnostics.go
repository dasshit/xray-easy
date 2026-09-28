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

type Entry struct {
	At        time.Time `json:"at"`
	Component string    `json:"component"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
}

type Buffer struct {
	mu      sync.Mutex
	entries []Entry
	limit   int
}

func NewBuffer(limit int) *Buffer {
	if limit < 1 {
		limit = 100
	}
	return &Buffer{limit: limit}
}

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
	secretFieldPattern       = regexp.MustCompile(`(?i)(private[_-]?key|password|token|secret|master[_-]?key|short[_-]?id)(\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s,;}]+)`)
	quotedSecretFieldPattern = regexp.MustCompile(`(?i)(["'])(private[_-]?key|password|token|secret|master[_-]?key|short[_-]?id)(["'])\s*:\s*("[^"]*"|'[^']*'|[^\s,;}]+)`)
	uuidPattern              = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b`)
	vlessPattern             = regexp.MustCompile(`(?i)vless://[^\s"']+`)
	bearerPattern            = regexp.MustCompile(`(?i)\bBearer\s+[^\s,;}]+`)
)

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

func sensitiveJSONKey(key string) bool {
	key = strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(key))
	switch key {
	case "id", "uuid", "email", "name", "privatekey", "password", "token", "secret", "masterkey", "shortid", "shortids", "recoverycodes":
		return true
	default:
		return false
	}
}
