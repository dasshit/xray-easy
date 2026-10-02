package control

import (
	"fmt"
	"strings"
)

// routeDevice performs the operation represented by its name.
func routeDevice(route string) (string, error) {
	parts := strings.Fields(route)
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "dev" && parts[i+1] != "" {
			return parts[i+1], nil
		}
	}
	return "", fmt.Errorf("route has no device: %q", route)
}
