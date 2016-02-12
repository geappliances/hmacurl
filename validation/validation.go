package validation

import (
	"strings"
)

// Method validates the HTTP method type
func Method(method string) bool {
	switch strings.ToUpper(method) {
	case "GET", "PUT", "POST":
		return true
	default:
		return false
	}
}
