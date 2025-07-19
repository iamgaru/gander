package inspection

import (
	"strconv"
	"strings"
)

// parseSize parses size string (e.g., "10MB", "1GB") to bytes
func parseSize(sizeStr string) int64 {
	if sizeStr == "" {
		return 0
	}

	// Remove spaces and convert to uppercase
	sizeStr = strings.ToUpper(strings.ReplaceAll(sizeStr, " ", ""))

	// Parse numeric part and unit
	var numeric string
	var unit string
	for i, char := range sizeStr {
		if char >= '0' && char <= '9' || char == '.' {
			numeric += string(char)
		} else {
			unit = sizeStr[i:]
			break
		}
	}

	// Convert to float
	value, err := strconv.ParseFloat(numeric, 64)
	if err != nil {
		return 0
	}

	// Apply unit multiplier
	switch unit {
	case "B", "":
		return int64(value)
	case "KB":
		return int64(value * 1024)
	case "MB":
		return int64(value * 1024 * 1024)
	case "GB":
		return int64(value * 1024 * 1024 * 1024)
	default:
		return 0
	}
}