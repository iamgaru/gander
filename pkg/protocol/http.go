package protocol

import (
	"bufio"
	"bytes"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// HTTPRequest represents a parsed HTTP request
type HTTPRequest struct {
	Method      string
	URL         string
	Path        string
	Query       string
	HTTPVersion string
	Headers     map[string]string
	Body        string
	BodySize    int
	ContentType string
	UserAgent   string
	Referer     string
	Host        string
}

// HTTPResponse represents a parsed HTTP response
type HTTPResponse struct {
	StatusCode int
	Headers    map[string]string
	Body       string
	BodySize   int
}

// ExtractHTTPHost extracts the host from HTTP request data
func ExtractHTTPHost(data []byte) string {
	reader := bufio.NewReader(bytes.NewReader(data))

	// Skip request line
	_, _, err := reader.ReadLine()
	if err != nil {
		return ""
	}

	// Read headers
	for {
		line, _, err := reader.ReadLine()
		if err != nil || len(line) == 0 {
			break
		}

		headerLine := string(line)
		if colonIdx := strings.Index(headerLine, ":"); colonIdx != -1 {
			key := strings.TrimSpace(strings.ToLower(headerLine[:colonIdx]))
			value := strings.TrimSpace(headerLine[colonIdx+1:])

			if key == "host" {
				return value
			}
		}
	}

	return ""
}

// ParseHTTPRequest parses HTTP request data into a structured format
func ParseHTTPRequest(data []byte) (*HTTPRequest, error) {
	// Find the end of headers (double CRLF)
	headerEndIndex := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEndIndex == -1 {
		// If no double CRLF found, treat entire data as headers (incomplete request)
		headerEndIndex = len(data)
	}

	headerData := data[:headerEndIndex]
	reader := bufio.NewReader(bytes.NewReader(headerData))

	// Parse request line
	requestLine, _, err := reader.ReadLine()
	if err != nil {
		return nil, err
	}

	requestParts := strings.Fields(string(requestLine))
	if len(requestParts) < 3 {
		return nil, fmt.Errorf("invalid HTTP request line")
	}

	method := requestParts[0]
	urlPath := requestParts[1]
	httpVersion := requestParts[2]

	request := &HTTPRequest{
		Method:      method,
		URL:         urlPath,
		HTTPVersion: httpVersion,
		Headers:     make(map[string]string),
	}

	// Parse URL for path and query
	if parsedURL, err := url.Parse(urlPath); err == nil {
		request.Path = parsedURL.Path
		request.Query = parsedURL.RawQuery
	} else {
		request.Path = urlPath
	}

	// Parse headers
	for {
		line, _, err := reader.ReadLine()
		if err != nil || len(line) == 0 {
			break
		}

		headerLine := string(line)
		if colonIdx := strings.Index(headerLine, ":"); colonIdx != -1 {
			key := strings.TrimSpace(headerLine[:colonIdx])
			value := strings.TrimSpace(headerLine[colonIdx+1:])

			// Store all headers
			request.Headers[key] = value

			// Extract common headers for easy access
			switch strings.ToLower(key) {
			case "host":
				request.Host = value
			case "content-type":
				request.ContentType = value
			case "user-agent":
				request.UserAgent = value
			case "referer":
				request.Referer = value
			}
		}
	}

	// Read body if present (after the double CRLF)
	if headerEndIndex < len(data) && headerEndIndex+4 < len(data) {
		bodyData := data[headerEndIndex+4:] // Skip the \r\n\r\n
		if len(bodyData) > 0 {
			// For binary data, we might want to base64 encode, but for now treat as string
			request.Body = string(bodyData)
			request.BodySize = len(bodyData)
		}
	}

	return request, nil
}

// ParseHTTPResponse parses HTTP response data into a structured format
func ParseHTTPResponse(data []byte) (*HTTPResponse, error) {
	// Find the end of headers (double CRLF)
	headerEndIndex := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEndIndex == -1 {
		// If no double CRLF found, treat entire data as headers (incomplete response)
		headerEndIndex = len(data)
	}

	headerData := data[:headerEndIndex]
	reader := bufio.NewReader(bytes.NewReader(headerData))

	// Parse status line
	statusLine, _, err := reader.ReadLine()
	if err != nil {
		return nil, err
	}

	statusParts := strings.Fields(string(statusLine))
	if len(statusParts) < 2 {
		return nil, fmt.Errorf("invalid HTTP response status line")
	}

	// Parse status code
	statusCode, err := strconv.Atoi(statusParts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid status code: %v", err)
	}

	response := &HTTPResponse{
		StatusCode: statusCode,
		Headers:    make(map[string]string),
	}

	// Parse headers
	for {
		line, _, err := reader.ReadLine()
		if err != nil || len(line) == 0 {
			break
		}

		headerLine := string(line)
		if colonIdx := strings.Index(headerLine, ":"); colonIdx != -1 {
			key := strings.TrimSpace(headerLine[:colonIdx])
			value := strings.TrimSpace(headerLine[colonIdx+1:])

			// Store all headers
			response.Headers[key] = value
		}
	}

	// Read body if present (after the double CRLF)
	if headerEndIndex < len(data) && headerEndIndex+4 < len(data) {
		bodyData := data[headerEndIndex+4:] // Skip the \r\n\r\n
		if len(bodyData) > 0 {
			// For binary data, we might want to base64 encode, but for now treat as string
			response.Body = string(bodyData)
			response.BodySize = len(bodyData)
		}
	}

	return response, nil
}

// IsHTTPRequest checks if data looks like an HTTP request
func IsHTTPRequest(data []byte) bool {
	if len(data) < 8 {
		return false
	}

	// Check for common HTTP methods
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "TRACE ", "CONNECT "}
	for _, method := range methods {
		if bytes.HasPrefix(data, []byte(method)) {
			return true
		}
	}

	return false
}

// IsHTTPResponse checks if data looks like an HTTP response
func IsHTTPResponse(data []byte) bool {
	if len(data) < 8 {
		return false
	}

	// Check for HTTP response start patterns
	return bytes.HasPrefix(data, []byte("HTTP/1.0 ")) ||
		bytes.HasPrefix(data, []byte("HTTP/1.1 ")) ||
		bytes.HasPrefix(data, []byte("HTTP/2.0 "))
}
