package protocol

import (
	"reflect"
	"testing"
)

func TestExtractHTTPHost(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "Standard GET request",
			data:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"),
			expected: "example.com",
		},
		{
			name:     "Host with port",
			data:     []byte("POST /api HTTP/1.1\r\nHost: api.example.com:8080\r\nContent-Type: application/json\r\n\r\n"),
			expected: "api.example.com:8080",
		},
		{
			name:     "No Host header",
			data:     []byte("GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n"),
			expected: "",
		},
		{
			name:     "Empty data",
			data:     []byte(""),
			expected: "",
		},
		{
			name:     "Malformed request",
			data:     []byte("INVALID REQUEST"),
			expected: "",
		},
		{
			name:     "Multiple headers with Host",
			data:     []byte("GET /test HTTP/1.1\r\nConnection: keep-alive\r\nHost: test.example.com\r\nAccept: text/html\r\n\r\n"),
			expected: "test.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractHTTPHost(tt.data)
			if result != tt.expected {
				t.Errorf("ExtractHTTPHost() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestParseHTTPRequest(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		expected    *HTTPRequest
		expectError bool
	}{
		{
			name: "Simple GET request",
			data: []byte("GET /test?param=value HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test-agent\r\n\r\n"),
			expected: &HTTPRequest{
				Method:      "GET",
				URL:         "/test?param=value",
				Path:        "/test",
				Query:       "param=value",
				HTTPVersion: "HTTP/1.1",
				Headers: map[string]string{
					"Host":       "example.com",
					"User-Agent": "test-agent",
				},
				Host:      "example.com",
				UserAgent: "test-agent",
				Body:      "",
				BodySize:  0,
			},
			expectError: false,
		},
		{
			name: "POST request with body",
			data: []byte("POST /api/submit HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 25\r\n\r\n{\"name\":\"test\",\"id\":123}"),
			expected: &HTTPRequest{
				Method:      "POST",
				URL:         "/api/submit",
				Path:        "/api/submit",
				Query:       "",
				HTTPVersion: "HTTP/1.1",
				Headers: map[string]string{
					"Host":           "api.example.com",
					"Content-Type":   "application/json",
					"Content-Length": "25",
				},
				Host:        "api.example.com",
				ContentType: "application/json",
				Body:        "{\"name\":\"test\",\"id\":123}",
				BodySize:    24,
			},
			expectError: false,
		},
		{
			name: "Request with Referer header",
			data: []byte("GET /page HTTP/1.1\r\nHost: example.com\r\nReferer: https://google.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"),
			expected: &HTTPRequest{
				Method:      "GET",
				URL:         "/page",
				Path:        "/page",
				HTTPVersion: "HTTP/1.1",
				Headers: map[string]string{
					"Host":       "example.com",
					"Referer":    "https://google.com",
					"User-Agent": "Mozilla/5.0",
				},
				Host:      "example.com",
				UserAgent: "Mozilla/5.0",
				Referer:   "https://google.com",
			},
			expectError: false,
		},
		{
			name:        "Invalid request line",
			data:        []byte("INVALID\r\nHost: example.com\r\n\r\n"),
			expected:    nil,
			expectError: true,
		},
		{
			name:        "Empty data",
			data:        []byte(""),
			expected:    nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseHTTPRequest(tt.data)

			if tt.expectError {
				if err == nil {
					t.Errorf("ParseHTTPRequest() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("ParseHTTPRequest() unexpected error: %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ParseHTTPRequest() = %+v, want %+v", result, tt.expected)
			}
		})
	}
}

func TestParseHTTPResponse(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		expected    *HTTPResponse
		expectError bool
	}{
		{
			name: "Simple 200 response",
			data: []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, World!"),
			expected: &HTTPResponse{
				StatusCode: 200,
				Headers: map[string]string{
					"Content-Type":   "text/html",
					"Content-Length": "13",
				},
				Body:     "Hello, World!",
				BodySize: 13,
			},
			expectError: false,
		},
		{
			name: "404 response",
			data: []byte("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nPage not found"),
			expected: &HTTPResponse{
				StatusCode: 404,
				Headers: map[string]string{
					"Content-Type": "text/plain",
				},
				Body:     "Page not found",
				BodySize: 14,
			},
			expectError: false,
		},
		{
			name: "Response without body",
			data: []byte("HTTP/1.1 204 No Content\r\nServer: nginx/1.18.0\r\n\r\n"),
			expected: &HTTPResponse{
				StatusCode: 204,
				Headers: map[string]string{
					"Server": "nginx/1.18.0",
				},
				Body:     "",
				BodySize: 0,
			},
			expectError: false,
		},
		{
			name:        "Invalid status line",
			data:        []byte("INVALID RESPONSE\r\n\r\n"),
			expected:    nil,
			expectError: true,
		},
		{
			name:        "Invalid status code",
			data:        []byte("HTTP/1.1 INVALID\r\n\r\n"),
			expected:    nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseHTTPResponse(tt.data)

			if tt.expectError {
				if err == nil {
					t.Errorf("ParseHTTPResponse() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("ParseHTTPResponse() unexpected error: %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ParseHTTPResponse() = %+v, want %+v", result, tt.expected)
			}
		})
	}
}

func TestIsHTTPRequest(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "Valid GET request",
			data:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: true,
		},
		{
			name:     "Valid POST request",
			data:     []byte("POST /api HTTP/1.1\r\nHost: api.example.com\r\n\r\n"),
			expected: true,
		},
		{
			name:     "Valid PUT request",
			data:     []byte("PUT /resource HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: true,
		},
		{
			name:     "Invalid method",
			data:     []byte("INVALID / HTTP/1.1\r\n\r\n"),
			expected: false,
		},
		{
			name:     "HTTP response (not request)",
			data:     []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"),
			expected: false,
		},
		{
			name:     "Empty data",
			data:     []byte(""),
			expected: false,
		},
		{
			name:     "Binary data",
			data:     []byte{0x16, 0x03, 0x01, 0x00, 0x2F}, // TLS handshake
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsHTTPRequest(tt.data)
			if result != tt.expected {
				t.Errorf("IsHTTPRequest() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsHTTPResponse(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "Valid HTTP response",
			data:     []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"),
			expected: true,
		},
		{
			name:     "HTTP/1.0 response",
			data:     []byte("HTTP/1.0 404 Not Found\r\nContent-Type: text/plain\r\n\r\n"),
			expected: true,
		},
		{
			name:     "HTTP request (not response)",
			data:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: false,
		},
		{
			name:     "Invalid status line",
			data:     []byte("INVALID RESPONSE\r\n\r\n"),
			expected: false,
		},
		{
			name:     "Empty data",
			data:     []byte(""),
			expected: false,
		},
		{
			name:     "Binary data",
			data:     []byte{0x16, 0x03, 0x01, 0x00, 0x2F}, // TLS handshake
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsHTTPResponse(tt.data)
			if result != tt.expected {
				t.Errorf("IsHTTPResponse() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Benchmark tests for performance validation
func BenchmarkExtractHTTPHost(b *testing.B) {
	data := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExtractHTTPHost(data)
	}
}

func BenchmarkParseHTTPRequest(b *testing.B) {
	data := []byte("POST /api/submit HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\n\r\n{\"test\":\"data\"}")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseHTTPRequest(data)
	}
}

func BenchmarkIsHTTPRequest(b *testing.B) {
	data := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IsHTTPRequest(data)
	}
}
