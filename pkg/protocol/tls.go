package protocol

import (
	"encoding/binary"
)

// ExtractSNI extracts the Server Name Indication from TLS ClientHello
func ExtractSNI(data []byte) string {
	if len(data) < 6 {
		return ""
	}

	// Check for TLS handshake (0x16) and ClientHello (0x01)
	if data[0] != 0x16 || len(data) < 43 {
		return ""
	}

	// Skip TLS record header (5 bytes) and handshake header (4 bytes)
	pos := 9

	// Skip version (2 bytes)
	pos += 2

	// Skip random (32 bytes)
	pos += 32

	if pos >= len(data) {
		return ""
	}

	// Skip session ID
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	if pos+2 >= len(data) {
		return ""
	}

	// Skip cipher suites
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2 + cipherSuitesLen

	if pos+1 >= len(data) {
		return ""
	}

	// Skip compression methods
	compressionMethodsLen := int(data[pos])
	pos += 1 + compressionMethodsLen

	if pos+2 >= len(data) {
		return ""
	}

	// Extensions length
	extensionsLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2

	if pos+extensionsLen > len(data) {
		return ""
	}

	// Parse extensions
	extensionsEnd := pos + extensionsLen
	for pos < extensionsEnd {
		if pos+4 > extensionsEnd {
			break
		}

		extensionType := binary.BigEndian.Uint16(data[pos : pos+2])
		extensionLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if pos+extensionLen > extensionsEnd {
			break
		}

		// Check for SNI extension (type 0x0000)
		if extensionType == 0x0000 {
			return parseSNIExtension(data[pos : pos+extensionLen])
		}

		pos += extensionLen
	}

	return ""
}

// parseSNIExtension parses the SNI extension data
func parseSNIExtension(data []byte) string {
	if len(data) < 5 {
		return ""
	}

	// Skip server name list length (2 bytes)
	pos := 2

	// Server name type (1 byte) - should be 0x00 for hostname
	if data[pos] != 0x00 {
		return ""
	}
	pos++

	// Server name length (2 bytes)
	if pos+2 > len(data) {
		return ""
	}
	nameLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2

	if pos+nameLen > len(data) {
		return ""
	}

	return string(data[pos : pos+nameLen])
}

// IsTLSHandshake checks if data looks like a TLS handshake
func IsTLSHandshake(data []byte) bool {
	if len(data) < 6 {
		return false
	}

	// Check for TLS record type (0x16 = handshake)
	if data[0] != 0x16 {
		return false
	}

	// Check TLS version (should be 0x03xx)
	if data[1] != 0x03 {
		return false
	}

	// Check handshake type (0x01 = ClientHello)
	if len(data) > 5 && data[5] == 0x01 {
		return true
	}

	return false
}

// IsTLSData checks if data looks like TLS encrypted data
func IsTLSData(data []byte) bool {
	if len(data) < 3 {
		return false
	}

	// Check for TLS record types
	recordType := data[0]
	switch recordType {
	case 0x14: // Change Cipher Spec
	case 0x15: // Alert
	case 0x16: // Handshake
	case 0x17: // Application Data
		// Check TLS version (should be 0x03xx)
		return data[1] == 0x03
	}

	return false
}
