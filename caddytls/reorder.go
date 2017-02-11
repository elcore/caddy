package caddytls

import "crypto/tls"

// isChaCha returns true if the provided cipher suite represents ChaCha20 cipher suites
func isChaCha(suiteID uint16) bool {
	switch suiteID {
	case 0xcc13, 0xcc14, 0xcca8, 0xcca9, 0xccac:
		return true
	default:
		return false
	}
}

// isGREASE returns true if the provided cipher suite represents GREASE for TLS
func isGREASE(suiteID uint16) bool {
	switch suiteID {
	case 0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA:
		return true
	default:
		return false
	}
}

// PreferChaChaIfFirst moves ChaCha20 cipher suites to the front
func (c *Config) PreferChaChaIfFirst(clientHello *tls.ClientHelloInfo) (*tls.Config, error) {
	if isGREASE(clientHello.CipherSuites[0]) && !isChaCha(clientHello.CipherSuites[1]) {
		// Return unmodified tls.Config
		return nil, nil
	} else if !isGREASE(clientHello.CipherSuites[0]) && !isChaCha(clientHello.CipherSuites[0]) {
		// Return unmodified tls.Config
		return nil, nil
	}

	ciphers := c.TLSConfig.CipherSuites

	reordered := make([]uint16, 0, len(ciphers))
	// first pass: preferred ciphers
	for _, suiteID := range ciphers {
		if isChaCha(suiteID) {
			reordered = append(reordered, suiteID)
		}
	}
	// second pass: all remaining
	for _, suiteID := range ciphers {
		if !isChaCha(suiteID) {
			reordered = append(reordered, suiteID)
		}
	}

	c.TLSConfig.CipherSuites = reordered

	// It's safe to set the maximum version as the minimum version here
	if clientHello.SupportedVersions[0] == c.TLSConfig.MaxVersion && c.TLSConfig.MaxVersion > c.TLSConfig.MinVersion {
		c.TLSConfig.MinVersion = c.TLSConfig.MaxVersion
	}

	c.ModifiedTLSConfig = true

	// Return modified copy of tls.Config
	return c.TLSConfig, nil
}
