package caddytls

import (
	"crypto/tls"
	"reflect"
	"testing"
)

var (
	config = &tls.Config{
		CipherSuites: []uint16{
			0xc02c,
			0xc030,
			0xc02b,
			0xc02f,
			0xcca9,
			0xcca8,
		},
		MinVersion: 0x0302,
		MaxVersion: 0x0303,
	}

	expectedTLSConfig = &tls.Config{
		CipherSuites: []uint16{
			0xcca9,
			0xcca8,
			0xc02c,
			0xc030,
			0xc02b,
			0xc02f,
		},
		MinVersion: 0x0303,
		MaxVersion: 0x0303,
	}
)

func TestPreferChaChaIfFirstWithGREASE(t *testing.T) {
	clientHello := &tls.ClientHelloInfo{
		CipherSuites: []uint16{
			0x0A0A,
			0xcca9,
			0xcca8,
			0xc02c,
			0xc030,
			0xc02b,
			0xc02f,
		},
		SupportedVersions: []uint16{
			0x0303,
			0x0302,
		},
	}

	rTLS, reordered := preferChaChaIfFirst(config, clientHello)

	if !reordered {
		t.Fatalf("Expected a successful reorder of cipher suites")
	}

	if !reflect.DeepEqual(rTLS, expectedTLSConfig) {
		for i, actual := range rTLS.CipherSuites {
			if actual != expectedTLSConfig.CipherSuites[i] {
				t.Errorf("Expected ciphers in position %d to be %v, got %v", i, expectedTLSConfig.CipherSuites[i], actual)
			}
		}
		if got, want := rTLS.MinVersion, expectedTLSConfig.MinVersion; got != want {
			t.Errorf("Expected min version to be %x, got %x", want, got)
		}
		if got, want := rTLS.MaxVersion, expectedTLSConfig.MaxVersion; got != want {
			t.Errorf("Expected max version to be %x, got %x", want, got)
		}
	}
}

func TestPreferChaChaIfFirstWithoutGREASE(t *testing.T) {
	clientHello := &tls.ClientHelloInfo{
		CipherSuites: []uint16{
			0xcca9,
			0xcca8,
			0xc02c,
			0xc030,
			0xc02b,
			0xc02f,
		},
		SupportedVersions: []uint16{
			0x0303,
			0x0302,
		},
	}

	rTLS, reordered := preferChaChaIfFirst(config, clientHello)

	if !reordered {
		t.Fatalf("Expected a successful reorder of cipher suites")
	}

	if !reflect.DeepEqual(rTLS, expectedTLSConfig) {
		for i, actual := range rTLS.CipherSuites {
			if actual != expectedTLSConfig.CipherSuites[i] {
				t.Errorf("Expected ciphers in position %d to be %v, got %v", i, expectedTLSConfig.CipherSuites[i], actual)
			}
		}
		if got, want := rTLS.MinVersion, expectedTLSConfig.MinVersion; got != want {
			t.Errorf("Expected min version to be %x, got %x", want, got)
		}
		if got, want := rTLS.MaxVersion, expectedTLSConfig.MaxVersion; got != want {
			t.Errorf("Expected max version to be %x, got %x", want, got)
		}
	}
}

func TestPreferChaChaIfFirstWithoutChaCha(t *testing.T) {
	clientHello := &tls.ClientHelloInfo{
		CipherSuites: []uint16{
			0x0A0A,
			0xc02c,
			0xc030,
			0xc02b,
			0xc02f,
		},
		SupportedVersions: []uint16{
			0x0303,
			0x0302,
		},
	}

	_, reordered := preferChaChaIfFirst(config, clientHello)

	if reordered {
		t.Fatalf("Didn't expect a successful reorder of cipher suites")
	}
}
