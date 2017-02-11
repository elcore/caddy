package caddytls

import (
	"crypto/tls"
	"reflect"
	"testing"
)

var (
	config = &Config{
		TLSConfig: &tls.Config{
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
		},
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
	c := *config

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

	output, err := c.PreferChaChaIfFirst(clientHello)
	if err != nil {
		t.Fatalf("Did not expect an error, but got %v", err)
	}
	if output == nil {
		t.Fatalf("Expected a modified tls.Config")
	}

	if !reflect.DeepEqual(output, expectedTLSConfig) {
		for i, actual := range output.CipherSuites {
			if actual != expectedTLSConfig.CipherSuites[i] {
				t.Errorf("Expected ciphers in position %d to be %v, got %v", i, expectedTLSConfig.CipherSuites[i], actual)
			}
		}
		if got, want := output.MinVersion, expectedTLSConfig.MinVersion; got != want {
			t.Errorf("Expected min version to be %x, got %x", want, got)
		}
		if got, want := output.MaxVersion, expectedTLSConfig.MaxVersion; got != want {
			t.Errorf("Expected max version to be %x, got %x", want, got)
		}
	}

	if !c.ModifiedTLSConfig {
		t.Fatal("config.ModifiedTLSConfig should be true")
	}
}

func TestPreferChaChaIfFirstWithoutGREASE(t *testing.T) {
	c := *config

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

	output, err := c.PreferChaChaIfFirst(clientHello)
	if err != nil {
		t.Fatalf("Did not expect an error, but got %v", err)
	}
	if output == nil {
		t.Fatalf("Expected a modified tls.Config")
	}

	if !reflect.DeepEqual(output, expectedTLSConfig) {
		for i, actual := range output.CipherSuites {
			if actual != expectedTLSConfig.CipherSuites[i] {
				t.Errorf("Expected ciphers in position %d to be %v, got %v", i, expectedTLSConfig.CipherSuites[i], actual)
			}
		}
		if got, want := output.MinVersion, expectedTLSConfig.MinVersion; got != want {
			t.Errorf("Expected min version to be %x, got %x", want, got)
		}
		if got, want := output.MaxVersion, expectedTLSConfig.MaxVersion; got != want {
			t.Errorf("Expected max version to be %x, got %x", want, got)
		}
	}

	if !c.ModifiedTLSConfig {
		t.Fatal("config.ModifiedTLSConfig should be true")
	}
}

func TestPreferChaChaIfFirstWithoutChaCha(t *testing.T) {
	c := *config

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

	output, err := c.PreferChaChaIfFirst(clientHello)
	if err != nil {
		t.Fatalf("Did not expect an error, but got %v", err)
	}
	if output != nil {
		t.Fatalf("Expected an unmodified tls.Config")
	}

	if c.ModifiedTLSConfig {
		t.Fatal("config.ModifiedTLSConfig should be false")
	}
}
