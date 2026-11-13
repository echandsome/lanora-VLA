package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"lanora/internal/server/config"
	"lanora/internal/tlspin"
)

// tlsSetup is the outcome of preparing TLS for the configured mode.
type tlsSetup struct {
	config *tls.Config  // nil when TLS is off
	pin    string       // certificate pin clients need (self-signed mode only)
	acme   http.Handler // HTTP-01 challenge handler (autocert mode only)
}

func prepareTLS(cfg *config.Config) (tlsSetup, error) {
	switch cfg.TLSMode {
	case config.TLSOff:
		return tlsSetup{}, nil

	case config.TLSFiles:
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return tlsSetup{}, fmt.Errorf("loading TLS certificate: %w", err)
		}
		return tlsSetup{config: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}}, nil

	case config.TLSAutocert:
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.TLSDomains...),
			Cache:      autocert.DirCache(filepath.Join(cfg.DataDir, "acme")),
			Email:      cfg.ACMEEmail,
		}
		tc := m.TLSConfig()
		tc.MinVersion = tls.VersionTLS12
		tc.NextProtos = append([]string{"h2", "http/1.1"}, acme.ALPNProto)
		return tlsSetup{config: tc, acme: m.HTTPHandler(nil)}, nil

	case config.TLSSelfSigned:
		cert, err := loadOrCreateSelfSigned(filepath.Join(cfg.DataDir, "tls"))
		if err != nil {
			return tlsSetup{}, err
		}
		return tlsSetup{
			config: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}},
			pin:    tlspin.Of(cert.Leaf),
		}, nil
	}
	return tlsSetup{}, fmt.Errorf("unknown TLS mode %q", cfg.TLSMode)
}

// SelfSignedPin returns the pin of the server's self-signed certificate,
// creating the certificate if the server has not started yet. Clients need
// it as part of the server address.
func SelfSignedPin(cfg *config.Config) (string, error) {
	if cfg.TLSMode != config.TLSSelfSigned {
		return "", fmt.Errorf("the server is configured with LANORA_TLS=%s; only a self-signed certificate needs a pin", cfg.TLSMode)
	}
	cert, err := loadOrCreateSelfSigned(filepath.Join(cfg.DataDir, "tls"))
	if err != nil {
		return "", err
	}
	return tlspin.Of(cert.Leaf), nil
}

// loadOrCreateSelfSigned returns the server's self-signed certificate,
// generating and saving one on first use. The key is kept for the life of
// the installation, because clients pin it: replacing it would lock every
// client out until they were given the new pin.
func loadOrCreateSelfSigned(dir string) (tls.Certificate, error) {
	certPath, keyPath := filepath.Join(dir, "selfsigned.crt"), filepath.Join(dir, "selfsigned.key")
	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err == nil && time.Now().Before(cert.Leaf.NotAfter) {
			return cert, nil
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Lanora server"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(20, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert.Leaf, err = x509.ParseCertificate(der)
	return cert, err
}
