// Package tlspin implements certificate pinning for servers that use a
// self-signed certificate.
//
// A pin is the SHA-256 of the certificate's public key (its
// SubjectPublicKeyInfo), written "sha256:<base64url>". A client that was
// given a pin trusts exactly the server holding that key and nothing else,
// which is stronger than trusting every certificate authority and works for
// servers reachable only by IP address, where no public authority will
// issue a certificate.
package tlspin

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
)

const prefix = "sha256:"

// Of returns the pin of a certificate.
func Of(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return prefix + base64.RawURLEncoding.EncodeToString(sum[:])
}

// Valid reports whether s is a well-formed pin.
func Valid(s string) bool {
	raw, ok := strings.CutPrefix(s, prefix)
	if !ok {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	return err == nil && len(b) == sha256.Size
}

// ErrMismatch is returned when the server's key does not match the pin.
var ErrMismatch = errors.New("the server's certificate does not match the pinned fingerprint")

// Config returns a TLS client configuration that accepts only a server
// presenting the pinned key. Certificate-authority and host-name checks are
// replaced by the pin comparison, not merely skipped.
func Config(pin string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Verification is done in VerifyConnection below, against the pin.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return ErrMismatch
			}
			if subtle.ConstantTimeCompare([]byte(Of(cs.PeerCertificates[0])), []byte(pin)) != 1 {
				return ErrMismatch
			}
			return nil
		},
	}
}
