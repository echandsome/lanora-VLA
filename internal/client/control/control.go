// Package control is the client's connection to the Lanora server: the
// HTTPS API used to join a room and the WebSocket that carries signalling
// for the rest of the session.
package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/coder/websocket"

	"lanora/internal/client/transport"
	"lanora/internal/proto"
	"lanora/internal/tlspin"
	"lanora/internal/version"
)

// Address is a parsed server address.
type Address struct {
	Base *url.URL // scheme://host[:port], no path
	Pin  string   // certificate pin, or "" to verify against the system's trusted authorities
}

// ParseAddress interprets what a user types as the server address. It
// accepts a bare host ("lan.example.com", "203.0.113.5:8443") or a URL, and
// an optional certificate pin as the URL fragment, which is how the address
// of a server with a self-signed certificate is shared:
//
//	https://203.0.113.5:8443/#pin=sha256:...
//
// HTTPS is assumed. Plain HTTP is accepted only for a server on this
// machine, where it is used for testing; a room password is never sent in
// clear over a network.
func ParseAddress(s string) (Address, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Address{}, errors.New("enter the server address")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return Address{}, errors.New("the server address is not valid")
	}
	var a Address
	if frag := u.Fragment; frag != "" {
		pin, ok := strings.CutPrefix(frag, "pin=")
		if !ok || !tlspin.Valid(pin) {
			return Address{}, errors.New("the certificate pin in the server address is not valid")
		}
		a.Pin = pin
	}
	switch u.Scheme {
	case "https":
	case "http":
		if host := u.Hostname(); host != "localhost" {
			if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
				return Address{}, errors.New("the server address must start with https://")
			}
		}
		if a.Pin != "" {
			return Address{}, errors.New("a certificate pin needs an https:// address")
		}
	default:
		return Address{}, errors.New("the server address must start with https://")
	}
	if u.User != nil {
		return Address{}, errors.New("the server address must not contain a user name")
	}
	a.Base = &url.URL{Scheme: u.Scheme, Host: u.Host}
	return a, nil
}

// String returns the canonical form of the address.
func (a Address) String() string {
	s := a.Base.String()
	if a.Pin != "" {
		s += "/#pin=" + a.Pin
	}
	return s
}

// Client talks to one server on behalf of one device identity.
type Client struct {
	addr     Address
	identity ed25519.PrivateKey
	tls      *tls.Config
	http     *http.Client

	// Header is added to every request. The load generator uses it to give
	// each simulated client its own forwarded address, so that per-address
	// rate limits apply to them as they would to clients on different
	// networks.
	Header http.Header
}

// New returns a client for the server at addr.
func New(addr Address, identity ed25519.PrivateKey) *Client {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if addr.Pin != "" {
		tlsCfg = tlspin.Config(addr.Pin)
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return &Client{
		addr:     addr,
		identity: identity,
		tls:      tlsCfg,
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				DialContext:           dialer.DialContext,
				TLSClientConfig:       tlsCfg,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 20 * time.Second,
				MaxIdleConns:          4,
				IdleConnTimeout:       60 * time.Second,
				ForceAttemptHTTP2:     true,
			},
		},
	}
}

// Host returns the server's host name or IP address without the port.
func (c *Client) Host() string { return c.addr.Base.Hostname() }

// Close releases idle connections.
func (c *Client) Close() { c.http.CloseIdleConnections() }

func (c *Client) url(path string) string { return c.addr.Base.String() + path }

// do performs a JSON request and decodes the response into out.
func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.url(path), body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "Lanora/"+version.Version)
	for k, v := range c.Header {
		req.Header[k] = v
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return describeNetError(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return describeNetError(err)
	}
	if resp.StatusCode/100 != 2 {
		return apiError(resp.StatusCode, raw)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return errors.New("the server sent a reply this version of Lanora does not understand")
	}
	return nil
}

// apiError converts an error response into a *proto.APIError.
func apiError(status int, body []byte) error {
	var er proto.ErrorResponse
	if err := json.Unmarshal(body, &er); err != nil || er.Error.Code == "" {
		// Not a Lanora error body: a proxy's error page, or not a Lanora
		// server at all.
		return &proto.APIError{Status: status, ErrorBody: proto.ErrorBody{
			Code:    proto.CodeServerError,
			Message: fmt.Sprintf("The server answered with an unexpected error (HTTP %d). Check the server address.", status),
		}}
	}
	return &proto.APIError{Status: status, ErrorBody: er.Error}
}

// TrustError reports that the server's identity could not be verified.
// Retrying cannot help, and nothing confidential was sent.
type TrustError struct{ msg string }

func (e *TrustError) Error() string { return e.msg }

// describeNetError turns low-level connection failures into messages a
// user can act on.
func describeNetError(err error) error {
	var dnsErr *net.DNSError
	var certErr *tls.CertificateVerificationError
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, tlspin.ErrMismatch):
		return &TrustError{"The server's certificate does not match the pin in the server address. Check that the address is complete and correct."}
	case errors.As(err, &certErr):
		return &TrustError{"The server's certificate is not trusted. If the server uses a self-signed certificate, the server address must include its pin (…/#pin=sha256:…)."}
	case errors.As(err, &dnsErr):
		return errors.New("The server's name could not be found. Check the server address and your internet connection.")
	case errors.Is(err, context.DeadlineExceeded) || isTimeout(err):
		return errors.New("The server did not answer in time. Check the server address and your internet connection.")
	}
	return fmt.Errorf("Could not reach the server: %w", unwrapURLError(err))
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func unwrapURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// Hello asks the server for its version and a join nonce.
func (c *Client) Hello(ctx context.Context) (proto.HelloResponse, error) {
	var out proto.HelloResponse
	err := c.do(ctx, http.MethodGet, proto.PathHello, nil, &out)
	return out, err
}

// Join authenticates to a room. On success the response carries the session
// token and the virtual network parameters.
func (c *Client) Join(ctx context.Context, roomID, password, nickname string) (proto.JoinResponse, error) {
	var out proto.JoinResponse
	id, err := proto.NormalizeRoomID(roomID)
	if err != nil {
		return out, &proto.APIError{Status: http.StatusBadRequest, ErrorBody: proto.ErrorBody{
			Code: proto.CodeBadRequest, Message: "A room ID is 9 letters and digits, for example 7KQ-2MX-9DW.",
		}}
	}
	hello, err := c.Hello(ctx)
	if err != nil {
		return out, err
	}
	if hello.Protocol != version.Protocol {
		msg := "This server is older than your Lanora app and does not support it yet."
		if hello.Protocol > version.Protocol {
			msg = "This version of Lanora is too old for this server. Please update the app."
		}
		return out, &proto.APIError{Status: http.StatusUpgradeRequired, ErrorBody: proto.ErrorBody{Code: proto.CodeClientTooOld, Message: msg}}
	}
	var identity proto.Key32
	copy(identity[:], c.identity.Public().(ed25519.PublicKey))
	req := proto.JoinRequest{
		RoomID:        id,
		Password:      password,
		Nickname:      nickname,
		Identity:      identity,
		Nonce:         hello.Nonce,
		Signature:     ed25519.Sign(c.identity, proto.JoinTranscript(hello.Nonce, id, identity)),
		ClientVersion: version.Version,
		Protocol:      version.Protocol,
		Platform:      runtime.GOOS + "/" + runtime.GOARCH,
	}
	err = c.do(ctx, http.MethodPost, proto.PathJoin, req, &out)
	return out, err
}

// Session is an open signalling connection.
type Session struct {
	conn *websocket.Conn
}

// OpenSession connects the signalling WebSocket and sends the hello message.
func (c *Client) OpenSession(ctx context.Context, token string, hello proto.Msg) (*Session, error) {
	conn, err := c.dialWS(ctx, proto.PathSession, "Bearer "+token)
	if err != nil {
		return nil, err
	}
	conn.SetReadLimit(proto.MaxServerMessage)
	s := &Session{conn: conn}
	hello.T = proto.MsgHello
	if err := s.Write(ctx, hello); err != nil {
		conn.CloseNow()
		return nil, describeNetError(err)
	}
	return s, nil
}

// dialWS opens a WebSocket on the server (or at an absolute URL).
func (c *Client) dialWS(ctx context.Context, target, authorization string) (*websocket.Conn, error) {
	u, err := c.addr.Base.Parse(target)
	if err != nil {
		return nil, err
	}
	// The WebSocket library dials http(s) URLs and upgrades them.
	switch u.Scheme {
	case "wss":
		u.Scheme = "https"
	case "ws":
		u.Scheme = "http"
	}
	header := http.Header{"Authorization": {authorization}, "User-Agent": {"Lanora/" + version.Version}}
	for k, v := range c.Header {
		header[k] = v
	}
	conn, resp, err := websocket.Dial(ctx, u.String(), &websocket.DialOptions{
		HTTPClient:      &http.Client{Transport: c.http.Transport},
		HTTPHeader:      header,
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		if resp != nil && resp.StatusCode != http.StatusSwitchingProtocols && resp.Body != nil {
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			return nil, apiError(resp.StatusCode, raw)
		}
		return nil, describeNetError(err)
	}
	return conn, nil
}

// Read returns the next signalling message.
func (s *Session) Read(ctx context.Context) (*proto.Msg, error) {
	typ, data, err := s.conn.Read(ctx)
	if err != nil {
		return nil, err
	}
	if typ != websocket.MessageText {
		return nil, errors.New("unexpected binary message on the signalling channel")
	}
	var m proto.Msg
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("malformed signalling message: %w", err)
	}
	return &m, nil
}

// Write sends a signalling message.
func (s *Session) Write(ctx context.Context, m proto.Msg) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.conn.Write(wctx, websocket.MessageText, data)
}

// Ping checks that the server is still there. A Read must be in progress on
// another goroutine for the reply to be noticed.
func (s *Session) Ping(ctx context.Context) error {
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.conn.Ping(pctx)
}

// Close ends the session.
func (s *Session) Close() { s.conn.CloseNow() }

// DialStream opens the TCP-fallback relay connection. It satisfies
// transport.StreamDialer.
func (c *Client) DialStream(ctx context.Context, target, authorization string) (transport.StreamConn, error) {
	conn, err := c.dialWS(ctx, target, authorization)
	if err != nil {
		return nil, err
	}
	conn.SetReadLimit(4096)
	return streamConn{conn}, nil
}

type streamConn struct{ conn *websocket.Conn }

func (s streamConn) Read(ctx context.Context) ([]byte, error) {
	_, data, err := s.conn.Read(ctx)
	return data, err
}

func (s streamConn) Write(ctx context.Context, msg []byte) error {
	return s.conn.Write(ctx, websocket.MessageBinary, msg)
}

func (s streamConn) Close() error { return s.conn.CloseNow() }
