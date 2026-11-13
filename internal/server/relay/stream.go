package relay

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"lanora/internal/proto"
)

// Stream relay
//
// Some networks drop UDP entirely. For those, a client can reach the relay
// over a WebSocket on the server's HTTPS port instead. Each binary message
// is one relayed packet: four bytes naming the peer (destination when sent
// by the client, source when sent by the relay) followed by the payload.
// The relay bridges freely between UDP-bound and stream-bound members.
//
// TCP adds head-of-line blocking, so this is strictly a last resort; clients
// keep trying UDP and switch back as soon as it works.

const (
	streamQueue       = 512
	streamIdleTimeout = 60 * time.Second
	streamWriteWait   = 10 * time.Second
)

// streamPeer is the outbound side of a stream-connected client: a bounded
// queue drained by one writer goroutine. When the queue is full packets are
// dropped, exactly as a congested network link would, rather than letting a
// slow client stall the relay or grow memory without bound.
type streamPeer struct {
	queue chan []byte
	done  chan struct{}
	once  sync.Once
}

func newStreamPeer() *streamPeer {
	return &streamPeer{queue: make(chan []byte, streamQueue), done: make(chan struct{})}
}

// enqueue queues a copy of msg, reporting false if it had to be dropped.
func (sp *streamPeer) enqueue(msg []byte) bool {
	cp := make([]byte, len(msg))
	copy(cp, msg)
	select {
	case sp.queue <- cp:
		return true
	default:
		return false
	}
}

func (sp *streamPeer) close() { sp.once.Do(func() { close(sp.done) }) }

// authorizeStream validates the bearer ticket of a stream bind.
func (r *Relay) authorizeStream(req *http.Request) (proto.Claims, bool) {
	bearer, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
	if !ok || len(bearer) > 256 {
		return proto.Claims{}, false
	}
	c, k, ok := strings.Cut(bearer, ".")
	if !ok {
		return proto.Claims{}, false
	}
	enc := base64.RawURLEncoding
	claimBytes, err := enc.DecodeString(c)
	if err != nil || len(claimBytes) != proto.ClaimsLen {
		return proto.Claims{}, false
	}
	key, err := enc.DecodeString(k)
	if err != nil {
		return proto.Claims{}, false
	}
	if !hmac.Equal(key, proto.RelaySessionKey(r.opts.Secret, claimBytes)) {
		return proto.Claims{}, false
	}
	claims, err := proto.ParseClaims(claimBytes)
	if err != nil || claims.Expiry <= time.Now().Unix() || r.ticketRevoked(claims) {
		return proto.Claims{}, false
	}
	return claims, true
}

// ServeHTTP upgrades the request to a WebSocket and relays over it.
func (r *Relay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	claims, ok := r.authorizeStream(req)
	if !ok {
		r.bindsBad.Add(1)
		http.Error(w, "invalid relay ticket", http.StatusUnauthorized)
		return
	}
	s := r.bind(claims, time.Now().Unix())
	if s == nil {
		r.bindsBad.Add(1)
		http.Error(w, "relay is at capacity", http.StatusServiceUnavailable)
		return
	}
	conn, err := websocket.Accept(w, req, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(maxDatagram)
	r.bindsOK.Add(1)

	sp := newStreamPeer()
	if old := s.stream.Swap(sp); old != nil {
		old.close()
	}
	// A client only opens the stream when its UDP bind has stopped being
	// answered, so any UDP address still on record for it is stale. Forget
	// it, or packets for the client would keep going there instead of down
	// the stream. A later successful UDP bind records the address again.
	if ap := s.addr.Swap(nil); ap != nil {
		r.byAddr.CompareAndDelete(*ap, s)
	}
	defer func() {
		sp.close()
		if s.stream.CompareAndSwap(sp, nil) && s.addr.Load() == nil {
			r.remove(s)
		}
	}()

	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()

	// Writer: drains the queue until the peer is closed.
	go func() {
		defer cancel()
		for {
			select {
			case <-ctx.Done():
				return
			case <-sp.done:
				return
			case <-r.closed:
				return
			case msg := <-sp.queue:
				wctx, wcancel := context.WithTimeout(ctx, streamWriteWait)
				err := conn.Write(wctx, websocket.MessageBinary, msg)
				wcancel()
				if err != nil {
					return
				}
			}
		}
	}()

	// A client that sends nothing for a while (not even the empty keepalive
	// message) is gone.
	idle := time.AfterFunc(streamIdleTimeout, cancel)
	defer idle.Stop()

	// Reader: every message becomes a relay frame handled by the same code
	// path as UDP. The buffer keeps two spare bytes in front for the frame
	// header.
	buf := make([]byte, proto.HeaderLen+maxDatagram)
	udp := r.conns[0]
	for {
		typ, rd, err := conn.Reader(ctx)
		if err != nil {
			return
		}
		n, err := io.ReadFull(rd, buf[proto.HeaderLen:])
		if err != io.ErrUnexpectedEOF && err != io.EOF {
			return // message larger than a datagram, or a read error
		}
		idle.Reset(streamIdleTimeout)
		s.lastSeen.Store(r.now.Load())
		if typ != websocket.MessageBinary || n < proto.PeerIDLen {
			continue // keepalive
		}
		if s.expiry.Load() <= r.now.Load() {
			conn.Close(websocket.StatusPolicyViolation, "ticket expired")
			return
		}
		frame := buf[:proto.HeaderLen+n]
		frame[0], frame[1] = proto.Magic, proto.FrameRelaySend
		r.route(udp, s, frame)
	}
}
