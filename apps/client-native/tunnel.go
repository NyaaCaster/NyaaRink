package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/websocket"
	"io"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type controlMessage struct {
	V          int             `json:"v"`
	ID         string          `json:"id"`
	Epoch      string          `json:"epoch"`
	SessionID  string          `json:"sessionId"`
	Generation int             `json:"generation"`
	Type       string          `json:"type"`
	Payload    json.RawMessage `json:"payload"`
}

func socketURL(s *State, path string) string {
	return "wss://" + strings.TrimPrefix(s.Bootstrap.Origin, "https://") + path
}
func runTunnel(ctx context.Context, dir string, s *State) error {
	failures := 0
	for ctx.Err() == nil && !revoked(dir) {
		if e := verifyRelease(s.Runtime); e != nil {
			return e
		}
		daemon, e := startLocal(dir, s)
		if e != nil {
			return e
		}
		connected := false
		e = controlSessionReady(ctx, dir, s, func() { connected = true })
		daemon.stop()
		if connected {
			failures = 0
		}
		if revoked(dir) {
			return cleanupLocal(dir, s)
		}
		if ctx.Err() != nil {
			return nil
		}
		if e != nil {
			fmt.Println("连接中断，授权保留，稍后重连")
		}
		wait := time.Second * time.Duration(1<<min(failures, 5))
		if wait > 30*time.Second {
			wait = 30 * time.Second
		}
		failures++
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
	if revoked(dir) {
		return cleanupLocal(dir, s)
	}
	return nil
}
func controlSession(ctx context.Context, dir string, s *State) error {
	return controlSessionReady(ctx, dir, s, func() {})
}
func controlSessionReady(ctx context.Context, dir string, s *State, ready func()) error {
	dialer := websocket.Dialer{Proxy: http.ProxyFromEnvironment, HandshakeTimeout: 15 * time.Second, EnableCompression: false, TLSClientConfig: s.tlsConfig}
	ws, response, e := dialer.DialContext(ctx, socketURL(s, "/api/v1/device/control"), nil)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if e != nil {
		return e
	}
	defer ws.Close()
	ws.SetReadLimit(32768)
	var writes sync.Mutex
	generation := 0
	phase := "challenge"
	hello := Hello{1, s.DevicePublicKey}
	send := func(kind string, body any) error {
		payload, e := wireJSON(body)
		if e != nil {
			return e
		}
		message := controlMessage{1, randomID(), s.Bootstrap.Epoch, s.Bootstrap.SessionID, generation, kind, payload}
		writes.Lock()
		defer writes.Unlock()
		_ = ws.SetWriteDeadline(time.Now().Add(15 * time.Second))
		return ws.WriteJSON(message)
	}
	if e = send("hello", hello); e != nil {
		return e
	}
	streamsCtx, cancel := context.WithCancel(ctx)
	var streams atomic.Int32
	var workers sync.WaitGroup
	var ids sync.Map
	defer func() { cancel(); workers.Wait() }()
	bandwidth := newBandwidth(10 * 1024 * 1024)
	go func() { <-streamsCtx.Done(); ws.Close() }()
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-watchDone:
				return
			case <-ticker.C:
				if revoked(dir) {
					ws.Close()
					return
				}
			}
		}
	}()
	for {
		_ = ws.SetReadDeadline(time.Now().Add(45 * time.Second))
		kind, data, e := ws.ReadMessage()
		if e != nil {
			return e
		}
		if kind != websocket.TextMessage {
			return errors.New("unexpected binary control")
		}
		var input controlMessage
		if e = strictJSON(data, &input); e != nil {
			return e
		}
		if input.V != 1 || !uuidPattern.MatchString(input.ID) || input.Epoch != s.Bootstrap.Epoch || input.SessionID != s.Bootstrap.SessionID || input.Generation < 0 {
			return errors.New("control identity mismatch")
		}
		if phase == "challenge" {
			var challenge struct {
				Nonce      string `json:"nonce"`
				InstanceID string `json:"instanceId"`
			}
			if input.Type != "challenge" || input.Generation != 0 {
				return errors.New("challenge expected")
			}
			if e = strictJSON(input.Payload, &challenge); e != nil {
				return e
			}
			if challenge.InstanceID != s.Bootstrap.InstanceID || !credentialPattern.MatchString(challenge.Nonce) {
				return errors.New("challenge identity mismatch")
			}
			signature, e := deviceSignature(s, "control", challenge.Nonce, hello)
			if e != nil {
				return e
			}
			if e = send("auth", map[string]any{"nonce": challenge.Nonce, "signature": signature}); e != nil {
				return e
			}
			phase = "ready"
			continue
		}
		if phase == "ready" {
			if input.Type != "ready" && input.Type != "revoke" {
				return errors.New("ready expected")
			}
			if input.Generation < 1 && input.Type != "revoke" {
				return errors.New("invalid control generation")
			}
			generation = input.Generation
			phase = "active"
			if input.Type == "ready" {
				var initial struct {
					Stage string `json:"stage"`
				}
				if e = strictJSON(input.Payload, &initial); e != nil || initial.Stage != "transport" {
					return errors.New("transport ready expected")
				}
				if e = send("ready", map[string]any{"stage": "local"}); e != nil {
					return e
				}
				continue
			}
		}
		if input.Generation != generation || revoked(dir) {
			return errors.New("stale generation")
		}
		switch input.Type {
		case "revoke":
			if strictJSON(input.Payload, &struct{}{}) != nil || string(input.Payload) == "null" {
				return errors.New("invalid revoke")
			}
			if e = durableWrite(filepathJoin(dir, "revoked"), []byte("{\"revoked\":true}")); e != nil {
				return e
			}
			return nil
		case "ping":
			var ping struct {
				Timestamp float64 `json:"timestamp"`
			}
			if e = strictJSON(input.Payload, &ping); e != nil || ping.Timestamp < 0 || math.IsNaN(ping.Timestamp) || math.IsInf(ping.Timestamp, 0) {
				return errors.New("invalid ping")
			}
			if e = send("pong", ping); e != nil {
				return e
			}
		case "ready":
			if e = validateReady(input.Payload); e != nil {
				return e
			}
			var stage struct {
				Stage string `json:"stage"`
			}
			_ = json.Unmarshal(input.Payload, &stage)
			if stage.Stage != "verified" || phase != "active" {
				return errors.New("unexpected ready stage")
			}
			phase = "verified"
			ready()
		case "error":
			var problem struct {
				StreamID string `json:"streamId,omitempty"`
				Code     string `json:"code"`
			}
			if e = strictJSON(input.Payload, &problem); e != nil || len(problem.Code) > 64 || (problem.StreamID != "" && !uuidPattern.MatchString(problem.StreamID)) {
				return errors.New("invalid error payload")
			}
		case "open":
			var open struct {
				StreamID string `json:"streamId"`
				Ticket   string `json:"ticket"`
			}
			if e = strictJSON(input.Payload, &open); e != nil {
				return e
			}
			if !uuidPattern.MatchString(open.StreamID) || !credentialPattern.MatchString(open.Ticket) {
				return errors.New("invalid stream")
			}
			// S verifies SSH through a stream before sending the verified stage.
			if _, loaded := ids.LoadOrStore(open.StreamID, true); loaded {
				return errors.New("duplicate stream ID")
			}
			if streams.Add(1) > 4 {
				streams.Add(-1)
				ids.Delete(open.StreamID)
				_ = send("error", map[string]any{"streamId": open.StreamID, "code": "LIMIT_EXCEEDED"})
				continue
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer streams.Add(-1)
				defer ids.Delete(open.StreamID)
				_ = bridgeStream(streamsCtx, dir, s, open.StreamID, open.Ticket, bandwidth)
			}()
		default:
			return errors.New("unexpected control message")
		}
	}
}
func validateReady(payload []byte) error {
	var ready struct {
		Stage string `json:"stage"`
	}
	if strictJSON(payload, &ready) != nil || (ready.Stage != "transport" && ready.Stage != "local" && ready.Stage != "verified") {
		return errors.New("invalid ready payload")
	}
	return nil
}

// Shared across both directions and all four streams. Synchronous reads/writes
// bound userspace buffering to one 64 KiB chunk per direction per stream.
type bandwidthBudget struct {
	sync.Mutex
	rate   float64
	tokens float64
	at     time.Time
}

func newBandwidth(rate int) *bandwidthBudget {
	return &bandwidthBudget{rate: float64(rate), tokens: float64(rate), at: time.Now()}
}
func (b *bandwidthBudget) wait(ctx context.Context, size int) error {
	b.Lock()
	now := time.Now()
	b.tokens = math.Min(b.rate, b.tokens+now.Sub(b.at).Seconds()*b.rate) - float64(size)
	b.at = now
	delay := time.Duration(math.Max(0, -b.tokens/b.rate) * float64(time.Second))
	b.Unlock()
	if delay == 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func bridgeStream(ctx context.Context, dir string, s *State, id, ticket string, bandwidth *bandwidthBudget) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if s.Enrollment == nil || revoked(dir) {
		return errors.New("local access unavailable")
	}
	local := s.Enrollment
	if local.Host != "127.0.0.1" && local.Host != "::1" {
		return errors.New("non-loopback target refused")
	}
	dialer := websocket.Dialer{Proxy: http.ProxyFromEnvironment, HandshakeTimeout: 15 * time.Second, EnableCompression: false, TLSClientConfig: s.tlsConfig}
	ws, response, e := dialer.DialContext(ctx, socketURL(s, "/api/v1/device/streams/"+id), http.Header{"Authorization": []string{"Bearer " + ticket}})
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if e != nil {
		return e
	}
	defer ws.Close()
	ws.SetReadLimit(256 * 1024)
	socket, e := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(local.Host, fmt.Sprint(local.Port)))
	if e != nil {
		return e
	}
	defer socket.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			ws.Close()
			socket.Close()
		case <-done:
		}
	}()
	writerDone := make(chan struct{})
	defer func() { cancel(); socket.Close(); ws.Close(); <-writerDone }()
	go func() {
		defer close(writerDone)
		buffer := make([]byte, 64*1024)
		for {
			n, e := socket.Read(buffer)
			if n > 0 {
				if x := bandwidth.wait(ctx, n); x != nil {
					ws.Close()
					return
				}
				_ = ws.SetWriteDeadline(time.Now().Add(45 * time.Second))
				if x := ws.WriteMessage(websocket.BinaryMessage, buffer[:n]); x != nil {
					ws.Close()
					return
				}
			}
			if e != nil {
				ws.Close()
				return
			}
		}
	}()
	for {
		kind, reader, e := ws.NextReader()
		if e != nil {
			return e
		}
		if kind != websocket.BinaryMessage {
			return errors.New("unexpected text data")
		}
		if revoked(dir) {
			return errors.New("authorization revoked")
		}
		if _, e = io.CopyBuffer(pacedWriter{ctx, socket, bandwidth}, reader, make([]byte, 64*1024)); e != nil {
			return e
		}
	}
}

type pacedWriter struct {
	ctx    context.Context
	socket net.Conn
	budget *bandwidthBudget
}

func (w pacedWriter) Write(p []byte) (int, error) {
	if e := w.budget.wait(w.ctx, len(p)); e != nil {
		return 0, e
	}
	_ = w.socket.SetWriteDeadline(time.Now().Add(45 * time.Second))
	return w.socket.Write(p)
}
