package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var uuidPattern = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)
var credentialPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

type Bootstrap struct {
	V            int    `json:"v"`
	SessionID    string `json:"sessionId"`
	EnrollmentID string `json:"enrollmentId"`
	BootstrapKey string `json:"bootstrapKey"`
	ExpiresAt    string `json:"expiresAt"`
	Origin       string `json:"origin"`
	InstanceID   string `json:"instanceId"`
	Epoch        string `json:"epoch"`
}

func (b Bootstrap) validate() error {
	u, e := url.Parse(b.Origin)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.String() != b.Origin {
		return errors.New("invalid HTTPS origin")
	}
	if b.V != 1 || !uuidPattern.MatchString(b.SessionID) || !uuidPattern.MatchString(b.EnrollmentID) || !uuidPattern.MatchString(b.InstanceID) || !uuidPattern.MatchString(b.Epoch) || !credentialPattern.MatchString(b.BootstrapKey) {
		return errors.New("invalid bootstrap identity")
	}
	_, e = time.Parse(time.RFC3339Nano, b.ExpiresAt)
	return e
}

type Enrollment struct {
	SessionID       string   `json:"sessionId"`
	EnrollmentID    string   `json:"enrollmentId"`
	DevicePublicKey string   `json:"devicePublicKey"`
	Account         string   `json:"account"`
	Home            string   `json:"home"`
	Shell           string   `json:"shell"`
	Platform        string   `json:"platform"`
	Host            string   `json:"host"`
	Port            int      `json:"port"`
	HostKeys        []string `json:"hostKeys"`
}

// Struct field order matches the existing JavaScript wire signature contract.
type Hello struct {
	ProtocolVersion int    `json:"protocolVersion"`
	DevicePublicKey string `json:"devicePublicKey"`
}

func wireJSON(v any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	err := e.Encode(v)
	// Match JSON.stringify, without changing literal backslash-u sequences.
	raw := bytes.TrimSuffix(b.Bytes(), []byte("\n"))
	var out bytes.Buffer
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\\' && i+1 < len(raw) {
			if i+6 <= len(raw) && (string(raw[i:i+6]) == `\u2028` || string(raw[i:i+6]) == `\u2029`) {
				if raw[i+5] == '8' {
					out.WriteRune('\u2028')
				} else {
					out.WriteRune('\u2029')
				}
				i += 5
			} else {
				out.Write(raw[i : i+2])
				i++
			}
		} else {
			out.WriteByte(raw[i])
		}
	}
	return out.Bytes(), err
}
func strictJSON(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}
func devicePair() (string, string, error) {
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return "", "", e
	}
	pr, e := x509.MarshalPKCS8PrivateKey(priv)
	if e != nil {
		return "", "", e
	}
	pu, e := x509.MarshalPKIXPublicKey(pub)
	if e != nil {
		return "", "", e
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pr})), string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pu})), nil
}
func deviceSignature(s *State, operation, nonce string, body any) (string, error) {
	block, _ := pem.Decode([]byte(s.DevicePrivateKey))
	if block == nil {
		return "", errors.New("device key unavailable")
	}
	key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return "", e
	}
	private, ok := key.(ed25519.PrivateKey)
	if !ok {
		return "", errors.New("wrong device key type")
	}
	message, e := wireJSON([]any{1, operation, s.Bootstrap.InstanceID, s.Bootstrap.Epoch, s.Bootstrap.SessionID, nonce, body})
	if e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, message)), nil
}
func digest(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
func randomID() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}

type APIError struct {
	Status int
	Code   string
}

func (e *APIError) Error() string { return fmt.Sprintf("S端请求失败 (%d, %s)", e.Status, e.Code) }

type DeviceAPI struct {
	State  *State
	Client *http.Client
}

func (a DeviceAPI) post(path string, body, result any) error {
	if e := a.State.Bootstrap.validate(); e != nil {
		return e
	}
	if !strings.HasPrefix(path, "/api/v1/device/") {
		return errors.New("invalid API path")
	}
	data, e := wireJSON(body)
	if e != nil {
		return e
	}
	req, e := http.NewRequest("POST", a.State.Bootstrap.Origin+path, bytes.NewReader(data))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	client := a.Client
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = a.State.tlsConfig
		client = &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
		defer transport.CloseIdleConnections()
	}
	response, e := client.Do(req)
	if e != nil {
		return e
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, 32769))
	if e != nil {
		return e
	}
	if len(raw) > 32768 {
		return errors.New("API response too large")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var problem struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(raw, &problem)
		return &APIError{response.StatusCode, problem.Error.Code}
	}
	if result == nil {
		return nil
	}
	return strictJSON(raw, result)
}
func (a DeviceAPI) perform(operation string, body map[string]any, result any) error {
	var challenge struct {
		Nonce      string `json:"nonce"`
		V          int    `json:"v"`
		InstanceID string `json:"instanceId"`
		Epoch      string `json:"epoch"`
	}
	s := a.State
	if e := a.post("/api/v1/device/challenge", map[string]any{"sessionId": s.Bootstrap.SessionID, "operation": operation}, &challenge); e != nil {
		return e
	}
	if challenge.V != 1 || challenge.InstanceID != s.Bootstrap.InstanceID || challenge.Epoch != s.Bootstrap.Epoch || !credentialPattern.MatchString(challenge.Nonce) {
		return errors.New("S端实例身份改变；访问冻结")
	}
	if body == nil {
		body = map[string]any{}
	}
	signature, e := deviceSignature(s, operation, challenge.Nonce, body)
	if e != nil {
		return e
	}
	payload := map[string]any{"sessionId": s.Bootstrap.SessionID, "nonce": challenge.Nonce, "signature": signature}
	for k, v := range body {
		payload[k] = v
	}
	return a.post("/api/v1/device/"+operation, payload, result)
}
