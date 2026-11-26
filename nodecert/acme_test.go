package nodecert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mholt/acmez/v3/acme"
)

func TestCertificatePinnedACMEHTTP01FlowAndArtifact(t *testing.T) {
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	requireNodeTestSuccess(t, err)
	root, _ = x509.ParseCertificate(rootDER)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	address := listener.Addr().String()
	listener.Close()
	solver := &HTTP01{Address: address}
	defer solver.Close()
	var authorized atomic.Bool
	var nonce atomic.Int64
	var chain string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", base64.RawURLEncoding.EncodeToString([]byte(big.NewInt(nonce.Add(1)).String())))
		w.Header().Set("Content-Type", "application/json")
		decode := func(target interface{}) {
			var envelope struct {
				Payload string `json:"payload"`
			}
			if json.NewDecoder(r.Body).Decode(&envelope) != nil {
				t.Error("invalid JWS envelope")
				return
			}
			body, _ := base64.RawURLEncoding.DecodeString(envelope.Payload)
			_ = json.Unmarshal(body, target)
		}
		order := func() map[string]interface{} {
			state := "pending"
			if authorized.Load() {
				state = "ready"
			}
			result := map[string]interface{}{"status": state, "identifiers": []map[string]string{{"type": "dns", "value": "node.example"}}, "authorizations": []string{server.URL + "/auth"}, "finalize": server.URL + "/finalize"}
			if chain != "" {
				result["status"], result["certificate"] = "valid", server.URL+"/cert"
			}
			return result
		}
		switch r.URL.Path {
		case "/directory":
			json.NewEncoder(w).Encode(map[string]string{"newNonce": server.URL + "/nonce", "newAccount": server.URL + "/account", "newOrder": server.URL + "/new-order"})
		case "/nonce":
			w.WriteHeader(204)
		case "/account":
			w.Header().Set("Location", server.URL+"/account/1")
			w.WriteHeader(201)
			io.WriteString(w, `{"status":"valid","orders":"/orders"}`)
		case "/new-order":
			w.Header().Set("Location", server.URL+"/order")
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(order())
		case "/auth":
			state := "pending"
			if authorized.Load() {
				state = "valid"
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"status": state, "identifier": map[string]string{"type": "dns", "value": "node.example"}, "challenges": []map[string]string{{"type": "http-01", "url": server.URL + "/challenge", "token": "fixture-token", "status": state}}})
		case "/challenge":
			req, _ := http.NewRequest("GET", "http://"+address+"/.well-known/acme-challenge/fixture-token", nil)
			req.Host = "node.example"
			response, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if !strings.HasPrefix(string(body), "fixture-token.") {
				t.Error("HTTP01 challenge not served")
			}
			authorized.Store(true)
			json.NewEncoder(w).Encode(map[string]string{"type": "http-01", "status": "valid", "url": server.URL + "/challenge", "token": "fixture-token"})
		case "/order":
			json.NewEncoder(w).Encode(order())
		case "/finalize":
			var request struct {
				CSR string `json:"csr"`
			}
			decode(&request)
			der, _ := base64.RawURLEncoding.DecodeString(request.CSR)
			csr, err := x509.ParseCertificateRequest(der)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: csr.DNSNames, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(12 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			der, err = x509.CreateCertificate(rand.Reader, leaf, root, csr.PublicKey, rootKey)
			if err != nil {
				t.Error(err)
			}
			chain = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))
			json.NewEncoder(w).Encode(order())
		case "/cert":
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			io.WriteString(w, chain)
		default:
			t.Error("unexpected ACME endpoint", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	key, _ := NewAccountKey()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	bundle, err := issue(ctx, &acme.Client{Directory: server.URL + "/directory", HTTPClient: server.Client(), PollInterval: time.Millisecond}, "", key, "node.example", "http-01", solver)
	requireNodeTestSuccess(t, err)
	if !authorized.Load() {
		t.Fatal("ACME skipped HTTP proof")
	}
	directory := t.TempDir()
	meta, err := Install(directory, bundle, "node.example", roots)
	requireNodeTestSuccess(t, err)
	if _, err := Validate(bundle, "wrong.example", roots, now); err == nil {
		t.Fatal("wrong hostname accepted")
	}
	if _, err := Validate(bundle, "node.example", nil, now); err == nil {
		t.Fatal("untrusted chain accepted")
	}
	for _, checkTime := range []time.Time{now.Add(-48 * time.Hour), now.Add(48 * time.Hour)} {
		if _, err := Validate(bundle, "node.example", roots, checkTime); err == nil || err.Error() != "certificate_expired_or_not_yet_valid" {
			t.Fatal("certificate validity period ignored", err)
		}
	}
	for _, name := range []string{meta.CertificatePath, meta.KeyPath} {
		info, err := os.Stat(filepath.Join(directory, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("artifact permissions", err)
		}
	}
	repeat, err := Install(directory, bundle, "node.example", roots)
	if err != nil || repeat.Digest != meta.Digest {
		t.Fatal("artifact not idempotent", err)
	}
}

func TestCertificateHTTP01BusyPortDoesNotReplaceListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	requireNodeTestSuccess(t, err)
	defer listener.Close()
	solver := &HTTP01{Address: listener.Addr().String()}
	defer solver.Close()
	err = solver.Present(context.Background(), acme.Challenge{Identifier: acme.Identifier{Value: "node.example"}, Token: "fixture-token", KeyAuthorization: "fixture-token.proof"})
	if err == nil || err.Error() != "http01_port_occupied" {
		t.Fatal("busy port accepted", err)
	}
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal("foreign listener stopped", err)
	}
	conn.Close()
}
