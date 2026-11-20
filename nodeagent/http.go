package nodeagent

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
)

func ServerTLS(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("no client CA certificates")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}, nil
}

// Handler must only be served behind ServerTLS; the command has no insecure mode.
func Handler(manager *Manager) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(manager.Status())
	})
	mux.HandleFunc("PUT /v1/deployment", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		var d Deployment
		if decoder.Decode(&d) != nil || decoder.Decode(new(any)) != io.EOF {
			http.Error(w, "invalid deployment body", http.StatusBadRequest)
			return
		}
		if err := manager.Apply(d); err != nil {
			if errors.Is(err, ErrConflict) {
				http.Error(w, "revision or node conflict", http.StatusConflict)
			} else {
				// Core parsing errors can contain credentials. Do not echo them.
				http.Error(w, "deployment was not applied", http.StatusUnprocessableEntity)
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(manager.Status())
	})
	return mux
}
