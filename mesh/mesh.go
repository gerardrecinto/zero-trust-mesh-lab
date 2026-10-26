package mesh

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/gerardrecinto/zero-trust-mesh-lab/ca"
)

type ctxKey struct{}

// Service is one workload: an identity, a TLS listener that demands a client
// certificate, and a guard that applies policy before the handler runs.
type Service struct {
	Name   string
	ID     string
	Source *ca.Source
	srv    *http.Server
	url    string
}

type Mesh struct {
	Auth   *ca.Authority
	Policy *Engine
	Audit  *Audit
	Now    func() time.Time
}

func (m *Mesh) serverTLS(src *ca.Source) *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: src.GetCertificate,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      m.Auth.Pool(),
		Time:           m.Now,
	}
}

// Serve starts a service. The handler only runs for authenticated, authorized calls.
func (m *Mesh) Serve(name string, src *ca.Source, h http.Handler) *Service {
	guard := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "no identity", http.StatusUnauthorized)
			return
		}
		caller := ""
		if u := r.TLS.PeerCertificates[0].URIs; len(u) == 1 {
			caller = u[0].String()
		}
		d := m.Policy.Decide(caller, r.Method, r.URL.Path)
		m.Audit.Add(Record{At: m.Now(), Caller: caller, Target: src.ID(), Method: r.Method, Path: r.URL.Path, Allow: d.Allow, Reason: d.Reason})
		if !d.Allow {
			http.Error(w, "forbidden: "+d.Reason, http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
	// Not httptest.Server: its StartTLS fills tls.Config.Certificates with a
	// built-in example.com certificate, and Go prefers that over GetCertificate
	// when the client sends no SNI (as with an IP address). Our identity
	// certificate would never be presented.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	srv := &http.Server{Handler: guard, ErrorLog: log.New(io.Discard, "", 0)}
	go srv.Serve(tls.NewListener(ln, m.serverTLS(src)))
	return &Service{Name: name, ID: src.ID(), Source: src, srv: srv, url: "https://" + ln.Addr().String()}
}

func (s *Service) Close()      { _ = s.srv.Close() }
func (s *Service) URL() string { return s.url }

// Client returns an HTTP client that presents src's certificate and accepts a
// server only if its certificate chains to our CA and carries wantID. Host
// names are ignored on purpose: identity is the SPIFFE ID, not the address.
func (m *Mesh) Client(src *ca.Source, wantID string) *http.Client {
	return m.ClientWithPool(src, wantID, m.Auth.Pool())
}

func (m *Mesh) ClientWithPool(src *ca.Source, wantID string, pool *x509.CertPool) *http.Client {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		// InsecureSkipVerify disables Go's host name check only. The chain,
		// validity window, key usage and SPIFFE ID are all verified below.
		InsecureSkipVerify: true, //nolint:gosec
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			id, _, err := ca.PeerID(raw, pool, m.Auth.TrustDomain, m.Now())
			if err != nil {
				return err
			}
			if wantID != "" && id != wantID {
				return fmt.Errorf("server identity %s, expected %s", id, wantID)
			}
			return nil
		},
	}
	if src != nil {
		cfg.GetClientCertificate = src.GetClientCertificate
	}
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true},
	}
}

var ErrDenied = errors.New("denied")
