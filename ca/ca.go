// Package ca is a tiny certificate authority that issues short-lived X.509
// identity certificates in the SPIFFE style: the workload identity is a URI
// subject alternative name such as spiffe://lab.local/ns/shop/sa/orders, not a
// host name or an IP address. Nothing here is a substitute for a real CA.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Authority struct {
	TrustDomain string
	Now         func() time.Time

	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func New(trustDomain string, now func() time.Time) (*Authority, error) {
	if now == nil {
		now = time.Now
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: trustDomain + " root"},
		NotBefore:             now().Add(-time.Minute),
		NotAfter:              now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &Authority{TrustDomain: trustDomain, Now: now, cert: cert, key: key, pool: pool}, nil
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	return n
}

func (a *Authority) Pool() *x509.CertPool { return a.pool }

// ID builds a SPIFFE ID inside this authority's trust domain.
func (a *Authority) ID(path string) string {
	return "spiffe://" + a.TrustDomain + "/" + strings.TrimPrefix(path, "/")
}

// Issue returns a leaf certificate for a SPIFFE ID valid for ttl.
func (a *Authority) Issue(spiffeID string, ttl time.Duration) (tls.Certificate, error) {
	u, err := url.Parse(spiffeID)
	if err != nil || u.Scheme != "spiffe" || u.Host != a.TrustDomain {
		return tls.Certificate{}, fmt.Errorf("%q is not a SPIFFE ID in trust domain %q", spiffeID, a.TrustDomain)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := a.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		URIs:         []*url.URL{u},
		NotBefore:    now,
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// PeerID verifies a presented chain against the pool at the given time and
// returns the single SPIFFE ID it carries. This is what each side of a
// connection calls instead of checking host names.
func PeerID(chain [][]byte, pool *x509.CertPool, trustDomain string, now time.Time) (string, *x509.Certificate, error) {
	if len(chain) == 0 {
		return "", nil, errors.New("no certificate presented")
	}
	certs := make([]*x509.Certificate, 0, len(chain))
	for _, der := range chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return "", nil, err
		}
		certs = append(certs, c)
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{
		Roots: pool, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return "", nil, err
	}
	if len(certs[0].URIs) != 1 {
		return "", nil, errors.New("certificate must carry exactly one URI SAN")
	}
	u := certs[0].URIs[0]
	if u.Scheme != "spiffe" || u.Host != trustDomain {
		return "", nil, fmt.Errorf("identity %q is outside trust domain %q", u, trustDomain)
	}
	return u.String(), certs[0], nil
}

// Source hands out the current certificate for a workload and swaps it for a
// fresh one on Rotate. TLS asks for it on every handshake, so new connections
// pick up the new certificate with no restart.
type Source struct {
	mu   sync.RWMutex
	auth *Authority
	id   string
	ttl  time.Duration
	cur  tls.Certificate
	N    int // certificates issued so far
}

func NewSource(a *Authority, id string, ttl time.Duration) (*Source, error) {
	s := &Source{auth: a, id: id, ttl: ttl}
	return s, s.Rotate()
}

func (s *Source) Rotate() error {
	c, err := s.auth.Issue(s.id, s.ttl)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.cur = c
	s.N++
	s.mu.Unlock()
	return nil
}

func (s *Source) Current() tls.Certificate { s.mu.RLock(); defer s.mu.RUnlock(); return s.cur }
func (s *Source) ID() string               { return s.id }
func (s *Source) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c := s.Current()
	return &c, nil
}
func (s *Source) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	c := s.Current()
	return &c, nil
}

// RotateEvery renews the certificate at half its lifetime until stop closes.
func (s *Source) RotateEvery(stop <-chan struct{}) {
	t := time.NewTicker(s.ttl / 2)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			_ = s.Rotate()
		case <-stop:
			return
		}
	}
}
