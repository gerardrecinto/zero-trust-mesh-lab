package mesh_test

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gerardrecinto/zero-trust-mesh-lab/ca"
	"github.com/gerardrecinto/zero-trust-mesh-lab/mesh"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (f *fakeClock) Now() time.Time          { f.mu.Lock(); defer f.mu.Unlock(); return f.t }
func (f *fakeClock) Advance(d time.Duration) { f.mu.Lock(); f.t = f.t.Add(d); f.mu.Unlock() }

type world struct {
	clk       *fakeClock
	m         *mesh.Mesh
	orders    *mesh.Service
	payments  *mesh.Service
	front     *ca.Source
	batch     *ca.Source
	ordersSrc *ca.Source
}

func newWorld(t *testing.T, ttl time.Duration) *world {
	t.Helper()
	clk := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	auth, err := ca.New("lab.local", clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	pol := mesh.Policy{Rules: []mesh.Rule{
		{Source: auth.ID("ns/shop/sa/frontend"), Methods: []string{"GET"}, Paths: []string{"/orders"}},
		{Source: auth.ID("ns/shop/sa/orders"), Methods: []string{"POST"}, Paths: []string{"/charge"}},
	}}
	m := &mesh.Mesh{Auth: auth, Policy: mesh.NewEngine(pol), Audit: &mesh.Audit{}, Now: clk.Now}
	mk := func(p string) *ca.Source {
		s, err := ca.NewSource(auth, auth.ID(p), ttl)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	w := &world{clk: clk, m: m, front: mk("ns/shop/sa/frontend"), batch: mk("ns/shop/sa/batch"), ordersSrc: mk("ns/shop/sa/orders")}
	ok := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) { io.WriteString(rw, "ok") })
	w.orders = m.Serve("orders", w.ordersSrc, ok)
	w.payments = m.Serve("payments", mk("ns/shop/sa/payments"), ok)
	t.Cleanup(func() { w.orders.Close(); w.payments.Close() })
	return w
}

func do(c *http.Client, method, url string) (int, string, error) {
	req, _ := http.NewRequest(method, url, nil)
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), nil
}

func TestAllowedCallerSucceeds(t *testing.T) {
	w := newWorld(t, time.Hour)
	st, body, err := do(w.m.Client(w.front, w.orders.ID), "GET", w.orders.URL()+"/orders/1")
	if err != nil || st != 200 || body != "ok" {
		t.Fatalf("%d %q %v", st, body, err)
	}
}

func TestValidIdentityWithoutAPermissionIsForbidden(t *testing.T) {
	w := newWorld(t, time.Hour)
	// frontend authenticates fine but no rule lets it reach payments.
	st, body, err := do(w.m.Client(w.front, w.payments.ID), "POST", w.payments.URL()+"/charge")
	if err != nil || st != 403 || !strings.Contains(body, "default deny") {
		t.Fatalf("%d %q %v", st, body, err)
	}
	// and an allowed identity is still limited to its method and path.
	st, _, _ = do(w.m.Client(w.front, w.orders.ID), "DELETE", w.orders.URL()+"/orders/1")
	if st != 403 {
		t.Fatalf("DELETE got %d", st)
	}
}

func TestNoClientCertificateNeverReachesTheHandler(t *testing.T) {
	w := newWorld(t, time.Hour)
	// A caller on the "internal network" with no identity: network location earns nothing.
	_, _, err := do(w.m.Client(nil, w.orders.ID), "GET", w.orders.URL()+"/orders/1")
	if err == nil {
		t.Fatal("handshake succeeded without a client certificate")
	}
	if n := len(w.m.Audit.All()); n != 0 {
		t.Fatalf("request reached the guard (%d audit records)", n)
	}
}

func TestCertificateFromAnotherCARejected(t *testing.T) {
	w := newWorld(t, time.Hour)
	evil, _ := ca.New("lab.local", w.clk.Now) // same trust domain name, different key
	forged, _ := ca.NewSource(evil, evil.ID("ns/shop/sa/frontend"), time.Hour)
	_, _, err := do(w.m.Client(forged, w.orders.ID), "GET", w.orders.URL()+"/orders/1")
	if err == nil {
		t.Fatal("a certificate from a different CA was accepted")
	}
}

func TestClientRefusesAServerWithTheWrongIdentity(t *testing.T) {
	w := newWorld(t, time.Hour)
	// The client dials the payments address but expects orders: a swapped endpoint is caught.
	_, _, err := do(w.m.Client(w.front, w.orders.ID), "GET", w.payments.URL()+"/orders/1")
	if err == nil || !strings.Contains(err.Error(), "expected") {
		t.Fatalf("got %v", err)
	}
}

func TestExpiredCertificateRejectedAndRotationFixesIt(t *testing.T) {
	w := newWorld(t, 10*time.Minute)
	c := w.m.Client(w.front, w.orders.ID)
	if st, _, err := do(c, "GET", w.orders.URL()+"/orders/1"); err != nil || st != 200 {
		t.Fatalf("baseline %d %v", st, err)
	}
	w.clk.Advance(11 * time.Minute) // past the 10 minute lifetime, no rotation yet
	if _, _, err := do(c, "GET", w.orders.URL()+"/orders/1"); err == nil {
		t.Fatal("expired client certificate was accepted")
	}
	// Servers rotate too, or the client rejects their expired certificate.
	for _, s := range []*ca.Source{w.front, w.ordersSrc} {
		if err := s.Rotate(); err != nil {
			t.Fatal(err)
		}
	}
	if st, _, err := do(c, "GET", w.orders.URL()+"/orders/1"); err != nil || st != 200 {
		t.Fatalf("after rotation %d %v", st, err)
	}
}

func TestRotationUsesNewCertificateWithoutRestart(t *testing.T) {
	w := newWorld(t, time.Hour)
	serial := func() string { return w.front.Current().Leaf.SerialNumber.String() }
	a := serial()
	if err := w.front.Rotate(); err != nil {
		t.Fatal(err)
	}
	b := serial()
	if a == b {
		t.Fatal("rotation did not change the certificate")
	}
	if st, _, err := do(w.m.Client(w.front, w.orders.ID), "GET", w.orders.URL()+"/orders/1"); err != nil || st != 200 {
		t.Fatalf("call after rotation: %d %v", st, err)
	}
}

func TestRevocationBlocksAStillValidCertificate(t *testing.T) {
	w := newWorld(t, time.Hour)
	c := w.m.Client(w.front, w.orders.ID)
	if st, _, _ := do(c, "GET", w.orders.URL()+"/orders/1"); st != 200 {
		t.Fatal("baseline failed")
	}
	w.m.Policy.Revoke(w.front.ID())
	st, body, _ := do(c, "GET", w.orders.URL()+"/orders/1")
	if st != 403 || !strings.Contains(body, "revoked") {
		t.Fatalf("%d %q", st, body)
	}
}

func TestPolicyReloadTakesEffectImmediately(t *testing.T) {
	w := newWorld(t, time.Hour)
	c := w.m.Client(w.batch, w.orders.ID)
	if st, _, _ := do(c, "GET", w.orders.URL()+"/orders/1"); st != 403 {
		t.Fatalf("batch should start denied, got %d", st)
	}
	w.m.Policy.Set(mesh.Policy{Rules: []mesh.Rule{{Source: w.batch.ID(), Methods: []string{"GET"}, Paths: []string{"/orders"}}}})
	if st, _, _ := do(c, "GET", w.orders.URL()+"/orders/1"); st != 200 {
		t.Fatalf("batch should be allowed after reload, got %d", st)
	}
}

func TestEveryDecisionIsAudited(t *testing.T) {
	w := newWorld(t, time.Hour)
	do(w.m.Client(w.front, w.orders.ID), "GET", w.orders.URL()+"/orders/1")
	do(w.m.Client(w.batch, w.orders.ID), "GET", w.orders.URL()+"/orders/1")
	recs := w.m.Audit.All()
	if len(recs) != 2 || !recs[0].Allow || recs[1].Allow || recs[1].Caller != w.batch.ID() {
		t.Fatalf("%+v", recs)
	}
}

func TestIssueRejectsForeignTrustDomain(t *testing.T) {
	a, _ := ca.New("lab.local", nil)
	if _, err := a.Issue("spiffe://other.example/ns/x/sa/y", time.Hour); err == nil {
		t.Fatal("issued an identity outside the trust domain")
	}
}
