// matrix drives real mTLS servers and clients through every identity and
// target combination plus the certificate lifecycle events, and records what
// actually happened for the docs viewer. Exit status 1 if an outcome differs
// from the expectation written next to it.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gerardrecinto/zero-trust-mesh-lab/ca"
	"github.com/gerardrecinto/zero-trust-mesh-lab/mesh"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type Cell struct {
	Identity string `json:"identity"`
	Target   string `json:"target"`
	Outcome  string `json:"outcome"` // allowed | forbidden | rejected
	Detail   string `json:"detail"`
	Want     string `json:"-"`
}

type Step struct {
	Title   string `json:"title"`
	Result  string `json:"result"`
	Outcome string `json:"outcome"`
}

func call(c *http.Client, method, url string) (string, string) {
	req, _ := http.NewRequest(method, url, nil)
	resp, err := c.Do(req)
	if err != nil {
		msg := err.Error()
		if i := strings.LastIndex(msg, ": "); i >= 0 && strings.Contains(msg, "https://") {
			msg = msg[strings.Index(msg, "\": ")+3:]
		}
		return "rejected", msg
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	body := strings.TrimSpace(string(b))
	if resp.StatusCode == 200 {
		return "allowed", "200 " + body
	}
	return "forbidden", fmt.Sprintf("%d %s", resp.StatusCode, body)
}

func main() {
	clk := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	auth, _ := ca.New("lab.local", clk.Now)
	pol := mesh.Policy{Rules: []mesh.Rule{
		{Source: auth.ID("ns/shop/sa/frontend"), Methods: []string{"GET"}, Paths: []string{"/orders"}},
		{Source: auth.ID("ns/shop/sa/orders"), Methods: []string{"POST"}, Paths: []string{"/charge"}},
	}}
	m := &mesh.Mesh{Auth: auth, Policy: mesh.NewEngine(pol), Audit: &mesh.Audit{}, Now: clk.Now}
	src := func(a *ca.Authority, p string, ttl time.Duration) *ca.Source {
		s, err := ca.NewSource(a, a.ID(p), ttl)
		if err != nil {
			panic(err)
		}
		return s
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
	ordersSrc := src(auth, "ns/shop/sa/orders", 10*time.Minute)
	paySrc := src(auth, "ns/shop/sa/payments", 10*time.Minute)
	orders := m.Serve("orders", ordersSrc, ok)
	pay := m.Serve("payments", paySrc, ok)
	defer orders.Close()
	defer pay.Close()

	front := src(auth, "ns/shop/sa/frontend", 10*time.Minute)
	ords := src(auth, "ns/shop/sa/orders", 10*time.Minute)
	batch := src(auth, "ns/shop/sa/batch", 10*time.Minute)
	evil, _ := ca.New("lab.local", clk.Now)
	forged := src(evil, "ns/shop/sa/frontend", 10*time.Minute)
	stale := src(auth, "ns/shop/sa/frontend", time.Minute)

	type target struct{ name, method, url, wantID string }
	targets := []target{
		{"orders  GET /orders/1", "GET", orders.URL() + "/orders/1", orders.ID},
		{"payments  POST /charge", "POST", pay.URL() + "/charge", pay.ID},
		{"payments  GET /admin", "GET", pay.URL() + "/admin", pay.ID},
	}
	type ident struct {
		name string
		src  *ca.Source
		want [3]string
	}
	idents := []ident{
		{"frontend", front, [3]string{"allowed", "forbidden", "forbidden"}},
		{"orders", ords, [3]string{"forbidden", "allowed", "forbidden"}},
		{"batch (valid cert, no rule)", batch, [3]string{"forbidden", "forbidden", "forbidden"}},
		{"forged cert (other CA)", forged, [3]string{"rejected", "rejected", "rejected"}},
		{"no certificate", nil, [3]string{"rejected", "rejected", "rejected"}},
	}
	bad := 0
	var cells []Cell
	for _, id := range idents {
		for i, t := range targets {
			outcome, detail := call(m.Client(id.src, t.wantID), t.method, t.url)
			if outcome != id.want[i] {
				bad++
				fmt.Fprintf(os.Stderr, "UNEXPECTED %s -> %s: got %s want %s\n", id.name, t.name, outcome, id.want[i])
			}
			cells = append(cells, Cell{id.name, t.name, outcome, detail, id.want[i]})
		}
	}

	var steps []Step
	step := func(title, outcome, result string) { steps = append(steps, Step{title, result, outcome}) }
	url := orders.URL() + "/orders/1"

	o, d := call(m.Client(stale, orders.ID), "GET", url)
	step("Frontend certificate with a 1 minute lifetime, used straight away", o, d)
	clk.Advance(2 * time.Minute)
	o, d = call(m.Client(stale, orders.ID), "GET", url)
	step("Two minutes later, same certificate, no rotation (the server certificate also expired)", o, d)
	_ = ordersSrc.Rotate()
	_ = paySrc.Rotate()
	o, d = call(m.Client(stale, orders.ID), "GET", url)
	step("Servers rotated, client still holds its expired certificate", o, d)
	before := stale.Current().Leaf.SerialNumber.String()
	_ = stale.Rotate()
	after := stale.Current().Leaf.SerialNumber.String()
	o, d = call(m.Client(stale, orders.ID), "GET", url)
	step(fmt.Sprintf("Client rotated (serial %s... to %s...), no restart", before[:6], after[:6]), o, d)
	m.Policy.Revoke(stale.ID())
	o, d = call(m.Client(stale, orders.ID), "GET", url)
	step("Identity revoked while its certificate is still valid", o, d)
	m.Policy.Set(mesh.Policy{Rules: append(pol.Rules, mesh.Rule{Source: batch.ID(), Methods: []string{"GET"}, Paths: []string{"/orders"}})})
	o, d = call(m.Client(batch, orders.ID), "GET", url)
	step("Policy reloaded to allow batch on GET /orders", o, d)
	want := []string{"allowed", "rejected", "rejected", "allowed", "forbidden", "allowed"}
	for i, s := range steps {
		if s.Outcome != want[i] {
			bad++
			fmt.Fprintf(os.Stderr, "UNEXPECTED step %d %q: got %s want %s\n", i, s.Title, s.Outcome, want[i])
		}
	}

	recs := m.Audit.All()
	type ar struct {
		Caller, Target, Request, Decision string
	}
	var audit []ar
	for _, r := range recs {
		dec := "allow"
		if !r.Allow {
			dec = "deny: " + r.Reason
		}
		audit = append(audit, ar{strings.TrimPrefix(r.Caller, "spiffe://lab.local/"), strings.TrimPrefix(r.Target, "spiffe://lab.local/"), r.Method + " " + r.Path, dec})
	}
	out := map[string]any{"cells": cells, "steps": steps, "audit": audit, "policy": pol}
	b, _ := json.MarshalIndent(out, "", " ")
	_ = os.WriteFile("docs/data.json", b, 0o644)
	for _, c := range cells {
		fmt.Printf("%-30s %-26s %-10s %s\n", c.Identity, c.Target, c.Outcome, c.Detail)
	}
	for _, s := range steps {
		fmt.Printf("- %-10s %s\n", s.Outcome, s.Title)
	}
	if bad > 0 {
		os.Exit(1)
	}
}
