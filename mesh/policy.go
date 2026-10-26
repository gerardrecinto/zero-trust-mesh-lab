// Package mesh adds identity-based access control on top of mutual TLS:
// default deny, explicit allow rules keyed on the caller's SPIFFE ID, an
// identity deny list, and an audit record for every decision.
package mesh

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Rule struct {
	// Source is an exact SPIFFE ID, or a prefix ending in "*".
	Source  string   `json:"source"`
	Methods []string `json:"methods"`
	// Paths are prefixes.
	Paths []string `json:"paths"`
}

type Policy struct {
	Rules []Rule `json:"rules"`
}

type Decision struct {
	Allow  bool   `json:"allow"`
	Rule   int    `json:"rule"` // index of the matching rule, -1 if none
	Reason string `json:"reason"`
}

type Engine struct {
	policy atomic.Pointer[Policy]
	mu     sync.RWMutex
	denied map[string]bool
}

func NewEngine(p Policy) *Engine {
	e := &Engine{denied: map[string]bool{}}
	e.policy.Store(&p)
	return e
}

// Set swaps the whole policy atomically; in-flight requests finish on the old one.
func (e *Engine) Set(p Policy) { e.policy.Store(&p) }

// Revoke blocks an identity even though its certificate is still valid.
func (e *Engine) Revoke(id string) { e.mu.Lock(); e.denied[id] = true; e.mu.Unlock() }

func (e *Engine) Decide(id, method, path string) Decision {
	e.mu.RLock()
	rev := e.denied[id]
	e.mu.RUnlock()
	if rev {
		return Decision{false, -1, "identity revoked"}
	}
	for i, r := range e.policy.Load().Rules {
		if !matchID(r.Source, id) || !contains(r.Methods, method) || !hasPrefix(r.Paths, path) {
			continue
		}
		return Decision{true, i, "allowed by rule " + itoa(i)}
	}
	return Decision{false, -1, "no rule allows this (default deny)"}
}

func matchID(pat, id string) bool {
	if strings.HasSuffix(pat, "*") {
		return strings.HasPrefix(id, strings.TrimSuffix(pat, "*"))
	}
	return pat == id
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func hasPrefix(l []string, p string) bool {
	for _, x := range l {
		if strings.HasPrefix(p, x) {
			return true
		}
	}
	return false
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	return s
}

// Audit records every decision. Zero trust means every request is logged with
// who asked, what for, and why it was allowed or refused.
type Record struct {
	At     time.Time `json:"at"`
	Caller string    `json:"caller"`
	Target string    `json:"target"`
	Method string    `json:"method"`
	Path   string    `json:"path"`
	Allow  bool      `json:"allow"`
	Reason string    `json:"reason"`
}

type Audit struct {
	mu   sync.Mutex
	recs []Record
}

func (a *Audit) Add(r Record) { a.mu.Lock(); a.recs = append(a.recs, r); a.mu.Unlock() }
func (a *Audit) All() []Record {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]Record(nil), a.recs...)
}
