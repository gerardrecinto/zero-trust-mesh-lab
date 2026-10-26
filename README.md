# zero-trust-mesh-lab

Mutual TLS with SPIFFE-style workload identities, default-deny authorization and an audit trail, in Go. Real TLS connections between real servers on loopback.

**Live demo:** https://gerardrecinto.github.io/zero-trust-mesh-lab/ shows the recorded result of every identity against every target, the certificate lifecycle (expiry, rotation, revocation, policy reload) and the audit log.

Personal learning project. It is not a production system, not a replacement for a real CA, and not a service mesh.

## The model

Zero trust here means three things, each with tests:

1. **Identity comes from a certificate, not from where the request came from.** Each workload holds a short-lived X.509 certificate whose URI SAN is a SPIFFE ID such as `spiffe://lab.local/ns/shop/sa/orders`. Servers require a client certificate (TLS 1.3) and clients check the server's SPIFFE ID instead of its host name.
2. **Authentication is not authorization.** After the handshake, a guard looks up the caller's ID, method and path in a policy that is default deny. A valid certificate with no matching rule gets HTTP 403.
3. **Everything is short-lived and observable.** Certificates expire and are rotated without a restart, an identity can be revoked while its certificate is still valid, policy reloads atomically, and every decision is written to an audit log.

## Layout

- `ca/` a small CA that issues certificates with a SPIFFE ID, verifies a peer chain at a given time and returns its identity, and a `Source` that rotates a workload's certificate
- `mesh/` the guard (policy engine, revocation, audit) and helpers to start a service and build a client
- `cmd/matrix/` runs every identity against every target plus the lifecycle steps and writes `docs/data.json`; it exits non-zero if an outcome differs from its written expectation

## Tests

```
go test ./... -race -count=1
```

- an allowed caller succeeds; the same identity is refused on a different method or on a service it has no rule for
- a caller with no certificate never reaches the handler (the audit log stays empty)
- a certificate from a different CA that claims the same trust domain is rejected
- a client refuses a server presenting the wrong identity, even at the expected address
- an expired certificate is rejected and rotation fixes it; rotation changes the certificate without a restart
- revocation blocks a certificate that is still valid; a policy reload takes effect on the next request
- every decision, allowed or denied, appears in the audit log; identities outside the trust domain cannot be issued

Time is injected as a fake clock, so expiry tests run instantly.

## Things I hit while building it

- `httptest.Server.StartTLS` fills `tls.Config.Certificates` with a built-in `example.com` certificate. When the client dials an IP address it sends no SNI, and Go then prefers `Certificates` over `GetCertificate`, so my identity certificate was never presented and every handshake failed with `certificate signed by unknown authority`. I replaced `httptest` with a plain listener wrapped in `tls.NewListener`.
- With TLS 1.3 the server's rejection of a bad client certificate reaches the client only after the handshake appears to finish, so it surfaces on the first request instead of at dial time. The result is the same (the handler is never reached) but the error shows up later than it would on TLS 1.2.
- Rotating only the client is not enough once the clock moves: the server's certificate expires too and the client correctly rejects it. The lifecycle test rotates both sides.

## Not covered

A real CA and key storage (the root key lives in memory), CRL or OCSP, the SPIFFE Workload API and workload attestation, a sidecar proxy, network policy, certificate chains with intermediates in the issuer, and performance testing.

## References

- NIST, [SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final)
- SPIFFE: [concepts](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/), the [X509-SVID specification](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md), and [go-spiffe](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2)
- Go: [crypto/tls](https://pkg.go.dev/crypto/tls), [crypto/x509](https://pkg.go.dev/crypto/x509)
- IETF: [RFC 8446 (TLS 1.3)](https://www.rfc-editor.org/rfc/rfc8446), [RFC 5280 (X.509 profile)](https://www.rfc-editor.org/rfc/rfc5280)
- Google, [BeyondCorp: A New Approach to Enterprise Security](https://research.google/pubs/beyondcorp-a-new-approach-to-enterprise-security/)
- Istio, [Security concepts](https://istio.io/latest/docs/concepts/security/)
