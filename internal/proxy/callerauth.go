package proxy

// Caller authentication — the DIME fork's second delta.
//
// Upstream iron-proxy does not authenticate its callers at all:
// Proxy-Authorization appears in its source only in the hop-by-hop strip
// list. That is a defensible default for a proxy a company runs for its own
// traffic on a network it trusts. It is not one for a proxy that holds a
// single customer's live trading credentials and runs in a cluster alongside
// other customers' agents — which is what this fork is for.
//
// Without this, the only thing keeping one customer's agent off another's
// proxy is NetworkPolicy. That makes NetworkPolicy a prerequisite rather than
// defence in depth, and a single missing or mis-selectored policy object the
// whole tenant boundary.
//
// THE TOKEN COMES FROM THE POD'S ENVIRONMENT, NEVER THE CONFIG. In managed
// mode the config arrives from the control plane, and a token the control
// plane chose is a token the control plane can use. Same reasoning as
// kms_sm's namespace and key id: what this pod is allowed to do is decided by
// its own deployment.
//
// WHERE IT IS ENFORCED, AND THE ONE PLACE IT DELIBERATELY IS NOT:
//
//   - The explicit-proxy front door — a CONNECT, or an absolute-form HTTP
//     request on the tunnel listener. Both authenticate.
//   - The direct http/https listeners. They authenticate.
//   - Requests INSIDE an established tunnel do not, and must not. The
//     connection was authenticated when the CONNECT was accepted, and a
//     Proxy-Authorization header on a request inside the tunnel is one the
//     client sends END-TO-END — through the tunnel, to the venue. Requiring
//     it there would mean asking every agent to hand our proxy token to the
//     destination it is calling.
//   - SOCKS5 is refused outright while caller auth is on. Upstream negotiates
//     no-auth only (method 0x00), so leaving it reachable would be an
//     unauthenticated door into the same credentials. RFC 1929
//     username/password is more surface than this deployment needs: agents
//     reach the proxy by CONNECT, via egress-capture's netfilter REDIRECT.

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"
)

// envCallerToken names the per-customer token every caller must present. Set
// by the customer's own Helm release from its own secret, so two customers'
// proxies never share one.
const envCallerToken = "DIME_PROXY_AUTH_TOKEN"

// callerAuthScheme is the Proxy-Authorization scheme. Bearer rather than
// Basic: there is no username here, and Basic would invite someone to treat
// the base64 as protection.
const callerAuthScheme = "Bearer "

// callerAuth checks the per-customer caller token. A nil *callerAuth means
// unauthenticated — see newCallerAuth.
type callerAuth struct{ token string }

// newCallerAuth reads the token from the environment. Returns nil when unset,
// which leaves the proxy unauthenticated: upstream's own behaviour, and what
// its test suite and standalone users expect. A DIME deployment must set it,
// and New logs loudly when it is missing — see FORK.md.
func newCallerAuth(getenv func(string) string) *callerAuth {
	token := strings.TrimSpace(getenv(envCallerToken))
	if token == "" {
		return nil
	}
	return &callerAuth{token: token}
}

func (a *callerAuth) enabled() bool { return a != nil && a.token != "" }

// authorize reports whether r presents the caller token. Constant-time, so a
// caller cannot learn the token a byte at a time from response timing.
func (a *callerAuth) authorize(r *http.Request) bool {
	if !a.enabled() {
		return true
	}
	h := r.Header.Get("Proxy-Authorization")
	// The scheme is required. Without this check a scheme-less header would
	// be accepted as a raw token, because TrimPrefix returns the string
	// unchanged when the prefix is absent.
	if len(h) < len(callerAuthScheme) || !strings.EqualFold(h[:len(callerAuthScheme)], callerAuthScheme) {
		return false
	}
	got := strings.TrimSpace(h[len(callerAuthScheme):])
	return subtle.ConstantTimeCompare([]byte(got), []byte(a.token)) == 1
}

// requireCaller authorizes r, answering 407 and returning false if it fails.
// The refusal happens before ANY secret is looked up, host matched, or
// upstream dialed: an unauthenticated caller must not be able to make this
// proxy fetch, decrypt, or connect to anything.
func (p *Proxy) requireCaller(w http.ResponseWriter, r *http.Request) bool {
	if p.callerAuth.authorize(r) {
		return true
	}
	// RFC 7235: a 407 carries Proxy-Authenticate naming the scheme. No realm —
	// there is one credential and nothing to disambiguate.
	w.Header().Set("Proxy-Authenticate", strings.TrimSpace(callerAuthScheme))
	// Never log the presented value: a wrong token is often a right token for
	// somewhere else, and log lines outlive incidents.
	p.logger.Warn("refused an unauthenticated caller",
		slog.String("method", r.Method),
		slog.String("host", r.Host),
		slog.Bool("header_present", r.Header.Get("Proxy-Authorization") != ""),
	)
	http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
	return false
}
