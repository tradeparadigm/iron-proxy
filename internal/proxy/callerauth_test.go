package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testCallerToken = "cust-4275289e-Zk9pQ2xw"

// ─── The header check ───────────────────────────────────────────────────────

func TestCallerAuthAuthorize(t *testing.T) {
	a := newCallerAuth(func(string) string { return testCallerToken })
	require.True(t, a.enabled())

	cases := map[string]struct {
		header string
		want   bool
	}{
		"correct":            {header: "Bearer " + testCallerToken, want: true},
		"scheme lowercase":   {header: "bearer " + testCallerToken, want: true},
		"scheme mixed case":  {header: "BeArEr " + testCallerToken, want: true},
		"surrounding spaces": {header: "Bearer   " + testCallerToken + "  ", want: true},
		"absent":             {header: "", want: false},
		"wrong token":        {header: "Bearer another-customers-token", want: false},
		// TrimPrefix returns the string unchanged when the prefix is absent,
		// so without an explicit scheme check a bare token would be accepted.
		"scheme-less":  {header: testCallerToken, want: false},
		"wrong scheme": {header: "Basic " + testCallerToken, want: false},
		"empty bearer": {header: "Bearer ", want: false},
		// A prefix of the real token must not pass — the comparison is over
		// the whole value, not a prefix.
		"token prefix": {header: "Bearer " + testCallerToken[:8], want: false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			if tc.header != "" {
				r.Header.Set("Proxy-Authorization", tc.header)
			}
			require.Equal(t, tc.want, a.authorize(r))
		})
	}
}

// Unset means unauthenticated, which is upstream's behaviour and what its own
// suite depends on. The boot warning is what stops that being silent.
func TestCallerAuthDisabledWhenUnset(t *testing.T) {
	a := newCallerAuth(func(string) string { return "" })
	require.False(t, a.enabled())

	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	require.True(t, a.authorize(r), "with no token configured every caller is allowed")

	// A nil receiver must behave the same, since that is what New stores.
	var nilAuth *callerAuth
	require.False(t, nilAuth.enabled())
	require.True(t, nilAuth.authorize(r))
}

// ─── The front doors ────────────────────────────────────────────────────────

// A CONNECT is where a whole tunnel's authorization is decided, so it is the
// most important door.
func TestCallerAuthGuardsCONNECT(t *testing.T) {
	t.Setenv(envCallerToken, testCallerToken)
	_, tunnelAddr, _ := startTunnelProxy(t, nil)

	connect := func(t *testing.T, header string) *http.Response {
		t.Helper()
		conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		req := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n"
		if header != "" {
			req += "Proxy-Authorization: " + header + "\r\n"
		}
		_, err = fmt.Fprint(conn, req+"\r\n")
		require.NoError(t, err)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp
	}

	t.Run("no token", func(t *testing.T) {
		resp := connect(t, "")
		require.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
		// RFC 7235 requires the scheme be named on a 407.
		require.Equal(t, "Bearer", resp.Header.Get("Proxy-Authenticate"))
	})

	t.Run("another customer's token", func(t *testing.T) {
		resp := connect(t, "Bearer not-this-customers-token")
		require.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
	})

	t.Run("correct token", func(t *testing.T) {
		// The tunnel is allowed to fail on the dial to example.com; what
		// matters is that it got past authentication.
		resp := connect(t, "Bearer "+testCallerToken)
		require.NotEqual(t, http.StatusProxyAuthRequired, resp.StatusCode)
	})
}

// An absolute-form request on the proxy port is a front door too — it carries
// no tunnel, so it authenticates per request.
func TestCallerAuthGuardsAbsoluteFormAndStripsTheToken(t *testing.T) {
	t.Setenv(envCallerToken, testCallerToken)

	var reached int
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached++
		gotAuth = r.Header.Get("Proxy-Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	_, httpAddr, _, _ := startProxy(t)

	do := func(t *testing.T, header string) *http.Response {
		t.Helper()
		conn, err := net.DialTimeout("tcp", httpAddr, 5*time.Second)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		req := fmt.Sprintf("GET /test HTTP/1.1\r\nHost: %s\r\n", upstream.Listener.Addr().String())
		if header != "" {
			req += "Proxy-Authorization: " + header + "\r\n"
		}
		_, err = fmt.Fprint(conn, req+"\r\n")
		require.NoError(t, err)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp
	}

	t.Run("refused before the upstream is dialed", func(t *testing.T) {
		resp := do(t, "")
		require.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
		// The point of refusing at the front door: an unauthenticated caller
		// must not be able to make this proxy connect to anything.
		require.Zero(t, reached, "the upstream must not have been contacted")
	})

	t.Run("allowed, and our token never reaches the venue", func(t *testing.T) {
		resp := do(t, "Bearer "+testCallerToken)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, 1, reached)
		// Proxy-Authorization is hop-by-hop and stripped. If it were not, the
		// per-customer proxy token would be handed to every venue the agent
		// calls.
		require.Empty(t, gotAuth)
	})
}

// SOCKS5 negotiates no-auth only, so while caller auth is on it would be an
// anonymous door into the same credentials every other entry point protects.
// 0xFF is the protocol's "no acceptable methods".
func TestCallerAuthRefusesSOCKS5(t *testing.T) {
	t.Setenv(envCallerToken, testCallerToken)
	_, tunnelAddr, _ := startTunnelProxy(t, nil)

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	// Version 5, one method, no-auth.
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	reply := make([]byte, 2)
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)
	require.Equal(t, byte(0x05), reply[0])
	require.Equal(t, byte(0xFF), reply[1], "SOCKS5 must be refused while caller auth is enabled")
}

// With no token configured the proxy behaves exactly as upstream does. This is
// what lets the rest of the suite — and a standalone user — run unchanged.
func TestCallerAuthOffLeavesTheProxyOpen(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	_, httpAddr, _, _ := startProxy(t)

	conn, err := net.DialTimeout("tcp", httpAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	_, err = fmt.Fprintf(conn, "GET /test HTTP/1.1\r\nHost: %s\r\n\r\n", upstream.Listener.Addr().String())
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// The asymmetry, and the reason it exists.
//
// A request travelling INSIDE an established tunnel must not be asked for the
// caller token. Its headers are end-to-end: they are encrypted to the venue
// and delivered there. If this check applied inside the tunnel, every agent
// would have to put our per-customer proxy token into requests aimed at
// Binance — which hands the token to Binance.
//
// So: authenticate the CONNECT, then trust the tunnel it opened. This test is
// here because that reads like an omission, and someone will eventually try
// to "fix" it.
func TestCallerAuthDoesNotApplyInsideAnEstablishedTunnel(t *testing.T) {
	t.Setenv(envCallerToken, testCallerToken)

	var innerAuth string
	var innerSeen bool
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerSeen = true
		innerAuth = r.Header.Get("Proxy-Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "reached the venue")
	}))
	defer upstream.Close()

	p, tunnelAddr, caPool := startTunnelProxy(t, nil)
	upstreamAddr := upstream.Listener.Addr().String()
	p.transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, upstreamAddr)
		},
	}

	const venue = "api.binance.com"

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	// The CONNECT carries the token. This is the only place it appears.
	_, err = fmt.Fprintf(conn,
		"CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\nProxy-Authorization: Bearer %s\r\n\r\n",
		venue, venue, testCallerToken)
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	tlsConn := tls.Client(conn, &tls.Config{RootCAs: caPool, ServerName: venue})
	defer func() { _ = tlsConn.Close() }()
	require.NoError(t, tlsConn.Handshake())

	// The inner request carries NO proxy credential, the way a real agent's
	// request to a venue would not.
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s/api/v3/account", venue), nil)
	require.NoError(t, err)
	require.NoError(t, req.Write(tlsConn))

	inner, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	require.NoError(t, err)
	defer func() { _ = inner.Body.Close() }()

	require.Equal(t, http.StatusOK, inner.StatusCode,
		"a request inside an authenticated tunnel must not be challenged again")
	body, err := io.ReadAll(inner.Body)
	require.NoError(t, err)
	require.Equal(t, "reached the venue", string(body))

	require.True(t, innerSeen)
	require.Empty(t, innerAuth, "the venue must never see our per-customer proxy token")
}
