package secrets

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// A source that carries a label, which only the DIME kms_sm source does in
// production. The label is what the customer called the credential, and it is
// the one identifier a refusal can safely name — so the tests that check it
// need a source that has one.
type labeledFakeBuilder struct{ inner *fakeBuilder }

func (b *labeledFakeBuilder) Build(raw yaml.Node) (secretSource, error) {
	src, err := b.inner.Build(raw)
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Label string `yaml:"label"`
	}
	if err := raw.Decode(&cfg); err != nil {
		return nil, err
	}
	return labeledSource{Source: src, label: cfg.Label}, nil
}

// labeledEnvSource is envSource plus a label.
func labeledEnvSource(t *testing.T, varName, label string) yaml.Node {
	t.Helper()
	return yamlNode(t, map[string]string{"type": "labeled_env", "var": varName, "label": label})
}

// makeLabeledSecrets is makeSecrets with the labeled source registered.
func makeLabeledSecrets(t *testing.T, entries []secretEntry) *Secrets {
	t.Helper()
	reg := testRegistry()
	reg["labeled_env"] = &labeledFakeBuilder{inner: reg["env"].(*fakeBuilder)}
	s, err := newFromConfig(secretsConfig{Secrets: entries}, reg)
	require.NoError(t, err)
	return s
}

// says asserts the body contains a phrase, IGNORING where lines break.
//
// The body is wrapped after substitution, so where a line ends depends on how
// long the hostname was. Asserting on raw substrings makes a test that passes
// or fails on the length of a test fixture's hostname, which is a test of
// nothing. Content is what these assertions are about.
func says(t *testing.T, body, phrase string, why ...any) {
	t.Helper()
	flat := strings.Join(strings.Fields(body), " ")
	want := strings.Join(strings.Fields(phrase), " ")
	require.Contains(t, flat, want, why...)
}

// saysNothingAbout is says' negative, with the same whitespace insensitivity.
func saysNothingAbout(t *testing.T, body, phrase string, why ...any) {
	t.Helper()
	flat := strings.Join(strings.Fields(body), " ")
	want := strings.Join(strings.Fields(phrase), " ")
	require.NotContains(t, flat, want, why...)
}

// readRejection runs the transform, asserts it refused, and returns the body
// and headers the caller would see.
func readRejection(t *testing.T, s *Secrets, req *http.Request) (string, http.Header) {
	t.Helper()
	res, err := s.TransformRequest(context.Background(),
		&transform.TransformContext{Mode: transform.ModeMITM}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
	require.NotNil(t, res.Response, "a refusal with no Response falls back to the pipeline's "+
		"empty 403, which is the thing this whole file exists to stop")
	body, err := io.ReadAll(res.Response.Body)
	require.NoError(t, err)
	return string(body), res.Response.Header
}

// TestRejection_PlaceholderAbsentIsActionable covers the refusal an agent can
// fix, which is the only one where the body's content decides whether it does.
func TestRejection_PlaceholderAbsentIsActionable(t *testing.T) {
	s := makeLabeledSecrets(t, []secretEntry{{
		Source:     labeledEnvSource(t, "OPENAI_API_KEY", "openai-main"),
		Rules:      []hostmatch.RuleConfig{{Host: "api.openai.com"}},
		ProxyValue: "cred-openai-Ab3kQ9zLmNpQrStUvW",
		Require:    true,
	}})

	req := openaiReq("POST", "/v1/chat")
	body, header := readRejection(t, s, req)

	// The four things the agent needs and cannot get anywhere else.
	says(t, body, "cred-openai-Ab3kQ9zLmNpQrStUvW",
		"the placeholder must appear verbatim: it IS the retry")
	says(t, body, "openai-main", "which credential")
	says(t, body, "api.openai.com", "which destination")
	says(t, body, "any request header", "where to put it")

	// And the two instructions that stop an agent making it worse.
	says(t, body, "Do NOT substitute a credential of your own")
	says(t, body, "do not retry this request")

	require.Equal(t, "placeholder_absent", header.Get(rejectionReasonHeader))
	require.Equal(t, "openai-main", header.Get(rejectionLabelHeader))
	require.Equal(t, "no-store", header.Get("Cache-Control"),
		"a cached refusal would fail the corrected retry too")
}

// TestRejection_NeverContainsTheSecret is the assertion that matters most: the
// refusal is handed to the party the credential is being kept from.
func TestRejection_NeverContainsTheSecret(t *testing.T) {
	const realValue = "sk-real-openai-key" // testRegistry's value for OPENAI_API_KEY

	t.Run("placeholder absent", func(t *testing.T) {
		s := makeLabeledSecrets(t, []secretEntry{{
			Source:     labeledEnvSource(t, "OPENAI_API_KEY", "openai-main"),
			Rules:      []hostmatch.RuleConfig{{Host: "api.openai.com"}},
			ProxyValue: "cred-openai-placeholder",
			Require:    true,
		}})
		body, header := readRejection(t, s, openaiReq("GET", "/v1/chat"))
		saysNothingAbout(t, body, realValue)
		require.NotContains(t, strings.Join(header.Values(rejectionLabelHeader), " "), realValue)
	})

	t.Run("secret unavailable", func(t *testing.T) {
		// MISSING is not in testRegistry, so the fetch fails.
		s := makeLabeledSecrets(t, []secretEntry{{
			Source:     labeledEnvSource(t, "MISSING", "openai-main"),
			Rules:      []hostmatch.RuleConfig{{Host: "api.openai.com"}},
			ProxyValue: "cred-openai-placeholder",
			Require:    true,
		}})
		body, _ := readRejection(t, s, openaiReq("GET", "/v1/chat"))
		saysNothingAbout(t, body, realValue)
		// The fetch error names the source and says why. Both belong in the
		// request log, which the agent cannot read, and neither belongs here.
		saysNothingAbout(t, body, "MISSING",
			"the secret's storage identifier is operator detail, not agent detail")
		saysNothingAbout(t, body, "not found")
	})
}

// TestRejection_SecretUnavailableSaysNotYourFault covers the instruction that
// stops an agent varying a request that was never the problem, or reaching for
// a credential of its own when the proxy's one is broken.
func TestRejection_SecretUnavailableSaysNotYourFault(t *testing.T) {
	s := makeLabeledSecrets(t, []secretEntry{{
		Source: labeledEnvSource(t, "MISSING", "openai-main"),
		Rules:  []hostmatch.RuleConfig{{Host: "api.openai.com"}},
		Inject: &injectConfig{Header: "X-Api-Key", Require: true},
	}})

	body, header := readRejection(t, s, openaiReq("GET", "/v1/chat"))
	says(t, body, "NOTHING ABOUT THIS REQUEST CAUSED THIS")
	says(t, body, "changing the request cannot fix it")
	says(t, body, "Do not work around this with a credential of your own")
	require.Equal(t, "secret_unavailable", header.Get(rejectionReasonHeader))

	// No placeholder to offer: this is inject mode, and even in replace mode
	// there would be nothing to retry.
	saysNothingAbout(t, body, "then retry:")
}

// TestRejection_LocationsMatchTheConfig is the assertion that keeps the message
// honest. A body that names a position the transform does not actually scan
// sends an agent looking in the wrong place, which is worse than saying
// nothing — so the description is derived from the same fields the swap reads.
func TestRejection_LocationsMatchTheConfig(t *testing.T) {
	t.Run("no match_headers is the broadest entry, not an empty one", func(t *testing.T) {
		got := placeholderLocations(&resolvedSecret{})
		require.Len(t, got, 1)
		require.Contains(t, got[0], "any request header")
	})

	t.Run("named headers narrow it, and keep the user's casing", func(t *testing.T) {
		got := placeholderLocations(&resolvedSecret{
			matchHeaders: []headerMatcher{{name: "X-Mbx-Apikey", wireName: "X-MBX-APIKEY"}},
		})
		require.Len(t, got, 1)
		require.Contains(t, got[0], "these request headers only: X-MBX-APIKEY")
		require.NotContains(t, got[0], "any request header")
	})

	t.Run("a regex matcher is shown as one", func(t *testing.T) {
		got := placeholderLocations(&resolvedSecret{
			matchHeaders: []headerMatcher{{re: regexp.MustCompile("(?i)x-sig-.*")}},
		})
		require.Contains(t, got[0], "(?i)x-sig-.*")
	})

	t.Run("every extra position is listed, in swap order", func(t *testing.T) {
		got := placeholderLocations(&resolvedSecret{
			matchQuery: true, matchPath: true, matchBody: true,
		})
		require.Equal(t, 4, len(got))
		require.Contains(t, got[1], "query")
		require.Contains(t, got[2], "path")
		require.Contains(t, got[3], "body")
	})

	t.Run("positions that are off are not mentioned", func(t *testing.T) {
		joined := strings.Join(placeholderLocations(&resolvedSecret{}), " ")
		require.NotContains(t, joined, "body")
		require.NotContains(t, joined, "query")
		require.NotContains(t, joined, "path")
	})
}

// TestRejection_WrapsAfterSubstitution guards the bug the first version had:
// hand-wrapped prose looks right until a long hostname is interpolated into it
// and pushes one line to twice the margin while the rest stay put.
func TestRejection_WrapsAfterSubstitution(t *testing.T) {
	long := "some-extremely-long-venue-hostname-that-nobody-would-choose.example.com"
	for _, body := range []string{
		placeholderAbsentBody(long, "a-fairly-long-credential-label", &resolvedSecret{
			proxyValue:   "cred-a-fairly-long-credential-label-Zz9yYxXwWvVuUtTsSr",
			matchHeaders: []headerMatcher{{name: "X-Very-Long-Header-Name-Indeed", wireName: "X-Very-Long-Header-Name-Indeed"}},
			matchBody:    true,
		}),
		secretUnavailableBody(long, "a-fairly-long-credential-label"),
	} {
		for _, line := range strings.Split(body, "\n") {
			// An indented literal (the placeholder) is deliberately never
			// broken, so it is allowed to exceed the margin. Prose is not.
			if strings.HasPrefix(line, "    ") && !strings.Contains(strings.TrimSpace(line), " ") {
				continue
			}
			require.LessOrEqual(t, len([]rune(line)), rejectionWidth,
				"prose must wrap after substitution, not before: %q", line)
		}
	}
}

// TestRejection_NoLabelStillReads covers a source with no label — every source
// but the DIME ones is nameless, and %q of an empty string in the middle of a
// sentence is how that shows up if nobody checks.
func TestRejection_NoLabelStillReads(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Source:     envSource("OPENAI_API_KEY"),
		Rules:      []hostmatch.RuleConfig{{Host: "api.openai.com"}},
		ProxyValue: "cred-openai-placeholder",
		Require:    true,
	}})
	body, header := readRejection(t, s, openaiReq("GET", "/v1/chat"))
	says(t, body, "has a stored credential, which this agent")
	saysNothingAbout(t, body, `""`, "an empty label must not render as empty quotes")
	require.Empty(t, header.Get(rejectionLabelHeader))
}
