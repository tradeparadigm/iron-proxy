package secrets

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"

	starkcurve "github.com/consensys/gnark-crypto/ecc/stark-curve"
	starkecdsa "github.com/consensys/gnark-crypto/ecc/stark-curve/ecdsa"
	"github.com/consensys/gnark-crypto/ecc/stark-curve/fp"
	"github.com/consensys/gnark-crypto/ecc/stark-curve/fr"
	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// signKeys holds the material a sign test needs: the PEM the proxy is
// configured with, and the public half the test verifies against. A test that
// only checked "a signature came out" would pass against a signer that
// returned a constant, so every happy-path test here verifies.
type signKeys struct {
	pem  string
	pub  *ecdsa.PublicKey
	priv *ecdsa.PrivateKey
}

func newP256Key(t *testing.T) signKeys {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	return signKeys{
		pem:  string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})),
		pub:  &priv.PublicKey,
		priv: priv,
	}
}

// makeSignSecrets builds a Secrets with the labelled source registered and the
// given key material available to it.
func makeSignSecrets(t *testing.T, material map[string]string, entries []secretEntry) *Secrets {
	t.Helper()
	s, err := newSignSecrets(t, material, entries)
	require.NoError(t, err)
	return s
}

// newSignSecrets is makeSignSecrets without the assertion, for the tests that
// are about the config being refused.
func newSignSecrets(t *testing.T, material map[string]string, entries []secretEntry) (*Secrets, error) {
	t.Helper()
	reg := testRegistry()
	base := reg["env"].(*fakeBuilder)
	for k, v := range material {
		base.secrets[k] = v
	}
	reg["labeled_env"] = &labeledFakeBuilder{inner: base}
	return newFromConfig(secretsConfig{Secrets: entries}, reg)
}

// signEntry is the shape every end-to-end test here starts from: one signing
// credential on api.paradex.trade, placeholder in any header.
func signEntry(t *testing.T, varName, label, scheme string, opts ...func(*signConfig)) secretEntry {
	t.Helper()
	cfg := &signConfig{
		ProxyValue: "sign-" + label + "-Ab3kQ9zLmNpQ",
		Scheme:     scheme,
		Require:    true,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	return secretEntry{
		Source: labeledEnvSource(t, varName, label),
		Rules:  []hostmatch.RuleConfig{{Host: "api.paradex.trade"}},
		Sign:   cfg,
	}
}

func paradexReq(t *testing.T, payload []byte, label string) *http.Request {
	t.Helper()
	req := openaiReq("POST", "/v1/auth")
	req.URL.Host = "api.paradex.trade"
	req.Host = "api.paradex.trade"
	if payload != nil {
		req.Header.Set(signPayloadHeader(label), base64.StdEncoding.EncodeToString(payload))
	}
	return req
}

// runSign transforms the request and returns the annotations, asserting the
// request was allowed through.
func runSign(t *testing.T, s *Secrets, req *http.Request) map[string]any {
	t.Helper()
	tctx := &transform.TransformContext{Mode: transform.ModeMITM}
	res, err := s.TransformRequest(t.Context(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	return tctx.DrainAnnotations()
}

// ---------------------------------------------------------------------------
// signPayload: the scheme dispatch and the shape refusals
// ---------------------------------------------------------------------------

// TestSignPayload_ECDSAVerifies is the one that proves a real signature came
// out, not merely some bytes.
func TestSignPayload_ECDSAVerifies(t *testing.T) {
	k := newP256Key(t)
	digest := sha256.Sum256([]byte("the canonical message"))

	sig, err := signPayload(schemeECDSAP256, k.pem, digest[:])
	require.NoError(t, err)
	require.True(t, ecdsa.VerifyASN1(k.pub, digest[:], sig),
		"the signature must verify under the configured key over the exact digest handed in")
}

// TestSignPayload_ECDSARefusesAMessage covers the mistake the whole
// digest/message split exists for. Signing a message as if it were a digest
// produces a signature the venue rejects with no indication of why, so the
// proxy refuses instead.
func TestSignPayload_ECDSARefusesAMessage(t *testing.T) {
	k := newP256Key(t)

	_, err := signPayload(schemeECDSAP256, k.pem, []byte("the canonical message"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "32-byte digest")
	require.Contains(t, err.Error(), "hash the message first",
		"the error has to say what to do, not only what was wrong")
}

func TestSignPayload_ECDSARejectsBadKeys(t *testing.T) {
	digest := sha256.Sum256([]byte("m"))

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalECPrivateKey(p384)
	require.NoError(t, err)
	wrongCurve := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))

	for name, tc := range map[string]struct{ key, want string }{
		"not PEM":     {"sk-just-a-bearer-token", "not PEM"},
		"wrong curve": {wrongCurve, "unsupported curve"},
		"empty":       {"", "not PEM"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := signPayload(schemeECDSAP256, tc.key, digest[:])
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.want)
		})
	}
}

// TestSignPayload_ECDSAAcceptsPKCS8 covers the other PEM shape a key export
// can arrive in. Refusing it would look like a bad key to the customer.
func TestSignPayload_ECDSAAcceptsPKCS8(t *testing.T) {
	k := newP256Key(t)
	der, err := x509.MarshalPKCS8PrivateKey(k.priv)
	require.NoError(t, err)
	pkcs8 := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	digest := sha256.Sum256([]byte("m"))
	sig, err := signPayload(schemeECDSAP256, pkcs8, digest[:])
	require.NoError(t, err)
	require.True(t, ecdsa.VerifyASN1(k.pub, digest[:], sig))
}

// TestSignPayload_HMACMatchesTheStandard checks against the library rather
// than against a value this code produced: a self-consistent MAC that no other
// implementation agrees with is exactly the failure this catches.
func TestSignPayload_HMACMatchesTheStandard(t *testing.T) {
	key := []byte("a shared secret of some length")
	message := []byte("the whole canonical message, unhashed")

	got, err := signPayload(schemeHMACSHA256, string(key), message)
	require.NoError(t, err)

	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	require.Equal(t, mac.Sum(nil), got)
}

// THE STORED SECRET IS THE KEY, and this is the test that says a venue secret
// which happens to be valid base64 is NOT decoded.
//
// Bybit issues 36-character alphanumeric secrets. 36 is a multiple of 4 and
// every alphanumeric character is in base64's alphabet, so such a secret
// decodes cleanly to 27 bytes of unrelated data — no error, no warning, and a
// MAC over the wrong key that only the venue rejects. That was the behaviour
// here until this commit, so the case is pinned rather than left implied.
func TestSignPayload_HMACDoesNotDecodeASecretThatLooksLikeBase64(t *testing.T) {
	secret := "k7Rm2xQ9vBn4rTz8wLpAeF3jHs6dYu1Nc5Gt" // 36 chars, alphanumeric
	require.Len(t, secret, 36)
	require.Zero(t, len(secret)%4, "the shape that makes the old bug silent")
	decoded, err := base64.StdEncoding.DecodeString(secret)
	require.NoError(t, err, "it really is valid base64, which is the whole trap")
	require.Len(t, decoded, 27)

	got, err := signPayload(schemeHMACSHA256, secret, []byte("canonical"))
	require.NoError(t, err)

	want := hmac.New(sha256.New, []byte(secret))
	want.Write([]byte("canonical"))
	require.Equal(t, want.Sum(nil), got, "the secret's own bytes, not its base64 decoding")

	wrong := hmac.New(sha256.New, decoded)
	wrong.Write([]byte("canonical"))
	require.NotEqual(t, wrong.Sum(nil), got, "and emphatically not the decoded bytes")
}

// Surrounding whitespace is trimmed, because a trailing newline off a paste is
// otherwise the same silent wrong-key failure in a different costume.
func TestSignPayload_HMACTrimsSurroundingWhitespace(t *testing.T) {
	got, err := signPayload(schemeHMACSHA256, "  a-secret\n", []byte("m"))
	require.NoError(t, err)

	want := hmac.New(sha256.New, []byte("a-secret"))
	want.Write([]byte("m"))
	require.Equal(t, want.Sum(nil), got)
}

// TestSignPayload_HMACCoversWholeMessages asserts the half of the split that
// the ECDSA test cannot: a MAC must NOT impose a length, because the message
// it covers is whatever the venue will verify.
func TestSignPayload_HMACCoversWholeMessages(t *testing.T) {
	key := "k"
	for _, n := range []int{1, 31, 32, 33, 4096} {
		sig, err := signPayload(schemeHMACSHA256, key, make([]byte, n))
		require.NoError(t, err, "a MAC has no input-length requirement, %d bytes", n)
		require.Len(t, sig, sha256.Size)
	}
}

func TestSignPayload_HMACRejectsBadKeys(t *testing.T) {
	// Only emptiness is left to reject: any other byte string is a usable MAC
	// key, which is precisely why the decode had to go — it was inventing a
	// validity rule the scheme does not have.
	for name, tc := range map[string]struct{ key, want string }{
		"empty":           {"", "is empty"},
		"only whitespace": {"   \n", "is empty"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := signPayload(schemeHMACSHA256, tc.key, []byte("m"))
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestSignPayload_UnknownSchemeRefuses(t *testing.T) {
	_, err := signPayload("ed25519", "k", []byte("m"))
	require.Error(t, err)
	require.Contains(t, err.Error(), `unknown signing scheme "ed25519"`)
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

func TestEncodeSignature(t *testing.T) {
	sig := []byte{0x00, 0xff, 0x10, 0x01}

	for name, tc := range map[string]struct{ encoding, want string }{
		"hex":              {encodingHex, "00ff1001"},
		"default is hex":   {"", "00ff1001"},
		"base64":           {encodingBase64, base64.StdEncoding.EncodeToString(sig)},
		"felt pair splits": {encodingFeltPair, `["255","4097"]`},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := encodeSignature(tc.encoding, sig)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}

	t.Run("unknown", func(t *testing.T) {
		_, err := encodeSignature("der", sig)
		require.Error(t, err)
		require.Contains(t, err.Error(), `unknown signature encoding "der"`)
	})

	// An ASN.1 signature is almost always odd-length, so this is the shape the
	// mismatch actually takes: felt-pair configured against ecdsa-p256.
	t.Run("odd length names the mismatch", func(t *testing.T) {
		_, err := encodeSignature(encodingFeltPair, []byte{1, 2, 3})
		require.Error(t, err)
		require.Contains(t, err.Error(), "even-length")
		require.Contains(t, err.Error(), "stark")
	})

	t.Run("felt pair emits parseable JSON", func(t *testing.T) {
		got, err := encodeSignature(encodingFeltPair, sig)
		require.NoError(t, err)
		var parts []string
		require.NoError(t, json.Unmarshal([]byte(got), &parts),
			"the venue parses this as JSON, so it has to be JSON")
		require.Equal(t, []string{"255", "4097"}, parts)
	})
}

// ---------------------------------------------------------------------------
// Payload recovery
// ---------------------------------------------------------------------------

func TestDecodeSignPayload_AcceptsEveryBase64Alphabet(t *testing.T) {
	// Chosen so the standard and URL-safe alphabets actually differ: this
	// value encodes with a '+' and a '/' under the standard alphabet.
	raw := []byte{0xfb, 0xef, 0xbe}

	for name, encoded := range map[string]string{
		"standard":     base64.StdEncoding.EncodeToString(raw),
		"standard raw": base64.RawStdEncoding.EncodeToString(raw),
		"url":          base64.URLEncoding.EncodeToString(raw),
		"url raw":      base64.RawURLEncoding.EncodeToString(raw),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := decodeSignPayload(encoded)
			require.NoError(t, err)
			require.Equal(t, raw, got)
		})
	}

	t.Run("rejects non-base64", func(t *testing.T) {
		_, err := decodeSignPayload("!!! not base64 !!!")
		require.Error(t, err)
	})
}

func TestPayloadDigest(t *testing.T) {
	d := payloadDigest([]byte("a"))
	require.Len(t, d, 12, "a short prefix, not the whole digest")
	_, err := hex.DecodeString(d)
	require.NoError(t, err, "hex, so it is greppable in a log")
	require.NotEqual(t, d, payloadDigest([]byte("b")))
	require.Equal(t, d, payloadDigest([]byte("a")), "and stable")
}

// ---------------------------------------------------------------------------
// End to end through TransformRequest
// ---------------------------------------------------------------------------

// TestSign_EndToEnd is the whole feature in one test: the agent writes a
// placeholder and hands over bytes, and what leaves the proxy is a signature
// over exactly those bytes, in the right place, with the payload gone.
// AN ORDINARY SOURCE CAN CARRY A LABEL, which is what makes sign mode
// runnable off AWS.
//
// Sign mode needs a label — it is the suffix of the payload header — and only
// kms_sm used to have one, so signing could not be exercised on an env or file
// source at all. Every test in this file worked around it with a synthetic
// `labeled_env` builder, which proves the signer and proves nothing about
// whether a real config can reach it.
func TestResolveSource_LabelOnAnOrdinarySource(t *testing.T) {
	reg := testRegistry()

	node := func(t *testing.T, y string) yaml.Node {
		t.Helper()
		var n yaml.Node
		require.NoError(t, yaml.Unmarshal([]byte(y), &n))
		require.NotEmpty(t, n.Content)
		return *n.Content[0]
	}

	t.Run("an env source takes the label from config", func(t *testing.T) {
		src, err := resolveSource(reg, node(t, "type: env\nvar: OPENAI_API_KEY\nlabel: paradex-testnet-priv-key\n"))
		require.NoError(t, err)
		assert.Equal(t, "paradex-testnet-priv-key", sourceLabel(src))
	})

	t.Run("no label field leaves the source nameless", func(t *testing.T) {
		src, err := resolveSource(reg, node(t, "type: env\nvar: OPENAI_API_KEY\n"))
		require.NoError(t, err)
		assert.Equal(t, "", sourceLabel(src),
			"so sign mode still refuses it at load, which is the existing guard")
	})

	t.Run("a source that labels itself is not wrapped again", func(t *testing.T) {
		// kms_sm reads the SAME "label" key and requires it, because the label
		// is half the envelope's AAD. So the two can never disagree — but the
		// generic wrapper must still stand aside rather than wrap a labelled
		// source in a second label, which would leave two places to look when
		// an AAD mismatch has to be explained.
		reg := testRegistry()
		reg["labeled_env"] = &labeledFakeBuilder{inner: reg["env"].(*fakeBuilder)}
		src, err := resolveSource(reg, node(t, "type: labeled_env\nvar: OPENAI_API_KEY\nlabel: paradex-mainnet-priv-key\n"))
		require.NoError(t, err)
		assert.Equal(t, "paradex-mainnet-priv-key", sourceLabel(src))

		outer, wrapped := src.(labeledSource)
		if wrapped {
			_, twice := outer.Source.(labeledSource)
			assert.False(t, twice, "the builder already labelled it")
		}
	})

	t.Run("the label survives the json_key wrapper", func(t *testing.T) {
		// sourceLabel asserts on the OUTERMOST value, so the ordering of the
		// two wrappers is load-bearing rather than incidental.
		src, err := resolveSource(reg, node(t, "type: env\nvar: OPENAI_API_KEY\njson_key: secret\nlabel: binance\n"))
		require.NoError(t, err)
		assert.Equal(t, "binance", sourceLabel(src))
	})
}

func TestSign_EndToEnd(t *testing.T) {
	k := newP256Key(t)
	s := makeSignSecrets(t,
		map[string]string{"PARADEX_KEY": k.pem},
		[]secretEntry{signEntry(t, "PARADEX_KEY", "paradex", schemeECDSAP256)})

	digest := sha256.Sum256([]byte("POST/v1/auth{}1700000000"))
	req := paradexReq(t, digest[:], "paradex")
	req.Header.Set("PARADEX-STARKNET-SIGNATURE", "sign-paradex-Ab3kQ9zLmNpQ")

	annotations := runSign(t, s, req)

	// 1. The placeholder became a signature over the payload.
	got := req.Header.Get("PARADEX-STARKNET-SIGNATURE")
	require.NotContains(t, got, "sign-paradex", "the placeholder must be gone")
	sig, err := hex.DecodeString(got)
	require.NoError(t, err, "hex is the default encoding")
	require.True(t, ecdsa.VerifyASN1(k.pub, digest[:], sig),
		"and it must verify under the configured key over the payload the caller supplied")

	// 2. The payload header does NOT go to the venue. Leaving it on would hand
	//    the bytes we signed to whoever the request was addressed to.
	require.Empty(t, req.Header.Get(signPayloadHeader("paradex")),
		"the sign payload header must be stripped before forwarding")

	// 3. The audit says a signature went out, where, and over what — by
	//    digest. The payload itself must not be in the log.
	encoded, err := json.Marshal(annotations["signed_into"])
	require.NoError(t, err)
	require.Contains(t, string(encoded), "paradex")
	// Canonicalised, because that is how Go's server hands it to us and how it
	// goes back out; HTTP header names are case-insensitive at both ends.
	require.Contains(t, string(encoded), "header:Paradex-Starknet-Signature")
	require.Contains(t, string(encoded), payloadDigest(digest[:]))
	require.NotContains(t, string(encoded), hex.EncodeToString(digest[:]),
		"the digest prefix identifies the payload; the payload does not go in the log")
	require.Equal(t, outcomeSwapped, annotations["outcome"],
		"a signature substituted into a request is a swap as far as an audit is concerned")
}

// TestSign_HMACEndToEnd covers the other half of the split end to end, since
// the value substituted differs in both length and meaning.
func TestSign_HMACEndToEnd(t *testing.T) {
	// Stored as the venue gives it, which is what an operator pastes.
	key := []byte("shared secret")
	s := makeSignSecrets(t,
		map[string]string{"VENUE_KEY": string(key)},
		[]secretEntry{signEntry(t, "VENUE_KEY", "venue", schemeHMACSHA256,
			func(c *signConfig) { c.Encoding = encodingBase64 })})

	message := []byte("GET\n/orders\n1700000000")
	req := paradexReq(t, message, "venue")
	req.Header.Set("X-Signature", "sign-venue-Ab3kQ9zLmNpQ")

	runSign(t, s, req)

	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	require.Equal(t, base64.StdEncoding.EncodeToString(mac.Sum(nil)),
		req.Header.Get("X-Signature"))
}

// TestSign_SubstitutesInEveryConfiguredPosition proves sign reuses replace's
// scan rather than reimplementing it — the reason the two configs share field
// names in the first place.
func TestSign_SubstitutesInEveryConfiguredPosition(t *testing.T) {
	const key = "k"
	s := makeSignSecrets(t,
		map[string]string{"VENUE_KEY": key},
		[]secretEntry{signEntry(t, "VENUE_KEY", "venue", schemeHMACSHA256, func(c *signConfig) {
			c.MatchBody = true
			c.MatchQuery = true
		})})

	message := []byte("m")
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(message)
	want := hex.EncodeToString(mac.Sum(nil))

	req := paradexReq(t, message, "venue")
	req.URL.RawQuery = "sig=sign-venue-Ab3kQ9zLmNpQ"
	req.Header.Set("X-Signature", "sign-venue-Ab3kQ9zLmNpQ")
	req.Body = transform.NewBufferedBodyFromBytes([]byte(`{"signature":"sign-venue-Ab3kQ9zLmNpQ"}`))

	runSign(t, s, req)

	require.Equal(t, want, req.Header.Get("X-Signature"))
	require.Equal(t, want, req.URL.Query().Get("sig"))
	rewritten, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	require.Contains(t, string(rewritten), want)
	require.NotContains(t, string(rewritten), "sign-venue")
}

// TestSign_DoesNotTouchOtherHosts: a signing credential is scoped like any
// other, and a request elsewhere must pass through untouched — including its
// sign header, which belongs to nobody here.
func TestSign_DoesNotTouchOtherHosts(t *testing.T) {
	k := newP256Key(t)
	s := makeSignSecrets(t,
		map[string]string{"PARADEX_KEY": k.pem},
		[]secretEntry{signEntry(t, "PARADEX_KEY", "paradex", schemeECDSAP256)})

	req := openaiReq("POST", "/v1/chat")
	req.Header.Set(signPayloadHeader("paradex"), "AAAA")
	req.Header.Set("X-Signature", "sign-paradex-Ab3kQ9zLmNpQ")

	annotations := runSign(t, s, req)

	require.Equal(t, "sign-paradex-Ab3kQ9zLmNpQ", req.Header.Get("X-Signature"))
	require.Equal(t, "AAAA", req.Header.Get(signPayloadHeader("paradex")))
	require.Equal(t, outcomePassthrough, annotations["outcome"])
}

// ---------------------------------------------------------------------------
// The refusals, which are the interface an agent actually meets
// ---------------------------------------------------------------------------

// TestSign_RefusalTeachesTheWholeCall is the heart of this feature's
// usability. The agent cannot read the config, the settings page or this code,
// so the refusal is the only place the calling convention exists.
func TestSign_RefusalTeachesTheWholeCall(t *testing.T) {
	k := newP256Key(t)
	s := makeSignSecrets(t,
		map[string]string{"PARADEX_KEY": k.pem},
		[]secretEntry{signEntry(t, "PARADEX_KEY", "paradex", schemeECDSAP256)})

	// No payload header at all: the state an agent that has never seen this
	// mode arrives in.
	body, header := readRejection(t, s, paradexReq(t, nil, "paradex"))

	says(t, body, "api.paradex.trade", "which destination")
	says(t, body, "paradex", "which credential")
	says(t, body, "did not carry the X-Dime-Sign-paradex header", "what was missing")

	// Step 1: the payload, and the shape this scheme needs it in.
	says(t, body, "X-Dime-Sign-paradex: <base64 of the bytes to sign>")
	says(t, body, "32-byte SHA-256 DIGEST")
	says(t, body, "Hash the canonical message first")
	says(t, body, "REMOVES that header before forwarding")

	// Step 2: the placeholder, verbatim, and what it turns into.
	says(t, body, "sign-paradex-Ab3kQ9zLmNpQ", "the placeholder IS the retry")
	says(t, body, "replaces it with the signature, rendered as a hex string")
	says(t, body, "any request header", "where the proxy looks for it")

	// And the guardrails.
	says(t, body, "Do NOT sign with a key of your own")
	says(t, body, "do not retry this request unchanged")

	require.Equal(t, "sign_payload_absent", header.Get(rejectionReasonHeader))
	require.Equal(t, "paradex", header.Get(rejectionLabelHeader))
	require.Equal(t, "no-store", header.Get("Cache-Control"))
}

// TestSign_RefusalNamesTheEncoding: an agent placing a signature inside a JSON
// structure needs to know whether it is getting a string or an array, and
// finding out by trial costs a round trip against a live venue.
func TestSign_RefusalNamesTheEncoding(t *testing.T) {
	s := makeSignSecrets(t,
		map[string]string{"VENUE_KEY": base64.StdEncoding.EncodeToString([]byte("k"))},
		[]secretEntry{signEntry(t, "VENUE_KEY", "venue", schemeHMACSHA256,
			func(c *signConfig) { c.Encoding = encodingFeltPair })})

	body, _ := readRejection(t, s, paradexReq(t, nil, "venue"))

	says(t, body, `a JSON array of two decimal strings, ["<r>","<s>"]`)
	says(t, body, "covers the WHOLE MESSAGE", "the MAC half of the split")
	says(t, body, "do not hash them first")
}

// TestSign_RefusalDistinguishesTheThreePayloadFaults. All three arrive as a
// 403, and an agent that cannot tell them apart fixes the wrong one.
//
// The reason values are written out as LITERALS rather than referenced through
// their constants on purpose. They are a wire contract with whatever branches
// on the header, so a test that compared the header against the same constant
// that produced it would pass no matter what the constants were changed to —
// which is exactly what an earlier version of this test did.
func TestSign_RefusalDistinguishesTheThreePayloadFaults(t *testing.T) {
	k := newP256Key(t)
	s := makeSignSecrets(t,
		map[string]string{"PARADEX_KEY": k.pem},
		[]secretEntry{signEntry(t, "PARADEX_KEY", "paradex", schemeECDSAP256)})

	t.Run("not base64", func(t *testing.T) {
		req := paradexReq(t, nil, "paradex")
		req.Header.Set(signPayloadHeader("paradex"), "!!! raw bytes !!!")
		body, header := readRejection(t, s, req)
		says(t, body, "is not valid base64")
		says(t, body, "not the bytes themselves")
		require.Equal(t, "sign_payload_malformed", header.Get(rejectionReasonHeader),
			"a tool branching on the reason must not read this as a missing header")
	})

	t.Run("present but blank", func(t *testing.T) {
		req := paradexReq(t, nil, "paradex")
		req.Header.Set(signPayloadHeader("paradex"), "   ")
		body, header := readRejection(t, s, req)
		says(t, body, "did not carry the X-Dime-Sign-paradex header",
			"a blank header is the same fault as no header, and reads the same way")
		require.Equal(t, "sign_payload_absent", header.Get(rejectionReasonHeader))
	})

	t.Run("over the limit", func(t *testing.T) {
		req := paradexReq(t, make([]byte, maxSignPayload+1), "paradex")
		body, header := readRejection(t, s, req)
		says(t, body, "over this proxy's 65536-byte limit")
		says(t, body, "not a whole document")
		require.Equal(t, "sign_payload_too_large", header.Get(rejectionReasonHeader))
	})
}

// TestSign_FailureNamesTheShapeMismatch. The likeliest real-world failure: the
// caller sends the message where the scheme wanted a digest. The signer
// refuses rather than returning a signature the venue would reject, and the
// refusal has to say which way round it goes.
func TestSign_FailureNamesTheShapeMismatch(t *testing.T) {
	k := newP256Key(t)
	s := makeSignSecrets(t,
		map[string]string{"PARADEX_KEY": k.pem},
		[]secretEntry{signEntry(t, "PARADEX_KEY", "paradex", schemeECDSAP256)})

	req := paradexReq(t, []byte("the whole unhashed message"), "paradex")
	req.Header.Set("X-Signature", "sign-paradex-Ab3kQ9zLmNpQ")

	body, header := readRejection(t, s, req)

	require.Equal(t, "sign_failed", header.Get(rejectionReasonHeader))
	says(t, body, "could not produce a signature")
	says(t, body, "signs a 32-byte digest, got 26 bytes")
	says(t, body, "Hash the canonical message first")
	says(t, body, "Do NOT sign with a key of your own")

	// The request did not go anywhere, so the placeholder must still be there
	// unchanged — a partially transformed rejected request is a bug waiting to
	// be forwarded by a later refactor.
	require.Equal(t, "sign-paradex-Ab3kQ9zLmNpQ", req.Header.Get("X-Signature"))
}

// TestSign_PayloadIsStrippedEvenOnRefusal. The strip happens before the
// require check, so a refused request cannot carry the payload onward either.
// It matters because a rejection body is built from the request and a later
// change could start echoing headers into it.
func TestSign_PayloadIsStrippedEvenOnRefusal(t *testing.T) {
	k := newP256Key(t)
	s := makeSignSecrets(t,
		map[string]string{"PARADEX_KEY": k.pem},
		[]secretEntry{signEntry(t, "PARADEX_KEY", "paradex", schemeECDSAP256)})

	digest := sha256.Sum256([]byte("m"))
	// Payload present and valid, but NO placeholder anywhere: the swap finds
	// nothing and require refuses.
	req := paradexReq(t, digest[:], "paradex")

	body, header := readRejection(t, s, req)

	require.Equal(t, "placeholder_absent", header.Get(rejectionReasonHeader))
	require.Empty(t, req.Header.Get(signPayloadHeader("paradex")),
		"the payload must be off the request whatever happens next")
	saysNothingAbout(t, body, base64.StdEncoding.EncodeToString(digest[:]))
}

// TestSign_PlaceholderRefusalIsAboutSigning, not about substituting a
// credential. This is the SECOND refusal in the flow — the agent has already
// fixed the payload — and the replace-mode body it used to fall through to
// described the wrong mechanism entirely.
func TestSign_PlaceholderRefusalIsAboutSigning(t *testing.T) {
	k := newP256Key(t)
	s := makeSignSecrets(t,
		map[string]string{"PARADEX_KEY": k.pem},
		[]secretEntry{signEntry(t, "PARADEX_KEY", "paradex", schemeECDSAP256,
			func(c *signConfig) { c.MatchBody = true })})

	// Payload correct, no placeholder anywhere.
	digest := sha256.Sum256([]byte("the auth message hash"))
	body, header := readRejection(t, s, paradexReq(t, digest[:], "paradex"))

	require.Equal(t, "placeholder_absent", header.Get(rejectionReasonHeader),
		"the fault is the same one replace mode has, so the reason code is too")

	// What it must now say.
	says(t, body, "The bytes to sign WERE received and are fine",
		"an agent that cannot tell step 1 worked will go back and change it")
	says(t, body, "sign-paradex-Ab3kQ9zLmNpQ", "the placeholder is still the retry")
	says(t, body, "keep the sign header you already sent")
	says(t, body, "replaces it with the signature, rendered as a hex string")
	says(t, body, "Do NOT sign with a key of your own")

	// And what it must no longer say — the replace-mode story.
	saysNothingAbout(t, body, "substitutes the real credential on the way out",
		"nothing substitutes a credential here; a signature goes in")
	saysNothingAbout(t, body, "Do NOT substitute a credential of your own")
	saysNothingAbout(t, body, "where the credential belongs")
}

// TestSign_RefusalNeverCarriesTheKey. The same assertion the other refusals
// carry, and more load-bearing here: the secret is a private key, and this
// body is handed to the party it is being kept from.
func TestSign_RefusalNeverCarriesTheKey(t *testing.T) {
	k := newP256Key(t)
	s := makeSignSecrets(t,
		map[string]string{"PARADEX_KEY": k.pem},
		[]secretEntry{signEntry(t, "PARADEX_KEY", "paradex", schemeECDSAP256)})

	for name, req := range map[string]*http.Request{
		"no payload":  paradexReq(t, nil, "paradex"),
		"bad shape":   paradexReq(t, []byte("unhashed message"), "paradex"),
		"over limit":  paradexReq(t, make([]byte, maxSignPayload+1), "paradex"),
		"no matchers": paradexReq(t, sha256.New().Sum(nil), "paradex"),
	} {
		t.Run(name, func(t *testing.T) {
			body, _ := readRejection(t, s, req)
			saysNothingAbout(t, body, "PRIVATE KEY")
			saysNothingAbout(t, body, "PARADEX_KEY", "not even the storage identifier")
			for _, line := range strings.Split(k.pem, "\n") {
				if len(line) > 20 {
					saysNothingAbout(t, body, line, "no line of the key may appear")
				}
			}
		})
	}
}

// TestSign_AnnotationsNeverCarryTheKey. The refusal body has its own test; this
// is the other half, and the one easier to forget. sign_error is annotated
// verbatim from signPayload, so anything that error learns to say about the key
// ends up in a log line, and a log line is forever.
func TestSign_AnnotationsNeverCarryTheKey(t *testing.T) {
	k := newP256Key(t)
	s := makeSignSecrets(t,
		map[string]string{"PARADEX_KEY": k.pem},
		[]secretEntry{signEntry(t, "PARADEX_KEY", "paradex", schemeECDSAP256)})

	// A message where a digest was wanted: the path that annotates sign_error.
	req := paradexReq(t, []byte("the whole unhashed message"), "paradex")
	req.Header.Set("X-Signature", "sign-paradex-Ab3kQ9zLmNpQ")

	tctx := &transform.TransformContext{Mode: transform.ModeMITM}
	res, err := s.TransformRequest(t.Context(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)

	encoded, err := json.Marshal(tctx.DrainAnnotations())
	require.NoError(t, err)
	require.Contains(t, string(encoded), "sign_failed", "the annotation under test is present")
	for _, line := range strings.Split(k.pem, "\n") {
		if len(line) > 20 {
			require.NotContains(t, string(encoded), line, "no line of the key may be logged")
		}
	}
	require.NotContains(t, string(encoded), "PRIVATE KEY")
}

// TestSign_LimitRefusalSaysRetryingWillNotHelp. Reachable only through config,
// so the body's job is to stop an agent burning turns on a request it cannot
// fix.
func TestSign_LimitRefusalSaysRetryingWillNotHelp(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("k"))
	material := map[string]string{}
	var entries []secretEntry
	for i := 0; i < maxSignsPerRequest+1; i++ {
		label := string(rune('a'+i)) + "-venue"
		varName := "KEY_" + label
		material[varName] = key
		entries = append(entries, signEntry(t, varName, label, schemeHMACSHA256))
	}
	s := makeSignSecrets(t, material, entries)

	req := paradexReq(t, []byte("m"), "a-venue")
	for i := 0; i < maxSignsPerRequest+1; i++ {
		label := string(rune('a'+i)) + "-venue"
		req.Header.Set(signPayloadHeader(label), base64.StdEncoding.EncodeToString([]byte("m")))
		req.Header.Add("X-Signature-"+label, "sign-"+label+"-Ab3kQ9zLmNpQ")
	}

	body, header := readRejection(t, s, req)

	require.Equal(t, "sign_limit", header.Get(rejectionReasonHeader))
	// The label names the credential that could NOT be served — the one past
	// the budget, not the first one — so an operator reading the log knows
	// which entry to remove.
	overBudget := string(rune('a'+maxSignsPerRequest)) + "-venue"
	require.Equal(t, overBudget, header.Get(rejectionLabelHeader))
	says(t, body, "signs at most 8 times per request")
	says(t, body, "Splitting the work across several requests will not help")
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

// TestSign_ConfigRefusesWhatCouldNeverWork. Each of these produces a proxy
// that loads and then refuses every request to the host, which is
// indistinguishable from an outage — so they are caught at load instead.
func TestSign_ConfigRefusesWhatCouldNeverWork(t *testing.T) {
	k := newP256Key(t)
	material := map[string]string{"PARADEX_KEY": k.pem}

	for name, tc := range map[string]struct {
		entry secretEntry
		want  string
	}{
		"unknown scheme": {
			signEntry(t, "PARADEX_KEY", "paradex", "ed25519"),
			`unknown sign.scheme "ed25519"`,
		},
		"no scheme": {
			signEntry(t, "PARADEX_KEY", "paradex", ""),
			"sign.scheme is required",
		},
		"unknown encoding": {
			signEntry(t, "PARADEX_KEY", "paradex", schemeECDSAP256,
				func(c *signConfig) { c.Encoding = "der" }),
			`unknown sign.encoding "der"`,
		},
		"no placeholder": {
			signEntry(t, "PARADEX_KEY", "paradex", schemeECDSAP256,
				func(c *signConfig) { c.ProxyValue = "" }),
			"sign.proxy_value is required",
		},
		"unlabelled source": {
			secretEntry{
				Source: envSource("OPENAI_API_KEY"),
				Rules:  []hostmatch.RuleConfig{{Host: "api.paradex.trade"}},
				Sign:   &signConfig{ProxyValue: "sign-x-1", Scheme: schemeECDSAP256},
			},
			"needs a labelled credential source",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := newSignSecrets(t, material, []secretEntry{tc.entry})
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.want)
		})
	}
}

// TestSign_ConfigRefusesMoreThanOneMode. sign, replace and inject each say
// something different about what leaves the proxy, and a config that names two
// has no defensible winner.
func TestSign_ConfigRefusesMoreThanOneMode(t *testing.T) {
	k := newP256Key(t)
	for name, entry := range map[string]secretEntry{
		"sign and replace": {
			Source:  labeledEnvSource(t, "PARADEX_KEY", "paradex"),
			Rules:   []hostmatch.RuleConfig{{Host: "api.paradex.trade"}},
			Sign:    &signConfig{ProxyValue: "sign-paradex-1", Scheme: schemeECDSAP256},
			Replace: &replaceConfig{ProxyValue: "cred-paradex-1"},
		},
		"sign and inject": {
			Source: labeledEnvSource(t, "PARADEX_KEY", "paradex"),
			Rules:  []hostmatch.RuleConfig{{Host: "api.paradex.trade"}},
			Sign:   &signConfig{ProxyValue: "sign-paradex-1", Scheme: schemeECDSAP256},
			Inject: &injectConfig{Header: "Authorization"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := newSignSecrets(t, map[string]string{"PARADEX_KEY": k.pem}, []secretEntry{entry})
			require.Error(t, err)
			require.Contains(t, err.Error(), "cannot specify more than one of inject, replace and sign")
		})
	}
}

// TestSign_RequireIsNotOptional. A signing credential with require off would
// let a request through with the placeholder still in it, which the venue
// reads as a bad signature and nobody can debug. The control plane always
// emits require, and this pins that the proxy side honours it.
func TestSign_RequireIsNotOptional(t *testing.T) {
	k := newP256Key(t)
	s := makeSignSecrets(t,
		map[string]string{"PARADEX_KEY": k.pem},
		[]secretEntry{signEntry(t, "PARADEX_KEY", "paradex", schemeECDSAP256,
			func(c *signConfig) { c.Require = false })})

	digest := sha256.Sum256([]byte("m"))
	req := paradexReq(t, digest[:], "paradex")

	// require off, no placeholder: nothing to refuse on, so the request goes
	// through untransformed — and the payload is still stripped.
	annotations := runSign(t, s, req)
	require.Equal(t, outcomePassthrough, annotations["outcome"])
	require.Empty(t, req.Header.Get(signPayloadHeader("paradex")))
}

// ---------------------------------------------------------------------------
// Substituting into a JSON body
// ---------------------------------------------------------------------------

// TestSwapInBody covers the rule directly, because the end-to-end tests below
// can only reach a few of its cases.
func TestSwapInBody(t *testing.T) {
	const ph = "sign-paradex-Ab3kQ9zLmNpQ"
	const feltPair = `["123","456"]`

	for name, tc := range map[string]struct{ body, value, want string }{
		// The case this whole function exists for.
		"felt pair in a quoted JSON field": {
			`{"signature":"` + ph + `","market":"BTC-USD-PERP"}`,
			feltPair,
			`{"signature":"[\"123\",\"456\"]","market":"BTC-USD-PERP"}`,
		},
		// Every value in the fleet today, and both other encodings: nothing to
		// escape, so the output must be what bytes.ReplaceAll produced before.
		"hex is untouched": {
			`{"signature":"` + ph + `"}`,
			"00ff1001",
			`{"signature":"00ff1001"}`,
		},
		"base64 is untouched": {
			`{"sig":"` + ph + `"}`,
			"AP8QAQ==",
			`{"sig":"AP8QAQ=="}`,
		},
		// Not a string literal: no quotes around it, so no escaping.
		"unquoted in JSON stays raw": {
			`{"sig":` + ph + `}`,
			feltPair,
			`{"sig":["123","456"]}`,
		},
		// A quoted placeholder in a body that is not JSON. Escaping here would
		// corrupt a request that works today.
		"quoted in a non-JSON body stays raw": {
			`token="` + ph + `"`,
			feltPair,
			`token="["123","456"]"`,
		},
		// Only one side quoted is not a string literal either.
		"half-quoted stays raw": {
			`{"sig":"` + ph + `}`,
			feltPair,
			`{"sig":"["123","456"]}`,
		},
		// Several occurrences in one body, each judged on its own
		// surroundings rather than on a decision made once for the body.
		"two quoted occurrences": {
			`{"a":"` + ph + `","b":"` + ph + `"}`,
			feltPair,
			`{"a":"[\"123\",\"456\"]","b":"[\"123\",\"456\"]"}`,
		},
		"quoted and unquoted in one body": {
			`{"a":"` + ph + `","b":` + ph + `}`,
			feltPair,
			`{"a":"[\"123\",\"456\"]","b":["123","456"]}`,
		},
		// A replace-mode secret with a quote in it had the same bug.
		"a secret containing a quote": {
			`{"password":"` + ph + `"}`,
			`p"a\ss`,
			`{"password":"p\"a\\ss"}`,
		},
		"absent placeholder is a no-op": {
			`{"signature":"something-else"}`,
			feltPair,
			`{"signature":"something-else"}`,
		},
		// Leading whitespace must not hide the opening brace.
		"indented JSON is still JSON": {
			"\n  {\"sig\":\"" + ph + "\"}",
			feltPair,
			"\n  {\"sig\":\"[\\\"123\\\",\\\"456\\\"]\"}",
		},
		// A top-level array body, which the batch endpoint uses.
		"JSON array body": {
			`[{"sig":"` + ph + `"}]`,
			feltPair,
			`[{"sig":"[\"123\",\"456\"]"}]`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := string(swapInBody([]byte(tc.body), ph, tc.value))
			require.Equal(t, tc.want, got)
		})
	}
}

// TestSwapInBody_ProducesParseableJSON is the assertion that actually matters:
// not what the bytes look like, but that a venue can read them.
func TestSwapInBody_ProducesParseableJSON(t *testing.T) {
	const ph = "sign-paradex-Ab3kQ9zLmNpQ"
	body := `{"market":"BTC-USD-PERP","signature":"` + ph + `","signature_timestamp":1757000000}`

	got := swapInBody([]byte(body), ph, `["123","456"]`)

	var order struct {
		Market    string `json:"market"`
		Signature string `json:"signature"`
		Timestamp int64  `json:"signature_timestamp"`
	}
	require.NoError(t, json.Unmarshal(got, &order),
		"the venue parses this body; unescaped quotes make it unparseable")
	assert.Equal(t, "BTC-USD-PERP", order.Market)
	assert.Equal(t, `["123","456"]`, order.Signature,
		"and the field must decode back to exactly the felt pair the venue expects")
	assert.Equal(t, int64(1757000000), order.Timestamp, "the rest of the body is untouched")
}

// TestSign_ParadexShape is the case that prompted all of this: ONE credential,
// one key, two message types — an auth signature in a header and an order
// signature inside a JSON body. The two need different renderings of the same
// encoding, and the position decides which.
func TestSign_ParadexShape(t *testing.T) {
	const key = "stand-in for the stark key"
	s := makeSignSecrets(t,
		map[string]string{"PARADEX_KEY": key},
		// One entry, scanning headers AND the body, as a Paradex credential
		// has to be configured.
		[]secretEntry{signEntry(t, "PARADEX_KEY", "paradex", schemeHMACSHA256, func(c *signConfig) {
			c.Encoding = encodingFeltPair
			c.MatchBody = true
		})})

	sigFor := func(payload []byte) string {
		mac := hmac.New(sha256.New, []byte(key))
		mac.Write(payload)
		out, err := encodeSignature(encodingFeltPair, mac.Sum(nil))
		require.NoError(t, err)
		return out
	}

	t.Run("auth: signature in a header, unescaped", func(t *testing.T) {
		authPayload := []byte("auth typed data hash")
		req := paradexReq(t, authPayload, "paradex")
		req.URL.Path = "/v1/auth"
		req.Header.Set("PARADEX-STARKNET-SIGNATURE", "sign-paradex-Ab3kQ9zLmNpQ")

		runSign(t, s, req)

		require.Equal(t, sigFor(authPayload), req.Header.Get("PARADEX-STARKNET-SIGNATURE"),
			"a header value is not JSON, so the felt pair goes in as-is")
	})

	t.Run("order: signature in a JSON body, escaped", func(t *testing.T) {
		orderPayload := []byte("order typed data hash")
		req := paradexReq(t, orderPayload, "paradex")
		req.URL.Path = "/v1/orders"
		req.Header.Set("Content-Type", "application/json")
		req.Body = transform.NewBufferedBodyFromBytes([]byte(
			`{"market":"BTC-USD-PERP","side":"BUY","size":"0.1",` +
				`"signature":"sign-paradex-Ab3kQ9zLmNpQ","signature_timestamp":1757000000}`))

		runSign(t, s, req)

		sent, err := io.ReadAll(req.Body)
		require.NoError(t, err)

		var order map[string]any
		require.NoError(t, json.Unmarshal(sent, &order),
			"the order body must still be JSON after the swap")
		require.Equal(t, sigFor(orderPayload), order["signature"],
			"and the signature field must decode back to the felt pair")
		require.Equal(t, "BTC-USD-PERP", order["market"])
	})
}

// ---------------------------------------------------------------------------
// The STARK curve
// ---------------------------------------------------------------------------

// starkKey is a valid scalar, in the form Paradex's own code writes one
// (aux-account-deployer/keys/keypair.go formats keys as "0x%064x").
const starkKey = "0x03c0c075fb3b542a285cb277f46ab9756a7d69181b5e985760a35af798b0c387"

// starkFelt is a message hash as the agent would supply it: the felt from
// typed_data.message_hash(account_address), 32 big-endian bytes.
func starkFelt(t *testing.T, dec string) []byte {
	t.Helper()
	n, ok := new(big.Int).SetString(dec, 10)
	require.True(t, ok)
	out := make([]byte, 32)
	n.FillBytes(out)
	return out
}

// TestSignPayload_StarkVerifiesTheWayParadexVerifies is the test that decides
// whether this scheme works at all.
//
// It does NOT sign and then verify with our own signer — that proves only
// self-consistency, and a signer that is internally consistent and wrong is
// exactly the failure mode here. It reproduces the verification path from
// Paradex's own web-api (api/paradex/web-api/starknet/signature.go): the same
// gnark-crypto stark-curve ecdsa, a public key built from the x coordinate
// alone with y recovered, hFunc nil, and the signature as r||s.
func TestSignPayload_StarkVerifiesTheWayParadexVerifies(t *testing.T) {
	payload := starkFelt(t, "2846891009026995430665703316224827616914889274105712248413538305735679628177")

	sig, err := signPayload(schemeStark, starkKey, payload)
	require.NoError(t, err)
	require.Len(t, sig, 64, "r||s, each padded to the scalar size")

	// Rebuild the verifier the way the venue does: from the x coordinate only.
	priv, err := parseStarkPrivateKey(starkKey)
	require.NoError(t, err)
	pubX := priv.PublicKey.A.X

	var pub starkecdsa.PublicKey
	pub.A.X = pubX
	pub.A.Y = *recoverStarkY(t, &pubX)

	ok, err := pub.Verify(sig, payload, nil)
	require.NoError(t, err)
	require.True(t, ok,
		"a signature the venue's own verification path rejects is worse than no signature")
}

// recoverStarkY solves y² = x³ + x + b for y, which is what Paradex's
// PublicKey.Verify does when given only an x coordinate. Either root works —
// verification tries both — so this returns one and the caller may need the
// negation; the test below pins that we picked a root that verifies.
func recoverStarkY(t *testing.T, x *fp.Element) *fp.Element {
	t.Helper()
	var ySquared fp.Element
	ySquared.Mul(x, x).Mul(&ySquared, x)
	ySquared.Add(&ySquared, x)
	_, b := starkcurve.CurveCoefficients()
	ySquared.Add(&ySquared, &b)
	y := ySquared.Sqrt(&ySquared)
	require.NotNil(t, y, "x is not on the curve")

	// Pick the root matching the real key, so the assertion above is about the
	// signature rather than about which square root we happened to take.
	priv, err := parseStarkPrivateKey(starkKey)
	require.NoError(t, err)
	if !y.Equal(&priv.PublicKey.A.Y) {
		y.Neg(y)
	}
	return y
}

// TestSignPayload_StarkIsLowS. Paradex verifies with gnark, and gnark's Verify
// REFUSES a signature whose s is above (order-1)/2. Our signer must therefore
// produce low-s, and it does because it is the same library — this pins that
// the property is actually present rather than assumed.
func TestSignPayload_StarkIsLowS(t *testing.T) {
	half := new(big.Int).Rsh(fr.Modulus(), 1)
	for i := 0; i < 32; i++ {
		payload := starkFelt(t, fmt.Sprintf("%d", 1000000007+i))
		sig, err := signPayload(schemeStark, starkKey, payload)
		require.NoError(t, err)
		s := new(big.Int).SetBytes(sig[32:])
		require.LessOrEqual(t, s.Cmp(half), 0,
			"high-s signature %d would be rejected by the venue", i)
	}
}

// TestSignPayload_StarkRendersAsAFeltPair ties the scheme to the encoding the
// venue actually reads: PARADEX-STARKNET-SIGNATURE and the order body's
// "signature" field are both ["<r>","<s>"] as decimal strings.
func TestSignPayload_StarkRendersAsAFeltPair(t *testing.T) {
	payload := starkFelt(t, "2846891009026995430665703316224827616914889274105712248413538305735679628177")
	sig, err := signPayload(schemeStark, starkKey, payload)
	require.NoError(t, err)

	out, err := encodeSignature(encodingFeltPair, sig)
	require.NoError(t, err)

	var parts []string
	require.NoError(t, json.Unmarshal([]byte(out), &parts))
	require.Len(t, parts, 2)
	r, ok := new(big.Int).SetString(parts[0], 10)
	require.True(t, ok, "r must be a decimal string")
	s, ok := new(big.Int).SetString(parts[1], 10)
	require.True(t, ok, "s must be a decimal string")
	require.Equal(t, new(big.Int).SetBytes(sig[:32]), r)
	require.Equal(t, new(big.Int).SetBytes(sig[32:]), s)
}

// TestSignPayload_StarkRefusesTheWrongInput. The felt is the whole message as
// far as this scheme is concerned, and anything else is a caller that has not
// hashed the typed data.
func TestSignPayload_StarkRefusesTheWrongInput(t *testing.T) {
	for name, payload := range map[string][]byte{
		"a whole message": []byte("the typed data, unhashed"),
		"too short":       make([]byte, 31),
		"too long":        make([]byte, 33),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := signPayload(schemeStark, starkKey, payload)
			require.Error(t, err)
			require.Contains(t, err.Error(), "one field element of exactly 32 bytes")
			require.Contains(t, err.Error(), "message hash")
		})
	}
}

// TestParseStarkPrivateKey covers what a customer might paste.
func TestParseStarkPrivateKey(t *testing.T) {
	t.Run("accepts what Paradex's own tooling emits", func(t *testing.T) {
		with0x, err := parseStarkPrivateKey(starkKey)
		require.NoError(t, err)
		// Bare hex, no padding, and stray whitespace are all the same key.
		for _, variant := range []string{
			strings.TrimPrefix(starkKey, "0x"),
			"  " + starkKey + "\n",
			"0x" + strings.TrimLeft(strings.TrimPrefix(starkKey, "0x"), "0"),
		} {
			got, err := parseStarkPrivateKey(variant)
			require.NoError(t, err, variant)
			require.Equal(t, with0x.PublicKey.A.X, got.PublicKey.A.X,
				"%q must derive the same key", variant)
		}
	})

	for name, tc := range map[string]struct{ key, want string }{
		"empty":         {"", "is empty"},
		"only 0x":       {"0x", "is empty"},
		"not hex":       {"0xnot-a-scalar", "not a hex scalar"},
		"a PEM key":     {"-----BEGIN EC PRIVATE KEY-----", "not a hex scalar"},
		"zero":          {"0x0", "out of range"},
		"at the order":  {"0x800000000000010ffffffffffffffffffb781126dcae7b2321e66a241adc64d2f", "out of range"},
		"doubled paste": {strings.Repeat("f", 128), "out of range"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseStarkPrivateKey(tc.key)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.want)
		})
	}
}
