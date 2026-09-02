package secrets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// ─── The cross-implementation vectors ───────────────────────────────────────
//
// These constants are BYTE-IDENTICAL to the ones in dime-terminal's
// api/terminal/pkg/secrets/envelope_test.go and
// ui/terminal/packages/core/src/credential-envelope.test.ts. They are not a
// round-trip: a round-trip proves this file is self-consistent, which is
// exactly the bug that matters least. Fixed inputs and a fixed expected
// ciphertext prove all three implementations produce the same bytes.
//
// If a change here makes these fail, the format changed, and a format change
// means a new envelope version and re-enrollment for every user — not a
// tweak to the test.
const (
	vectorDataKeyB64    = "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio="
	vectorNonceB64      = "AAECAwQFBgcICQoL"
	vectorPlaintext     = "sk-live-EXAMPLE-not-a-real-key"
	vectorNamespace     = "terminal/prod/gw-alice"
	vectorLabel         = "binance"
	vectorAAD           = "dime-credential/v1/terminal/prod/gw-alice/binance"
	vectorCiphertextB64 = "P0Z5JPVVRhPba0emgvDArkOF5qL4Nss1SaPpaVIAZXZ+MyOyNVuaMzNVt2FE7w=="

	testKMSKeyID = "arn:aws:kms:ap-northeast-1:309666711671:key/f2262ed8-48c0-4d29-865f-3e458aaec804"
	testSecretID = "terminal/prod/gw-alice/binance-1fbd3c58"

	// The wrapped key is opaque to this code — KMS returns the data key — so
	// the tests only need it to be well-formed base64.
	testWrappedKeyB64 = "d3JhcHBlZC1rZXktYnl0ZXM="
)

func TestCredentialAADVector(t *testing.T) {
	assert.Equal(t, vectorAAD, string(credentialAAD(vectorNamespace, vectorLabel)))
}

func TestCredentialAADCanonicalizes(t *testing.T) {
	// The enrollment API restricts labels to [a-z0-9-], so this is a backstop
	// against a second implementation disagreeing over case or stray
	// whitespace, not the primary defence.
	assert.Equal(t, vectorAAD, string(credentialAAD("  Terminal/Prod/GW-Alice ", " BINANCE\n")))
}

// ─── Fakes ──────────────────────────────────────────────────────────────────

type fakeSM struct {
	value string
	err   error
}

func (f fakeSM) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &secretsmanager.GetSecretValueOutput{
		Name:         in.SecretId,
		SecretString: aws.String(f.value),
	}, nil
}

type fakeKMS struct {
	dataKey []byte
	err     error
	// calls records what the source asked KMS for, so the tests can assert
	// which key it selected rather than trusting the happy path.
	calls []kms.DecryptInput
}

func (f *fakeKMS) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	f.calls = append(f.calls, *in)
	if f.err != nil {
		return nil, f.err
	}
	return &kms.DecryptOutput{Plaintext: f.dataKey}, nil
}

// envelopeJSON builds a stored envelope, with overrides for the refusal tests.
func envelopeJSON(t *testing.T, mutate func(m map[string]any)) string {
	t.Helper()
	m := map[string]any{
		"v":           envelopeVersion,
		"alg":         envelopeAlg,
		"kid":         testKMSKeyID,
		"wrapped_key": testWrappedKeyB64,
		"nonce":       vectorNonceB64,
		"ciphertext":  vectorCiphertextB64,
	}
	if mutate != nil {
		mutate(m)
	}
	b, err := json.Marshal(m)
	require.NoError(t, err)
	return string(b)
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	require.NoError(t, err)
	return b
}

// sourceFor builds a kms_sm source over the given fakes and environment.
func sourceFor(t *testing.T, stored string, k *fakeKMS, env map[string]string, cfgYAML string) (secretSource, error) {
	t.Helper()
	if env == nil {
		env = map[string]string{
			envCredentialNamespace: vectorNamespace,
			envCredentialKMSKeyID:  testKMSKeyID,
		}
	}
	b := &kmsSMBuilder{
		smClientFor:  func(context.Context, string) (smClient, error) { return fakeSM{value: stored}, nil },
		kmsClientFor: func(context.Context, string) (kmsClient, error) { return k, nil },
		getenv:       func(key string) string { return env[key] },
	}
	if cfgYAML == "" {
		cfgYAML = fmt.Sprintf("type: kms_sm\nsecret_id: %s\nlabel: %s\n", testSecretID, vectorLabel)
	}
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(cfgYAML), &node))
	return b.Build(*node.Content[0])
}

// ─── The contract ───────────────────────────────────────────────────────────

// The whole point: a blob sealed by the browser, opened here, byte-for-byte.
func TestKMSSMOpensTheSharedVector(t *testing.T) {
	k := &fakeKMS{dataKey: mustDecode(t, vectorDataKeyB64)}
	src, err := sourceFor(t, envelopeJSON(t, nil), k, nil, "")
	require.NoError(t, err)

	got, err := src.Get(context.Background())
	require.NoError(t, err)
	assert.Equal(t, vectorPlaintext, got)

	// The display name is the AWS resource, never the credential.
	assert.Equal(t, testSecretID, src.Name())
}

// The key comes from this pod's configuration, and KeyId is passed so KMS
// ENFORCES it. A blob claiming a different kid must not redirect us.
func TestKMSSMSelectsTheConfiguredKeyNotTheEnvelopes(t *testing.T) {
	k := &fakeKMS{dataKey: mustDecode(t, vectorDataKeyB64)}
	// kid absent entirely: the source must still use the configured key.
	src, err := sourceFor(t, envelopeJSON(t, func(m map[string]any) { delete(m, "kid") }), k, nil, "")
	require.NoError(t, err)
	_, err = src.Get(context.Background())
	require.NoError(t, err)

	require.Len(t, k.calls, 1)
	assert.Equal(t, testKMSKeyID, aws.ToString(k.calls[0].KeyId))
	assert.Equal(t, kmstypes.EncryptionAlgorithmSpecRsaesOaepSha256, k.calls[0].EncryptionAlgorithm)
	assert.Equal(t, mustDecode(t, testWrappedKeyB64), k.calls[0].CiphertextBlob)
}

// A kid naming a different key is an error, not a hint. It means the blob was
// sealed to a key this pod cannot open — usually a config pointing at the
// wrong environment — and it must not reach KMS at all.
func TestKMSSMRefusesAKeyIDMismatch(t *testing.T) {
	k := &fakeKMS{dataKey: mustDecode(t, vectorDataKeyB64)}
	src, err := sourceFor(t, envelopeJSON(t, func(m map[string]any) {
		m["kid"] = "arn:aws:kms:ap-northeast-1:309666711671:key/OTHER"
	}), k, nil, "")
	require.NoError(t, err)

	_, err = src.Get(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "configured for")
	assert.Empty(t, k.calls, "a mismatched kid must be refused before any KMS call")
}

// The AAD is what stops a stored blob being copied into another account's slot
// and opened there — asymmetric kms:Decrypt takes no encryption context, so
// this tag is the only binding. Both halves must be wrong-proof.
func TestKMSSMRefusesTheWrongAADBinding(t *testing.T) {
	t.Run("another account's namespace", func(t *testing.T) {
		k := &fakeKMS{dataKey: mustDecode(t, vectorDataKeyB64)}
		src, err := sourceFor(t, envelopeJSON(t, nil), k, map[string]string{
			envCredentialNamespace: "terminal/prod/gw-bob",
			envCredentialKMSKeyID:  testKMSKeyID,
		}, "")
		require.NoError(t, err)
		_, err = src.Get(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "did not open")
	})

	t.Run("a different label", func(t *testing.T) {
		k := &fakeKMS{dataKey: mustDecode(t, vectorDataKeyB64)}
		src, err := sourceFor(t, envelopeJSON(t, nil), k, nil,
			fmt.Sprintf("type: kms_sm\nsecret_id: %s\nlabel: deribit\n", testSecretID))
		require.NoError(t, err)
		_, err = src.Get(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "did not open")
	})
}

func TestKMSSMRefusesAMalformedEnvelope(t *testing.T) {
	cases := map[string]struct {
		stored string
		want   string
	}{
		"not json":         {stored: "not-an-envelope", want: "not a credential envelope"},
		"empty":            {stored: "", want: "empty value"},
		"wrong version":    {stored: envelopeJSON(t, func(m map[string]any) { m["v"] = 2 }), want: "version 2 is not supported"},
		"wrong alg":        {stored: envelopeJSON(t, func(m map[string]any) { m["alg"] = "AES_256_GCM" }), want: "is not supported"},
		"no wrapped key":   {stored: envelopeJSON(t, func(m map[string]any) { m["wrapped_key"] = "" }), want: "wrapped_key is empty"},
		"nonce not base64": {stored: envelopeJSON(t, func(m map[string]any) { m["nonce"] = "!!!!" }), want: "not standard base64"},
		"short nonce":      {stored: envelopeJSON(t, func(m map[string]any) { m["nonce"] = "AAEC" }), want: "nonce is 3 bytes"},
		// URL-safe base64 is a real interop trap: a browser using
		// base64url would round-trip in its own tests and fail here.
		"url-safe base64": {stored: envelopeJSON(t, func(m map[string]any) {
			m["ciphertext"] = strings.NewReplacer("+", "-", "/", "_").Replace(vectorCiphertextB64)
		}), want: "not standard base64"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			k := &fakeKMS{dataKey: mustDecode(t, vectorDataKeyB64)}
			src, err := sourceFor(t, tc.stored, k, nil, "")
			require.NoError(t, err)
			_, err = src.Get(context.Background())
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestKMSSMRefusesAWrongSizedDataKey(t *testing.T) {
	k := &fakeKMS{dataKey: []byte("too-short")}
	src, err := sourceFor(t, envelopeJSON(t, nil), k, nil, "")
	require.NoError(t, err)
	_, err = src.Get(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "data key is 9 bytes")
}

// Build does static validation only, and every one of these makes the source
// unopenable — so the pipeline must refuse to build rather than fail per
// request. A config that cannot work should not load.
func TestKMSSMBuildRefusesUnworkableConfig(t *testing.T) {
	full := map[string]string{
		envCredentialNamespace: vectorNamespace,
		envCredentialKMSKeyID:  testKMSKeyID,
	}
	cases := map[string]struct {
		cfg  string
		env  map[string]string
		want string
	}{
		"no secret_id": {cfg: "type: kms_sm\nlabel: binance\n", env: full, want: `requires "secret_id"`},
		"no label":     {cfg: "type: kms_sm\nsecret_id: x\n", env: full, want: `requires "label"`},
		"no namespace": {
			cfg:  fmt.Sprintf("type: kms_sm\nsecret_id: %s\nlabel: binance\n", testSecretID),
			env:  map[string]string{envCredentialKMSKeyID: testKMSKeyID},
			want: envCredentialNamespace,
		},
		"no key id": {
			cfg:  fmt.Sprintf("type: kms_sm\nsecret_id: %s\nlabel: binance\n", testSecretID),
			env:  map[string]string{envCredentialNamespace: vectorNamespace},
			want: envCredentialKMSKeyID,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := sourceFor(t, envelopeJSON(t, nil), &fakeKMS{}, tc.env, tc.cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// Nothing on any failure path may carry the credential, the data key or the
// wrapped key — errors become log lines, and a log line is forever.
func TestKMSSMErrorsNeverCarrySecretMaterial(t *testing.T) {
	secretish := []string{vectorPlaintext, vectorDataKeyB64, testWrappedKeyB64, vectorCiphertextB64}

	failures := []struct {
		name string
		run  func() error
	}{
		{"kms refused", func() error {
			k := &fakeKMS{dataKey: mustDecode(t, vectorDataKeyB64), err: errors.New("AccessDeniedException")}
			src, err := sourceFor(t, envelopeJSON(t, nil), k, nil, "")
			require.NoError(t, err)
			_, err = src.Get(context.Background())
			return err
		}},
		{"aad mismatch", func() error {
			k := &fakeKMS{dataKey: mustDecode(t, vectorDataKeyB64)}
			src, err := sourceFor(t, envelopeJSON(t, nil), k, map[string]string{
				envCredentialNamespace: "terminal/prod/gw-bob",
				envCredentialKMSKeyID:  testKMSKeyID,
			}, "")
			require.NoError(t, err)
			_, err = src.Get(context.Background())
			return err
		}},
		{"bad data key", func() error {
			src, err := sourceFor(t, envelopeJSON(t, nil), &fakeKMS{dataKey: []byte("nope")}, nil, "")
			require.NoError(t, err)
			_, err = src.Get(context.Background())
			return err
		}},
	}
	for _, f := range failures {
		t.Run(f.name, func(t *testing.T) {
			err := f.run()
			require.Error(t, err)
			for _, s := range secretish {
				assert.NotContains(t, err.Error(), s)
			}
		})
	}
}

// kms_sm has to be reachable through the same registry every other source
// uses, or a config naming it fails to parse.
func TestKMSSMIsRegistered(t *testing.T) {
	_, ok := defaultRegistry(nil)["kms_sm"]
	assert.True(t, ok, "kms_sm must be in the default source registry")
}
