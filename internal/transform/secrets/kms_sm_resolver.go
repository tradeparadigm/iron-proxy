package secrets

// kms_sm — the DIME fork's secret source.
//
// It reads a sealed *envelope* from AWS Secrets Manager and opens it locally,
// rather than reading a plaintext secret. That inversion is the point of the
// fork: the service that STORES a user's credential (dime-terminal's web-api)
// holds PutSecretValue and neither GetSecretValue nor kms:Decrypt, so it writes
// what it cannot read. This proxy holds the other half. Nobody but the
// customer's own proxy pod can turn a stored blob back into a credential.
//
// The envelope is sealed in the user's BROWSER to a published KMS public key:
// a random AES-256 key encrypts the credential, and that key is wrapped to the
// public half with RSA-OAEP-SHA-256. (RSA-4096 OAEP tops out near 446 bytes,
// so wrapping the credential directly would rule out PEM keys.)
//
// FORMAT IS A CONTRACT ACROSS THREE IMPLEMENTATIONS: this file, Go's
// api/terminal/pkg/secrets/envelope.go, and the browser's
// ui/terminal/packages/core/src/credential-envelope.ts. A disagreement does
// not fail here — it fails at injection time, long after the user enrolled,
// as a credential that cannot be opened. The fixed vectors in
// kms_sm_resolver_test.go are byte-identical to the other two suites for
// exactly that reason; if you change anything in this file, those vectors are
// what tell you whether you changed the format.
//
// WHERE EACH INPUT COMES FROM, and why it matters:
//
//   - secret_id, label   per credential, from the control-plane config.
//   - namespace, key id  from THIS POD'S OWN ENVIRONMENT, never the config.
//
// The second line is load-bearing. The AAD binding the ciphertext is
// "dime-credential/v1/<namespace>/<label>", and asymmetric kms:Decrypt takes
// no encryption context, so the AAD is the only thing stopping a stored blob
// being copied into another account's slot and opened there. If the control
// plane supplied the namespace, a compromised control plane could name another
// account's namespace and undo that. Taking it from the deployment — the
// per-customer Helm release sets it — means the proxy's own identity decides
// what it is able to open. The same argument applies to the KMS key id: the
// opener's configuration picks the key, never the blob.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"gopkg.in/yaml.v3"
)

const (
	// envCredentialNamespace and envCredentialKMSKeyID are the deployment's
	// half of the inputs — see the package comment. Read at Build time, so a
	// pod missing either refuses to build its pipeline instead of failing
	// every request at runtime: without them no kms_sm secret can ever open,
	// and a config that cannot work should not load.
	envCredentialNamespace = "DIME_CREDENTIAL_NAMESPACE"
	envCredentialKMSKeyID  = "DIME_CREDENTIAL_KMS_KEY_ID"

	// envelopeVersion and envelopeAlg are checked EXACTLY, not as a minimum.
	// A silent mismatch between implementations surfaces as an unopenable
	// credential; a loud one surfaces as a refused request with a name in the
	// log.
	envelopeVersion = 1
	envelopeAlg     = "RSA_OAEP_SHA_256+AES_256_GCM"

	// envelopeKeyLen is AES-256; envelopeNonceLen is GCM's 96-bit nonce, the
	// only size WebCrypto interoperates on without special handling.
	envelopeKeyLen   = 32
	envelopeNonceLen = 12

	// envelopeMaxCiphertext bounds what is handed to GCM. A venue credential
	// is tens to hundreds of bytes; this is generous for a PEM key and small
	// enough that a malformed or hostile blob cannot make us allocate.
	envelopeMaxCiphertext = 64 << 10

	// credentialAADPrefix is the AAD's fixed leader. Versioned separately from
	// the envelope so the binding can change without the wire format doing so.
	credentialAADPrefix = "dime-credential/v1/"
)

// envelope is the sealed credential exactly as stored. Byte fields are
// standard base64 WITH padding — what the browser's btoa emits and what
// base64.StdEncoding reads. One encoding to agree on, no URL-safe variant.
type envelope struct {
	Version int    `json:"v"`
	Alg     string `json:"alg"`
	// KeyID is diagnostic only. It is NEVER used to select a decryption key:
	// the key comes from this pod's configuration, and a mismatch is an error
	// rather than a hint. Trusting it would let whoever wrote the blob choose
	// the key it is opened with.
	KeyID      string `json:"kid,omitempty"`
	WrappedKey string `json:"wrapped_key"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// credentialAAD builds the additional authenticated data binding a ciphertext
// to the namespace and label it was enrolled under. Canonicalized the same way
// on all three sides: the enrollment API restricts labels to [a-z0-9-], so
// this is a backstop against one implementation disagreeing over case or stray
// whitespace, not the primary defence.
func credentialAAD(namespace, label string) []byte {
	canon := func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
	return []byte(credentialAADPrefix + canon(namespace) + "/" + canon(label))
}

// kmsClient is the subset of the AWS KMS API this source uses.
type kmsClient interface {
	Decrypt(ctx context.Context, in *kms.DecryptInput, opts ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// kmsSMBuilder opens sealed envelopes stored in Secrets Manager.
type kmsSMBuilder struct {
	smClientFor  func(ctx context.Context, region string) (smClient, error)
	kmsClientFor func(ctx context.Context, region string) (kmsClient, error)
	getenv       func(string) string
	logger       *slog.Logger
}

type kmsSMConfig struct {
	Type     string `yaml:"type"`
	SecretID string `yaml:"secret_id"`
	// Label is the credential's user-chosen name, and the second half of the
	// AAD. It must be the label the credential was enrolled under or the GCM
	// tag fails — which is the intended behaviour when a config names the
	// wrong one.
	Label      string `yaml:"label"`
	Region     string `yaml:"region,omitempty"`
	TTL        string `yaml:"ttl,omitempty"`
	FailureTTL string `yaml:"failure_ttl,omitempty"`
}

func newKMSSMBuilder(logger *slog.Logger) *kmsSMBuilder {
	smCache := &awsClientCache[smClient]{
		clients:   make(map[string]smClient),
		newClient: func(cfg aws.Config) smClient { return secretsmanager.NewFromConfig(cfg) },
	}
	kmsCache := &awsClientCache[kmsClient]{
		clients:   make(map[string]kmsClient),
		newClient: func(cfg aws.Config) kmsClient { return kms.NewFromConfig(cfg) },
	}
	return &kmsSMBuilder{
		smClientFor:  smCache.get,
		kmsClientFor: kmsCache.get,
		getenv:       os.Getenv,
		logger:       logger,
	}
}

func (r *kmsSMBuilder) Build(raw yaml.Node) (secretSource, error) {
	var cfg kmsSMConfig
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing kms_sm source config: %w", err)
	}
	if cfg.SecretID == "" {
		return nil, fmt.Errorf("kms_sm source requires \"secret_id\" field")
	}
	if cfg.Label == "" {
		// Without a label there is no AAD, and with no AAD nothing opens. A
		// config that cannot work must not load.
		return nil, fmt.Errorf("kms_sm source requires \"label\" field (it is half the AAD the envelope is bound to)")
	}
	namespace := strings.TrimSpace(r.getenv(envCredentialNamespace))
	if namespace == "" {
		return nil, fmt.Errorf("kms_sm source requires %s in this pod's environment: it is half the AAD, and is deliberately NOT taken from the config", envCredentialNamespace)
	}
	keyID := strings.TrimSpace(r.getenv(envCredentialKMSKeyID))
	if keyID == "" {
		return nil, fmt.Errorf("kms_sm source requires %s in this pod's environment: the opener's configuration selects the key, never the stored blob", envCredentialKMSKeyID)
	}

	// The display name is the secret id, matching aws_sm. It names an AWS
	// resource, never a credential, so it is safe in a log line.
	return buildLazySource(cfg.SecretID, cfg.TTL, cfg.FailureTTL, r.logger, func(ctx context.Context) (string, error) {
		return r.fetchAndOpen(ctx, cfg, namespace, keyID)
	})
}

// fetchAndOpen reads the envelope and opens it. Every error path names the
// secret and the reason and NOTHING else: the wrapped key, the data key and
// the credential never reach an error string or a log line.
func (r *kmsSMBuilder) fetchAndOpen(ctx context.Context, cfg kmsSMConfig, namespace, keyID string) (string, error) {
	smc, err := r.smClientFor(ctx, cfg.Region)
	if err != nil {
		return "", fmt.Errorf("creating AWS SM client: %w", err)
	}
	out, err := smc.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(cfg.SecretID),
	})
	if err != nil {
		return "", fmt.Errorf("fetching sealed credential %q: %w", cfg.SecretID, err)
	}
	raw := aws.ToString(out.SecretString)
	if raw == "" {
		return "", fmt.Errorf("sealed credential %q resolved to an empty value", cfg.SecretID)
	}

	env, err := parseEnvelope(raw, keyID)
	if err != nil {
		return "", fmt.Errorf("sealed credential %q: %w", cfg.SecretID, err)
	}
	wrapped, nonce, ct, err := env.decodeParts()
	if err != nil {
		return "", fmt.Errorf("sealed credential %q: %w", cfg.SecretID, err)
	}

	kmsc, err := r.kmsClientFor(ctx, cfg.Region)
	if err != nil {
		return "", fmt.Errorf("creating AWS KMS client: %w", err)
	}
	// KeyId is supplied even though the blob identifies its own key: passing
	// it makes KMS ENFORCE that the wrapped key was sealed to the key this pod
	// is configured for, rather than opening whatever it was handed.
	dec, err := kmsc.Decrypt(ctx, &kms.DecryptInput{
		KeyId:               aws.String(keyID),
		CiphertextBlob:      wrapped,
		EncryptionAlgorithm: kmstypes.EncryptionAlgorithmSpecRsaesOaepSha256,
	})
	if err != nil {
		return "", fmt.Errorf("sealed credential %q: unwrapping the data key failed: %w", cfg.SecretID, err)
	}
	dataKey := dec.Plaintext
	// Best effort: Go cannot promise the bytes are gone from memory, but not
	// leaving a live AES key in a heap object for the GC to move around later
	// costs one line.
	defer func() {
		for i := range dataKey {
			dataKey[i] = 0
		}
	}()
	if len(dataKey) != envelopeKeyLen {
		return "", fmt.Errorf("sealed credential %q: unwrapped data key is %d bytes, want %d", cfg.SecretID, len(dataKey), envelopeKeyLen)
	}

	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return "", fmt.Errorf("sealed credential %q: %w", cfg.SecretID, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("sealed credential %q: %w", cfg.SecretID, err)
	}
	plain, err := aead.Open(nil, nonce, ct, credentialAAD(namespace, cfg.Label))
	if err != nil {
		// The tag covers the namespace and label, so this is what a blob
		// copied from another account — or named with the wrong label — looks
		// like. Say which binding was attempted; both parts are public.
		return "", fmt.Errorf("sealed credential %q did not open under namespace %q label %q: it was sealed for something else, or the stored bytes are damaged",
			cfg.SecretID, namespace, cfg.Label)
	}
	if len(plain) == 0 {
		return "", fmt.Errorf("sealed credential %q opened to an empty value", cfg.SecretID)
	}
	return string(plain), nil
}

// parseEnvelope decodes and validates the envelope's static shape.
func parseEnvelope(raw, wantKeyID string) (envelope, error) {
	var env envelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		return envelope{}, fmt.Errorf("stored value is not a credential envelope: %w", err)
	}
	if env.Version != envelopeVersion {
		return envelope{}, fmt.Errorf("envelope version %d is not supported (this build opens version %d only)", env.Version, envelopeVersion)
	}
	if env.Alg != envelopeAlg {
		return envelope{}, fmt.Errorf("envelope alg %q is not supported (this build opens %q only)", env.Alg, envelopeAlg)
	}
	// A kid that disagrees with our configured key is an error, not a hint to
	// follow. It means the blob was sealed to a different key than this pod
	// can open — most likely a config pointing at the wrong environment — and
	// guessing would be worse than refusing.
	if env.KeyID != "" && env.KeyID != wantKeyID {
		return envelope{}, fmt.Errorf("envelope names key %q but this pod is configured for %q", env.KeyID, wantKeyID)
	}
	return env, nil
}

// decodeParts base64-decodes the three byte fields and checks their sizes.
func (e envelope) decodeParts() (wrapped, nonce, ciphertext []byte, err error) {
	dec := func(field, s string) ([]byte, error) {
		if s == "" {
			return nil, fmt.Errorf("envelope %s is empty", field)
		}
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("envelope %s is not standard base64: %w", field, err)
		}
		return b, nil
	}
	if wrapped, err = dec("wrapped_key", e.WrappedKey); err != nil {
		return nil, nil, nil, err
	}
	if nonce, err = dec("nonce", e.Nonce); err != nil {
		return nil, nil, nil, err
	}
	if ciphertext, err = dec("ciphertext", e.Ciphertext); err != nil {
		return nil, nil, nil, err
	}
	if len(nonce) != envelopeNonceLen {
		return nil, nil, nil, fmt.Errorf("envelope nonce is %d bytes, want %d", len(nonce), envelopeNonceLen)
	}
	if len(ciphertext) > envelopeMaxCiphertext {
		return nil, nil, nil, fmt.Errorf("envelope ciphertext is %d bytes, over the %d limit", len(ciphertext), envelopeMaxCiphertext)
	}
	return wrapped, nonce, ciphertext, nil
}
