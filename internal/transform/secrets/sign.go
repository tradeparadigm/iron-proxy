package secrets

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
)

// The signing schemes this build can dispatch on. The control plane checks the
// same list in four places before a credential is ever stored — see
// pkg/datastore's ValidSignScheme — so a name arriving here that is not in this
// switch means the two sides have drifted, which is why it refuses rather than
// falling back to anything.
const (
	schemeHMACSHA256 = "hmac-sha256"
	schemeECDSAP256  = "ecdsa-p256"
	schemeStark      = "stark"
)

// How the signature is written back into the request.
const (
	encodingHex      = "hex"
	encodingBase64   = "base64"
	encodingFeltPair = "felt-pair"
)

// maxSignPayload caps what a single request may hand over to be signed.
//
// Not a resource limit — signing is cheap — but a shape check. Every scheme
// here signs either a 32-byte digest or a canonical message a venue is about
// to receive, and neither is large. A payload far outside that range is a
// caller doing something other than what this mode is for, and refusing it is
// cheaper than discovering later what it was.
const maxSignPayload = 64 * 1024

// maxSignsPerRequest caps how many signatures one request may produce.
//
// An entry signs at most once, so this only binds when many entries match one
// host. It exists so that a config with a large number of matching credentials
// cannot turn a single request into a bulk signing operation.
const maxSignsPerRequest = 8

// signPayloadHeader is where the caller puts the bytes it wants signed,
// base64-encoded, one header per credential label.
//
// A header of its own rather than a delimiter inside the placeholder: a
// delimiter inside a JSON string value is a parser waiting to disagree with
// itself, and a discrete header is the thing you can actually read back when a
// signature comes out wrong. The proxy STRIPS it before forwarding — the venue
// has no business seeing what we were asked to sign, and leaving it on would
// hand the payload to whoever the request was going to.
func signPayloadHeader(label string) string {
	return "X-Dime-Sign-" + label
}

// signPayload signs payload with key under the named scheme.
//
// THE DIGEST/MESSAGE SPLIT IS ENFORCED, not papered over. An asymmetric scheme
// signs a 32-byte digest and a MAC covers the whole message, and handing one
// the other's input produces a signature the venue rejects with no indication
// of why. Refusing here turns that into an error naming the mismatch, which is
// the difference between a five-minute fix and an afternoon.
func signPayload(scheme, key string, payload []byte) ([]byte, error) {
	switch scheme {
	case schemeECDSAP256:
		if len(payload) != sha256.Size {
			return nil, fmt.Errorf("%s signs a %d-byte digest, got %d bytes: hash the message first",
				schemeECDSAP256, sha256.Size, len(payload))
		}
		priv, err := parseECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		sig, err := ecdsa.SignASN1(rand.Reader, priv, payload)
		if err != nil {
			return nil, errors.New("ecdsa sign failed")
		}
		return sig, nil

	case schemeHMACSHA256:
		k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(key))
		if err != nil {
			return nil, errors.New("hmac key is not valid base64")
		}
		defer zeroise(k)
		if len(k) == 0 {
			return nil, errors.New("hmac key is empty")
		}
		mac := hmac.New(sha256.New, k)
		mac.Write(payload)
		return mac.Sum(nil), nil

	case schemeStark:
		// Deliberately not implemented yet rather than approximated. A STARK
		// signature needs the curve's own scalar arithmetic, and an
		// implementation that is merely close produces signatures a venue
		// rejects — or, worse, leaks the key through a timing or bias flaw
		// nothing here would notice. It arrives as its own change, with test
		// vectors, once a reviewed implementation is chosen.
		return nil, errors.New("the stark scheme is not implemented in this build")

	default:
		return nil, fmt.Errorf("unknown signing scheme %q", scheme)
	}
}

// encodeSignature renders a signature for the wire.
func encodeSignature(encoding string, sig []byte) (string, error) {
	switch encoding {
	case encodingHex, "":
		return hex.EncodeToString(sig), nil
	case encodingBase64:
		return base64.StdEncoding.EncodeToString(sig), nil
	case encodingFeltPair:
		return encodeFeltPair(sig)
	default:
		return "", fmt.Errorf("unknown signature encoding %q", encoding)
	}
}

// encodeFeltPair renders an (r, s) pair as the JSON array of decimal strings
// that Cairo-shaped venues expect: ["<r>","<s>"].
//
// Takes the two halves of a fixed-width pair rather than parsing ASN.1,
// because the schemes that use this encoding produce r and s directly. An
// odd-length signature is a mismatch between scheme and encoding rather than a
// malformed signature, so it says which.
func encodeFeltPair(sig []byte) (string, error) {
	if len(sig) == 0 || len(sig)%2 != 0 {
		return "", fmt.Errorf("felt-pair needs an even-length (r,s) signature, got %d bytes — "+
			"this encoding belongs to the stark scheme", len(sig))
	}
	half := len(sig) / 2
	r := new(big.Int).SetBytes(sig[:half])
	s := new(big.Int).SetBytes(sig[half:])
	return `["` + r.String() + `","` + s.String() + `"]`, nil
}

// parseECPrivateKey accepts SEC1 ("EC PRIVATE KEY") and PKCS#8 ("PRIVATE KEY")
// PEM blocks and requires P-256.
func parseECPrivateKey(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemStr)))
	if block == nil {
		return nil, errors.New("signing key is not PEM")
	}
	var priv *ecdsa.PrivateKey
	if p, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		priv = p
	} else if p8, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		ec, ok := p8.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("signing key is not an EC key")
		}
		priv = ec
	} else {
		return nil, errors.New("could not parse signing key")
	}
	if priv.Curve.Params().Name != "P-256" {
		return nil, fmt.Errorf("unsupported curve %q for %s", priv.Curve.Params().Name, schemeECDSAP256)
	}
	return priv, nil
}

// zeroise overwrites a decoded key so it does not sit in memory after use.
// Best-effort — Go's garbage collector may already have copied it — but the
// copy this function owns is the one that lives longest.
func zeroise(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Machine-readable reasons for the payload faults, for the tooling that would
// rather branch than parse the prose. Distinct values because the three faults
// call for three different responses: supply the bytes, re-encode the bytes,
// or send fewer of them.
const (
	reasonPayloadAbsent     = "sign_payload_absent"
	reasonPayloadMalformed  = "sign_payload_malformed"
	reasonPayloadTooLarge   = "sign_payload_too_large"
	reasonSignMisconfigured = "sign_misconfigured"
)

// signPayloadFor recovers the bytes this request asked to have signed.
//
// Returns the payload, or an empty payload plus a reason code and a `why` —
// one sentence naming the exact thing that was wrong, written to be dropped
// straight into the refusal body. Telling "no header" from "not base64" from
// "too large" is the whole value of this function: all three arrive as a 403,
// and an agent that cannot tell them apart will fix the wrong one.
func (s *Secrets) signPayloadFor(req *http.Request, sec *resolvedSecret) (payload []byte, reason, why string) {
	if sec.label == "" {
		// Unreachable through a loaded config — newFromConfig refuses a
		// labelless sign entry — and kept for a resolvedSecret built by hand.
		return nil, reasonSignMisconfigured,
			"This credential has no label, so there is no payload header for the caller to send. " +
				"That is a fault in the proxy's configuration, not in this request."
	}
	header := signPayloadHeader(sec.label)
	raw := strings.TrimSpace(req.Header.Get(header))
	if raw == "" {
		return nil, reasonPayloadAbsent,
			fmt.Sprintf("The request did not carry the %s header, so there was nothing to sign.", header)
	}
	// Accept both alphabets and both padding conventions. A caller that
	// base64url-encodes is doing something reasonable, and refusing it teaches
	// nothing; Go's decoders differ only in the characters they accept.
	// No zero-length case follows: no non-blank input decodes to zero bytes
	// under any of the four alphabets, so "nothing to sign" is entirely
	// covered by the empty-header check above.
	payload, err := decodeSignPayload(raw)
	if err != nil {
		return nil, reasonPayloadMalformed,
			fmt.Sprintf("The %s header is not valid base64, so the bytes to sign could not "+
				"be recovered. Send the base64 encoding of the raw bytes, not the bytes themselves "+
				"and not a JSON string.", header)
	}
	if len(payload) > maxSignPayload {
		return nil, reasonPayloadTooLarge,
			fmt.Sprintf("The %s header decoded to %d bytes, over this proxy's %d-byte limit. "+
				"Sign a digest or a canonical message, not a whole document.",
				header, len(payload), maxSignPayload)
	}
	return payload, "", ""
}

// decodeSignPayload accepts standard and URL-safe base64, padded or not.
func decodeSignPayload(raw string) ([]byte, error) {
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	var err error
	for _, enc := range encodings {
		var out []byte
		if out, err = enc.DecodeString(raw); err == nil {
			return out, nil
		}
	}
	return nil, err
}

// payloadDigest is the log's handle on what was signed: a short SHA-256
// prefix, hex.
//
// Truncated deliberately. The full digest of a short, low-entropy payload — a
// timestamp, a price — is brute-forceable back to the payload, and this value
// exists to correlate a signature with a request, not to prove what it
// covered. Twelve hex characters is more than enough to be unique within one
// customer's traffic.
func payloadDigest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])[:12]
}

// schemeExpectation says, in the imperative, what this scheme wants handed to
// it. THE LIKELIEST MISTAKE a caller makes is the digest/message split — the
// signer refuses a mismatch rather than returning a wrong answer — so the
// refusal has to state it rather than leave it to be inferred.
func schemeExpectation(scheme string) string {
	switch scheme {
	case schemeECDSAP256:
		return fmt.Sprintf("This credential signs with %s, which covers a %d-byte SHA-256 DIGEST. "+
			"Hash the canonical message first and send the digest, not the message. The signature "+
			"comes back as an ASN.1 DER (r,s) pair.", schemeECDSAP256, sha256.Size)
	case schemeHMACSHA256:
		return fmt.Sprintf("This credential authenticates with %s, which covers the WHOLE MESSAGE. "+
			"Send the exact canonical bytes the venue will verify — do not hash them first.",
			schemeHMACSHA256)
	case schemeStark:
		return fmt.Sprintf("This credential signs with %s, which covers a single field element: the "+
			"Poseidon hash of the venue's typed data, as big-endian bytes.", schemeStark)
	default:
		return fmt.Sprintf("This credential signs with %q.", scheme)
	}
}

// encodingDescription names the form the substituted signature takes, so a
// caller that has to place it inside a JSON structure knows whether it is
// getting a string or an array.
func encodingDescription(encoding string) string {
	switch encoding {
	case encodingBase64:
		return "a base64 string"
	case encodingFeltPair:
		return `a JSON array of two decimal strings, ["<r>","<s>"]`
	default:
		return "a hex string"
	}
}
