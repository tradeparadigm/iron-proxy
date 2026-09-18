package secrets

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	starkcurve "github.com/consensys/gnark-crypto/ecc/stark-curve"
	starkecdsa "github.com/consensys/gnark-crypto/ecc/stark-curve/ecdsa"
	"github.com/consensys/gnark-crypto/ecc/stark-curve/fr"
)

// The signing schemes this build can dispatch on. The control plane checks the
// same list in four places before a credential is ever stored — see
// pkg/datastore's ValidSignScheme — so a name arriving here that is not in this
// switch means the two sides have drifted, which is why it refuses rather than
// falling back to anything.
const (
	schemeHMACSHA256 = "hmac-sha256"
	// schemeHMACSHA512 is the same MAC over SHA-512. Kraken signs with it and
	// nothing else here does; no key encoding or signature encoding can stand
	// in for a different digest, so without the name that venue cannot be
	// enrolled at all.
	schemeHMACSHA512 = "hmac-sha512"
	schemeECDSAP256  = "ecdsa-p256"
	schemeStark      = "stark"
)

// How the signature is written back into the request.
const (
	encodingHex      = "hex"
	encodingBase64   = "base64"
	encodingFeltPair = "felt-pair"
)

// How the STORED KEY is written, which is a different question from the two
// above: those are about the signature going out, this is about the bytes we
// MAC with in the first place.
//
// It exists because the venues disagree and nothing about a key says which it
// is. Binance, Bybit and OKX issue a printable secret whose characters ARE the
// key. Paradigm and Kraken issue the key base64-encoded; Paradigm's documented
// recipe is
//
//	Paradigm-API-Signature: base64(HMAC_SHA256(base64_decode(signing_key), msg))
//
// and its own list of 401 causes names forgetting that decode.
//
// DECLARED PER CREDENTIAL, NEVER SNIFFED, and the comment in the HMAC branch
// below is the argument: base64's alphabet contains every alphanumeric
// character, so a printable secret whose length is a multiple of four is also
// valid base64 and decodes cleanly to unrelated bytes. Guessing produces a
// well-formed signature over the wrong key and a venue error that names
// nothing.
const (
	// keyEncodingRaw uses the stored characters as the key bytes. The DEFAULT,
	// and what an absent key_encoding means — every signing credential written
	// before this field existed relies on that, so it cannot change.
	keyEncodingRaw = "raw"
	// keyEncodingBase64 decodes the stored value first.
	keyEncodingBase64 = "base64"
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
func signPayload(scheme, keyEncoding, key string, payload []byte) ([]byte, error) {
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

	case schemeHMACSHA256, schemeHMACSHA512:
		k, err := hmacKey(keyEncoding, key)
		if err != nil {
			return nil, err
		}
		defer zeroise(k)
		h := sha256.New
		if scheme == schemeHMACSHA512 {
			h = sha512.New
		}
		mac := hmac.New(h, k)
		mac.Write(payload)
		return mac.Sum(nil), nil

	case schemeStark:
		// THE SAME LIBRARY THE VENUE VERIFIES WITH. Paradex's own web-api calls
		// gnark-crypto's stark-curve ecdsa.PublicKey.Verify with a nil hash
		// function, an r||s signature and the felt as the message — so signing
		// here is the exact mirror of that call, not an independent reading of
		// a spec. gnark's Sign also loops until s <= (order-1)/2, and that
		// same Verify rejects a high-s signature, so the low-s convention
		// lines up on both sides rather than by luck.
		if len(payload) != feltBytes {
			return nil, fmt.Errorf("%s signs one field element of exactly %d bytes, got %d: send the "+
				"typed-data message hash as big-endian bytes, not the typed data itself",
				schemeStark, feltBytes, len(payload))
		}
		priv, err := parseStarkPrivateKey(key)
		if err != nil {
			return nil, err
		}
		sig, err := priv.Sign(payload, nil)
		if err != nil {
			return nil, errors.New("stark sign failed")
		}
		// gnark returns r||s, each padded to the scalar size, which is what
		// encodeFeltPair splits. Any other length means the library changed
		// shape under us and the felt pair below would silently mis-split.
		if len(sig) != 2*feltBytes {
			return nil, fmt.Errorf("stark signature is %d bytes, expected %d", len(sig), 2*feltBytes)
		}
		return sig, nil

	default:
		return nil, fmt.Errorf("unknown signing scheme %q", scheme)
	}
}

// hmacKey turns the stored secret into the bytes to MAC with, under the
// encoding the credential declares.
//
// WHY THE ENCODING IS DECLARED RATHER THAN DETECTED. An unconditional decode
// used to live in the HMAC branch and was removed, because it was wrong in the
// one way that cannot be noticed. Binance, Bybit and OKX issue printable
// alphanumeric secrets, and the bytes to MAC with are those characters.
// Decoding one first is not a loud failure: base64's alphabet contains every
// alphanumeric character, so a secret whose length is a multiple of 4 IS valid
// base64 and decodes cleanly to three quarters as many bytes of unrelated data
// — a real 36-character Bybit secret does exactly that, and 36 is the length
// Bybit issues. The MAC is then computed over the wrong key, the venue reports
// only that the signature is bad, and nothing on either side names the
// encoding.
//
// The removal comment said what to do if a venue ever issued a key that really
// was encoded, and this is it: an explicit per-credential encoding rather than
// a rule every caller has to remember, or a guess. Paradigm and Kraken are
// those venues.
//
// WHY THE DECODE IS HERE AND NOT UPSTREAM. Storing decoded bytes would be
// simpler and is a trap. The raw branch below trims, deliberately — a trailing
// newline from a paste is otherwise exactly the silent wrong signature
// described above — and that trim is harmless on printable text and
// destructive on random bytes: measured over 200,000 samples, 4.60% of random
// 32-byte keys begin or end with an ASCII whitespace byte, roughly one in
// twenty-two, silently truncated and signed wrongly. A consistent failure is
// debuggable; a one-in-twenty-two failure is not. So the stored value stays the
// printable text the venue issued, and the decode happens here, once, where the
// encoding is known.
//
// A DECLARED-BASE64 KEY THAT WILL NOT DECODE IS AN ERROR, never a fall back to
// verbatim. Falling back would recreate exactly the silent-wrong-signature
// failure this field exists to remove, and it would do it on the credential
// whose owner had already said which encoding it was.
func hmacKey(keyEncoding, key string) ([]byte, error) {
	// Trimmed before the switch, so both branches see the same string: a
	// trailing newline from a paste breaks a base64 decode as surely as it
	// corrupts a raw MAC.
	trimmed := strings.TrimSpace(key)

	switch keyEncoding {
	case keyEncodingBase64:
		// Padded and unpadded, standard and URL-safe. Permissive here cannot
		// produce a WRONG key the way guessing the encoding can: the alphabets
		// differ only in two characters, and a string containing neither
		// decodes identically under all four, while one containing either
		// fails outright under the alphabets that do not have it. So this
		// accepts more inputs without ever accepting two readings of one.
		decoded, err := decodeSignKey(trimmed)
		if err != nil {
			return nil, fmt.Errorf("this credential declares a base64-encoded key, and the stored "+
				"value is not valid base64: %w. Either the key was pasted in some other form, or "+
				"this credential should be storing it raw — it is NOT re-read as raw here, because "+
				"MAC-ing with the undecoded characters would produce a signature the venue rejects "+
				"with no indication of why", err)
		}
		if len(decoded) == 0 {
			return nil, errors.New("this credential declares a base64-encoded key and the stored " +
				"value decodes to nothing")
		}
		return decoded, nil

	case keyEncodingRaw, "":
		// Empty means raw, and that is not leniency: sign_key_encoding is
		// nullable in the control plane precisely so that a signing credential
		// enrolled before the field existed keeps doing what it has always
		// done. Changing what an absent value means would reinterpret every
		// one of them at once.
		k := []byte(trimmed)
		if len(k) == 0 {
			return nil, errors.New("hmac key is empty")
		}
		return k, nil

	default:
		// Unreachable through a loaded config — validateSign refuses an unknown
		// key encoding — and kept because this function is also the one a test
		// or a hand-built resolvedSecret reaches.
		return nil, fmt.Errorf("unknown signing key encoding %q", keyEncoding)
	}
}

// decodeSignKey accepts standard and URL-safe base64, padded or not, for the
// reason decodeSignPayload does: the four decoders differ only in the two
// characters they accept, so trying them in turn widens what is accepted
// without ever accepting two different readings of the same string.
func decodeSignKey(raw string) ([]byte, error) {
	var err error
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		var out []byte
		if out, err = enc.DecodeString(raw); err == nil {
			return out, nil
		}
	}
	return nil, err
}

// feltBytes is the width of a STARK field element on the wire. The curve's
// order is just under 2^252, so a felt always fits in 32 bytes and is always
// written padded to 32 — which is what the venue hashes and what it verifies
// against.
const feltBytes = 32

// parseStarkPrivateKey builds a signing key from a bare scalar.
//
// NOT PEM, unlike the other asymmetric scheme here. A Starknet key has no
// standard container: every tool in that ecosystem passes the scalar as hex,
// and Paradex's own code formats it as "0x%064x". Demanding PEM would mean
// asking a customer to wrap a value nothing else wraps.
//
// gnark's PrivateKey.SetBytes wants [compressed public key || scalar], so the
// public half is derived here rather than asked for. That also means a
// malformed scalar is caught at this boundary instead of producing a key that
// signs successfully and verifies nowhere.
func parseStarkPrivateKey(key string) (*starkecdsa.PrivateKey, error) {
	raw := strings.TrimSpace(key)
	raw = strings.TrimPrefix(strings.TrimPrefix(raw, "0x"), "0X")
	if raw == "" {
		return nil, errors.New("stark signing key is empty")
	}
	d, ok := new(big.Int).SetString(raw, 16)
	if !ok {
		return nil, errors.New("stark signing key is not a hex scalar")
	}
	if d.Sign() <= 0 || d.Cmp(fr.Modulus()) >= 0 {
		// Zero, negative or beyond the curve order. All three produce a key
		// that is not a key; the last is the one a truncated or doubled paste
		// actually produces.
		return nil, errors.New("stark signing key is out of range for the curve")
	}

	var pub starkcurve.G1Affine
	pub.ScalarMultiplicationBase(d)
	compressed := pub.Bytes()

	buf := make([]byte, len(compressed)+feltBytes)
	copy(buf, compressed[:])
	d.FillBytes(buf[len(compressed):])

	var priv starkecdsa.PrivateKey
	if _, err := priv.SetBytes(buf); err != nil {
		return nil, errors.New("could not build the stark signing key")
	}
	return &priv, nil
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
	case schemeHMACSHA256, schemeHMACSHA512:
		return fmt.Sprintf("This credential authenticates with %s, which covers the WHOLE MESSAGE. "+
			"Send the exact canonical bytes the venue will verify — do not hash them first.",
			scheme)
	case schemeStark:
		return fmt.Sprintf("This credential signs with %s, which covers ONE FIELD ELEMENT of exactly "+
			"%d bytes: the typed-data message hash, big-endian. Compute the venue's message hash "+
			"over its typed data and send that — not the typed data, and not a SHA-256 of it. The "+
			"signature comes back as the (r,s) pair.", schemeStark, feltBytes)
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
