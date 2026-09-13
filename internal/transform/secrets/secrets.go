// Package secrets implements a transform that swaps proxy tokens for real
// secrets on outbound requests, scoped to allowed hosts.
package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/headers"
	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func init() {
	transform.Register("secrets", factory)
}

// secretsConfig is the YAML config structure.
type secretsConfig struct {
	Secrets []secretEntry `yaml:"secrets"`
}

type secretEntry struct {
	Source  yaml.Node              `yaml:"source"`
	Rules   []hostmatch.RuleConfig `yaml:"rules"`
	Inject  *injectConfig          `yaml:"inject,omitempty"`
	Replace *replaceConfig         `yaml:"replace,omitempty"`
	Sign    *signConfig            `yaml:"sign,omitempty"`

	// Deprecated top-level fields for backwards compatibility.
	// Users should migrate to the replace block.
	ProxyValue   string   `yaml:"proxy_value,omitempty"`
	MatchHeaders []string `yaml:"match_headers,omitempty"`
	MatchBody    bool     `yaml:"match_body,omitempty"`
	Require      bool     `yaml:"require,omitempty"`
}

type replaceConfig struct {
	ProxyValue   string   `yaml:"proxy_value"`
	MatchHeaders []string `yaml:"match_headers,omitempty"`
	MatchBody    bool     `yaml:"match_body,omitempty"`
	MatchPath    bool     `yaml:"match_path,omitempty"`
	MatchQuery   bool     `yaml:"match_query,omitempty"`
	Require      bool     `yaml:"require,omitempty"`
}

// signConfig is replace's shape plus the two things that make it signing: the
// algorithm to use, and how the signature is written back. The scan fields are
// replace's and deliberately spelled the same, because finding the placeholder
// IS the same operation — only the substituted value differs.
type signConfig struct {
	ProxyValue   string   `yaml:"proxy_value"`
	Scheme       string   `yaml:"scheme"`
	Encoding     string   `yaml:"encoding,omitempty"`
	MatchHeaders []string `yaml:"match_headers,omitempty"`
	MatchBody    bool     `yaml:"match_body,omitempty"`
	MatchPath    bool     `yaml:"match_path,omitempty"`
	MatchQuery   bool     `yaml:"match_query,omitempty"`
	Require      bool     `yaml:"require,omitempty"`
}

type injectConfig struct {
	Header     string `yaml:"header,omitempty"`
	QueryParam string `yaml:"query_param,omitempty"`
	Formatter  string `yaml:"formatter,omitempty"`
	// Require rejects the request when the secret is unavailable. When
	// false (default), an unavailable secret is skipped silently.
	Require bool `yaml:"require,omitempty"`
}

// resolvedSecret is a secret ready for use after config parsing and source resolution.
type resolvedSecret struct {
	source secretSource
	mode   string // "replace", "inject" or "sign"
	rules  []hostmatch.Rule

	// replace mode fields
	proxyValue   string
	matchHeaders []headerMatcher // empty = all headers
	matchBody    bool
	matchPath    bool
	matchQuery   bool
	require      bool

	// inject mode fields
	injectHeader     string
	injectQueryParam string
	formatter        *template.Template // nil = identity (raw value)

	// sign mode fields. The scan fields above are shared with replace; these
	// two say what to substitute rather than where.
	scheme   string
	encoding string
	// label names the payload header the caller hands the bytes over in. Read
	// off the source rather than configured, so the two sides cannot disagree
	// about it.
	label string
}

// headerMatcher selects request headers to scan. Exactly one of name or re is set.
type headerMatcher struct {
	name     string         // canonical header name; "" if regex
	wireName string         // header name with the user's original casing; "" if regex
	re       *regexp.Regexp // nil if literal name match
}

// parseHeaderMatchers compiles match_headers entries. Patterns delimited by
// "/.../" are compiled as case-insensitive regular expressions matched against
// canonical header names; all other entries are literal header names. Literal
// names are matched case-insensitively (via canonicalization) but the user's
// original casing is preserved when writing the header back over the wire.
func parseHeaderMatchers(patterns []string, ctx string) ([]headerMatcher, error) {
	if len(patterns) == 0 {
		return nil, nil
	}
	matchers := make([]headerMatcher, 0, len(patterns))
	for _, p := range patterns {
		if len(p) >= 2 && strings.HasPrefix(p, "/") && strings.HasSuffix(p, "/") {
			re, err := regexp.Compile("(?i)" + p[1:len(p)-1])
			if err != nil {
				return nil, fmt.Errorf("%s: invalid match_headers regex %q: %w", ctx, p, err)
			}
			matchers = append(matchers, headerMatcher{re: re})
			continue
		}
		matchers = append(matchers, headerMatcher{name: http.CanonicalHeaderKey(p), wireName: p})
	}
	return matchers, nil
}

// formatterData is the template context for inject formatters.
type formatterData struct {
	Value string
}

var formatterFuncs = template.FuncMap{
	"base64": func(parts ...string) string {
		return base64.StdEncoding.EncodeToString([]byte(strings.Join(parts, "")))
	},
}

// Secrets is the transform that swaps proxy tokens for real secrets.
type Secrets struct {
	secrets []resolvedSecret
}

func factory(cfg yaml.Node, logger *slog.Logger) (transform.Transformer, error) {
	var c secretsConfig
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing secrets config: %w", err)
	}
	return newFromConfig(c, defaultRegistry(logger))
}

// defaultRegistry returns the standard set of secret source builders. It is
// used by both the secrets transform's factory and by BuildSource so other
// transforms can compose the same sources.
func defaultRegistry(logger *slog.Logger) sourceBuilderRegistry {
	return sourceBuilderRegistry{
		"env":               newEnvBuilder(logger),
		"file":              newFileBuilder(logger),
		"control_plane":     newControlPlaneBuilder(logger),
		"aws_sm":            newAWSSMBuilder(logger),
		"kms_sm":            newKMSSMBuilder(logger),
		"aws_ssm":           newAWSSSMBuilder(logger),
		"1password":         newOPBuilder(logger),
		"1password_connect": newOPConnectBuilder(logger),
	}
}

// BuildSource constructs a secret Source from a yaml node shaped like a
// top-level "source:" block (e.g. {type: env, var: FOO}). It is intended for
// other transforms that want to load their inputs from any registered
// secrets backend (1Password, AWS SM, etc.).
func BuildSource(node yaml.Node, logger *slog.Logger) (Source, error) {
	return resolveSource(defaultRegistry(logger), node)
}

// jsonKeyHint peeks at the optional json_key field, common to every source
// type. When set, the source's value is parsed as a JSON object and the
// single top-level string field at that key is extracted.
type jsonKeyHint struct {
	JSONKey string `yaml:"json_key"`
}

// resolveSource dispatches a source config through the registry and applies
// the optional json_key extraction, which is available to every source type.
func resolveSource(registry sourceBuilderRegistry, node yaml.Node) (secretSource, error) {
	var hint sourceTypeHint
	if err := node.Decode(&hint); err != nil {
		return nil, fmt.Errorf("parsing source type: %w", err)
	}
	if hint.Type == "" {
		return nil, fmt.Errorf("source.type is required")
	}
	builder, ok := registry[hint.Type]
	if !ok {
		return nil, fmt.Errorf("unsupported source type %q", hint.Type)
	}
	src, err := builder.Build(node)
	if err != nil {
		return nil, err
	}
	var jk jsonKeyHint
	if err := node.Decode(&jk); err != nil {
		return nil, fmt.Errorf("parsing json_key: %w", err)
	}
	if jk.JSONKey != "" {
		src = &jsonKeySource{inner: src, key: jk.JSONKey}
	}
	return src, nil
}

// newFromConfig creates a Secrets transform from a parsed config.
func newFromConfig(cfg secretsConfig, registry sourceBuilderRegistry) (*Secrets, error) {
	resolved := make([]resolvedSecret, 0, len(cfg.Secrets))

	for i, entry := range cfg.Secrets {
		// Normalize legacy top-level fields into a replace block.
		replace, inject, sign, err := normalizeEntry(i, &entry)
		if err != nil {
			return nil, err
		}

		source, err := resolveSource(registry, entry.Source)
		if err != nil {
			return nil, fmt.Errorf("secrets[%d]: %w", i, err)
		}

		rules, err := hostmatch.CompileRules(entry.Rules, fmt.Sprintf("secrets[%d]", i))
		if err != nil {
			return nil, err
		}

		if inject != nil {
			sec := resolvedSecret{
				source:           source,
				mode:             "inject",
				rules:            rules,
				require:          inject.Require,
				injectHeader:     inject.Header,
				injectQueryParam: inject.QueryParam,
			}
			if inject.Formatter != "" {
				tmpl, err := template.New(fmt.Sprintf("secrets[%d]", i)).Funcs(formatterFuncs).Parse(inject.Formatter)
				if err != nil {
					return nil, fmt.Errorf("secrets[%d]: parsing formatter template: %w", i, err)
				}
				sec.formatter = tmpl
			}
			resolved = append(resolved, sec)
		} else if sign != nil {
			matchers, err := parseHeaderMatchers(sign.MatchHeaders, fmt.Sprintf("secrets[%d]", i))
			if err != nil {
				return nil, err
			}
			// The payload header is named after the credential, so a sign
			// entry whose source has no label has no header for the caller to
			// use and can never produce a signature. validateSign cannot see
			// this — the label belongs to the source, not the sign block — so
			// it is checked here, where the source is resolved, and refused at
			// load for the same reason validateSign refuses an unknown scheme:
			// a config that loads and then rejects every request to the host
			// is indistinguishable from an outage.
			label := sourceLabel(source)
			if label == "" {
				return nil, fmt.Errorf("secrets[%d]: sign mode needs a labelled credential source; "+
					"%q has no label, so there is no %s header for the caller to send",
					i, source.Name(), signPayloadHeader("<label>"))
			}
			resolved = append(resolved, resolvedSecret{
				source:       source,
				mode:         "sign",
				proxyValue:   sign.ProxyValue,
				scheme:       sign.Scheme,
				encoding:     sign.Encoding,
				matchHeaders: matchers,
				matchBody:    sign.MatchBody,
				matchPath:    sign.MatchPath,
				matchQuery:   sign.MatchQuery,
				require:      sign.Require,
				rules:        rules,
				label:        label,
			})
		} else {
			matchers, err := parseHeaderMatchers(replace.MatchHeaders, fmt.Sprintf("secrets[%d]", i))
			if err != nil {
				return nil, err
			}
			resolved = append(resolved, resolvedSecret{
				source:       source,
				mode:         "replace",
				proxyValue:   replace.ProxyValue,
				matchHeaders: matchers,
				matchBody:    replace.MatchBody,
				matchPath:    replace.MatchPath,
				matchQuery:   replace.MatchQuery,
				require:      replace.Require,
				rules:        rules,
			})
		}
	}

	return &Secrets{secrets: resolved}, nil
}

// normalizeEntry validates the entry and returns either a replaceConfig or injectConfig.
// It handles legacy top-level fields by normalizing them into a replaceConfig.
func normalizeEntry(i int, entry *secretEntry) (*replaceConfig, *injectConfig, *signConfig, error) {
	hasLegacy := entry.ProxyValue != "" || len(entry.MatchHeaders) > 0 || entry.MatchBody || entry.Require
	hasReplace := entry.Replace != nil
	hasInject := entry.Inject != nil
	hasSign := entry.Sign != nil

	// Count how many modes are specified.
	modeCount := 0
	if hasLegacy {
		modeCount++
	}
	if hasReplace {
		modeCount++
	}
	if hasInject {
		modeCount++
	}
	if hasSign {
		modeCount++
	}

	if modeCount == 0 {
		return nil, nil, nil, fmt.Errorf("secrets[%d]: must specify inject, replace or sign", i)
	}
	if modeCount > 1 {
		if hasLegacy && hasReplace {
			return nil, nil, nil, fmt.Errorf("secrets[%d]: cannot use both top-level proxy_value/match_headers and replace block", i)
		}
		if hasLegacy && hasInject {
			return nil, nil, nil, fmt.Errorf("secrets[%d]: cannot use both top-level proxy_value/match_headers and inject block", i)
		}
		return nil, nil, nil, fmt.Errorf("secrets[%d]: cannot specify more than one of inject, replace and sign", i)
	}

	if hasInject {
		if err := validateInject(i, entry.Inject); err != nil {
			return nil, nil, nil, err
		}
		return nil, entry.Inject, nil, nil
	}

	if hasSign {
		if err := validateSign(i, entry.Sign); err != nil {
			return nil, nil, nil, err
		}
		return nil, nil, entry.Sign, nil
	}

	if hasReplace {
		if entry.Replace.ProxyValue == "" {
			return nil, nil, nil, fmt.Errorf("secrets[%d]: replace.proxy_value is required", i)
		}
		return entry.Replace, nil, nil, nil
	}

	// Legacy top-level fields: normalize into replaceConfig.
	if entry.ProxyValue == "" {
		return nil, nil, nil, fmt.Errorf("secrets[%d]: proxy_value is required", i)
	}
	return &replaceConfig{
		ProxyValue:   entry.ProxyValue,
		MatchHeaders: entry.MatchHeaders,
		MatchBody:    entry.MatchBody,
		Require:      entry.Require,
	}, nil, nil, nil
}

// validateSign refuses a sign block that could not produce a signature.
//
// The scheme is checked HERE, at config load, rather than at the first matching
// request. A config that parses and then refuses every request to a
// credentialed host is indistinguishable from an outage; a config that refuses
// to load names the entry and the value, and the proxy keeps serving whatever
// it had before.
func validateSign(i int, cfg *signConfig) error {
	if cfg.ProxyValue == "" {
		return fmt.Errorf("secrets[%d]: sign.proxy_value is required", i)
	}
	switch cfg.Scheme {
	case schemeHMACSHA256, schemeECDSAP256, schemeStark:
	case "":
		return fmt.Errorf("secrets[%d]: sign.scheme is required", i)
	default:
		return fmt.Errorf("secrets[%d]: unknown sign.scheme %q", i, cfg.Scheme)
	}
	switch cfg.Encoding {
	case encodingHex, encodingBase64, encodingFeltPair, "":
	default:
		return fmt.Errorf("secrets[%d]: unknown sign.encoding %q", i, cfg.Encoding)
	}
	return nil
}

func validateInject(i int, cfg *injectConfig) error {
	hasHeader := cfg.Header != ""
	hasQuery := cfg.QueryParam != ""

	if !hasHeader && !hasQuery {
		return fmt.Errorf("secrets[%d]: inject must specify either header or query_param", i)
	}
	if hasHeader && hasQuery {
		return fmt.Errorf("secrets[%d]: inject cannot specify both header and query_param", i)
	}
	return nil
}

// sourceLabel reads the optional operator-facing name off a source. Only the
// DIME sources carry one; an env or file source is nameless.
func sourceLabel(src Source) string {
	if l, ok := src.(interface{ Label() string }); ok {
		return l.Label()
	}
	return ""
}

func (s *Secrets) Name() string { return "secrets" }

func (s *Secrets) TransformRequest(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	// The MITM CONNECT pre-flight is not a request this transform can act on.
	//
	// An HTTPS request through the tunnel is seen TWICE. First as a CONNECT
	// carrying nothing but a destination — no method, path, application headers
	// or body, because they are still inside a TLS session that has not been
	// negotiated yet. Then, after the proxy terminates that TLS, as the real
	// request with everything present.
	//
	// The pipeline runs at both points, and at the first one every question
	// this transform asks is unanswerable:
	//
	//   - replace + require REJECTED every such connection, because it looked
	//     for its proxy_value in a request that cannot carry one and treated
	//     absence as the workload trying to bypass the swap. A replace secret
	//     was therefore unusable through the tunnel: 403 on CONNECT, and the
	//     real request never got a chance to present the placeholder it had.
	//   - inject FETCHED AND DECRYPTED the secret to write it onto a synthetic
	//     request that is then discarded — a KMS call and a plaintext secret in
	//     memory per connection, for a mutation nothing reads.
	//
	// Continuing here costs no enforcement: the real request runs the identical
	// code path a moment later with its headers, body and path intact, so
	// require still refuses a workload that omits the placeholder, and inject
	// still attaches the secret. It just happens where the answer means
	// something.
	//
	// SNI-only mode is deliberately NOT skipped. There, the synthetic host-only
	// request is the only one there will ever be — the proxy peeks the SNI and
	// passes the encrypted stream through untouched — so the check here is the
	// only check, and require refusing a credentialed host it cannot inject
	// into is the honest outcome rather than a false negative.
	if tctx != nil && tctx.Mode == transform.ModeMITM && req.Method == http.MethodConnect {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}

	type secretRecord struct {
		Secret string `json:"secret"`
		// Label is the credential's user-chosen name, when its source has one
		// (see labeledSource). Secret names an AWS resource; an audit read by
		// a person needs the name the person chose.
		Label     string   `json:"label,omitempty"`
		Locations []string `json:"locations"`
		// Digest identifies WHAT was signed, for sign mode only: a short
		// SHA-256 prefix over the payload, never the payload. Enough to tie a
		// signature in a venue's logs to a request in ours, and not enough to
		// reconstruct what it covered.
		Digest string `json:"digest,omitempty"`
	}
	labelOf := sourceLabel
	var swapped, injected, signed []secretRecord
	// Bounded per request rather than per entry: many entries can match one
	// host, and the cap is about what a single request may become.
	signsLeft := maxSignsPerRequest
	var unavailable []string

	for _, sec := range s.secrets {
		if !hostmatch.MatchAnyRule(sec.rules, req) {
			continue
		}

		name := sec.source.Name()
		realValue, err := sec.source.Get(ctx)
		if err != nil {
			if sec.require {
				label := labelOf(sec.source)
				tctx.Annotate("rejected", name)
				tctx.Annotate("label", label)
				tctx.Annotate("reject_reason", "secret_unavailable")
				tctx.Annotate("outcome", outcomeRejected)
				// The fetch error itself stays HERE, in the log the operator
				// reads. It can name a secret identifier, an IAM denial or a
				// KMS failure, none of which the agent needs and some of which
				// it should not be handed.
				tctx.Annotate("fetch_error", err.Error())
				return &transform.TransformResult{
					Action: transform.ActionReject,
					Response: rejection(req, "secret_unavailable", label,
						secretUnavailableBody(rejectionHost(req), label)),
				}, nil
			}
			unavailable = append(unavailable, name)
			continue
		}

		if sec.mode == "inject" {
			locations, err := s.injectSecret(req, &sec, realValue)
			if err != nil {
				return nil, fmt.Errorf("injecting secret %q: %w", name, err)
			}
			if len(locations) > 0 {
				injected = append(injected, secretRecord{Secret: name, Label: labelOf(sec.source), Locations: locations})
			}
			continue
		}

		// SIGN MODE substitutes a computed value, and everything after this
		// point is replace's code unchanged — the scan, the positions, the
		// require refusal. Only what gets written differs, which is the whole
		// reason the config shares replace's field names.
		swapValue := realValue
		var signDigest string
		if sec.mode == "sign" {
			// The budget is checked BEFORE the payload, because it does not
			// depend on what the caller sent: it is a property of how many
			// signing credentials are configured for this host. Checking it
			// second would report a payload fault on a request that was going
			// to be refused for the config either way, and send the agent
			// chasing its own request.
			if signsLeft <= 0 {
				tctx.Annotate("rejected", name)
				tctx.Annotate("label", sec.label)
				tctx.Annotate("reject_reason", "sign_limit")
				tctx.Annotate("outcome", outcomeRejected)
				return &transform.TransformResult{
					Action: transform.ActionReject,
					Response: rejection(req, "sign_limit", sec.label,
						signLimitBody(rejectionHost(req))),
				}, nil
			}
			signsLeft--

			payload, reason, why := s.signPayloadFor(req, &sec)
			if why != "" {
				tctx.Annotate("rejected", name)
				tctx.Annotate("label", sec.label)
				tctx.Annotate("reject_reason", reason)
				tctx.Annotate("outcome", outcomeRejected)
				return &transform.TransformResult{
					Action: transform.ActionReject,
					Response: rejection(req, reason, sec.label,
						signPayloadAbsentBody(rejectionHost(req), why, &sec)),
				}, nil
			}

			sig, err := signPayload(sec.scheme, realValue, payload)
			if err != nil {
				// The signing error names the scheme and the shape it wanted,
				// and none of it is about the key — so unlike a fetch failure
				// this one is safe, and useful, to hand back.
				tctx.Annotate("rejected", name)
				tctx.Annotate("label", sec.label)
				tctx.Annotate("reject_reason", "sign_failed")
				tctx.Annotate("outcome", outcomeRejected)
				tctx.Annotate("sign_error", err.Error())
				return &transform.TransformResult{
					Action: transform.ActionReject,
					Response: rejection(req, "sign_failed", sec.label,
						signFailedBody(rejectionHost(req), sec.scheme, err)),
				}, nil
			}
			encoded, err := encodeSignature(sec.encoding, sig)
			if err != nil {
				tctx.Annotate("rejected", name)
				tctx.Annotate("label", sec.label)
				tctx.Annotate("reject_reason", "sign_failed")
				tctx.Annotate("outcome", outcomeRejected)
				tctx.Annotate("sign_error", err.Error())
				return &transform.TransformResult{
					Action: transform.ActionReject,
					Response: rejection(req, "sign_failed", sec.label,
						signFailedBody(rejectionHost(req), sec.scheme, err)),
				}, nil
			}
			swapValue = encoded

			// STRIPPED WHATEVER HAPPENS NEXT. The venue has no business seeing
			// what we were asked to sign, and a payload left on the request is
			// handed to whoever it was going to. Removed here rather than after
			// a successful swap, so the require refusal below cannot forward it
			// either.
			req.Header.Del(signPayloadHeader(sec.label))

			// Recorded on the entry's own record below rather than annotated
			// here. Several entries can sign in one request, and a per-entry
			// annotation under a single key would leave only the last.
			signDigest = payloadDigest(payload)
		}

		var locations []string
		locations = append(locations, s.swapHeaders(req, &sec, swapValue)...)

		if sec.matchQuery {
			locations = append(locations, s.swapQuery(req, &sec, swapValue)...)
		}

		if sec.matchPath {
			if loc := s.swapPath(req, &sec, swapValue); loc != "" {
				locations = append(locations, loc)
			}
		}

		if sec.matchBody {
			if loc := s.swapBody(req, &sec, swapValue); loc != "" {
				locations = append(locations, loc)
			}
		}

		if len(locations) > 0 {
			rec := secretRecord{Secret: name, Label: labelOf(sec.source), Locations: locations}
			if sec.mode == "sign" {
				rec.Digest = signDigest
				signed = append(signed, rec)
			} else {
				swapped = append(swapped, rec)
			}
		} else if sec.require {
			// require + nothing matched: the workload sent a request to a
			// credentialed host WITHOUT the placeholder. Refusing is the
			// point — it stops a workload bypassing the swap with a
			// credential of its own — so the reason is worth naming, not
			// just the rejection.
			//
			// This is also the ONE refusal the caller can fix, so it carries
			// the placeholder and the positions scanned. See reject.go for why
			// that is safe to hand over and why an opaque 403 was not.
			label := labelOf(sec.source)
			tctx.Annotate("rejected", name)
			tctx.Annotate("label", label)
			tctx.Annotate("reject_reason", "placeholder_absent")
			tctx.Annotate("outcome", outcomeRejected)
			// Same fault, so the same reason code — a tool branching on it is
			// asking "was the placeholder there", and the answer is no either
			// way. Only the explanation differs, because the two modes put
			// different things where the placeholder was.
			body := placeholderAbsentBody(rejectionHost(req), label, &sec)
			if sec.mode == "sign" {
				body = signPlaceholderAbsentBody(rejectionHost(req), label, &sec)
			}
			return &transform.TransformResult{
				Action:   transform.ActionReject,
				Response: rejection(req, "placeholder_absent", label, body),
			}, nil
		}
	}

	if len(swapped) > 0 {
		tctx.Annotate("swapped", swapped)
	}
	if len(injected) > 0 {
		tctx.Annotate("injected", injected)
	}
	if len(signed) > 0 {
		tctx.Annotate("signed_into", signed)
	}
	if len(unavailable) > 0 {
		tctx.Annotate("secret_unavailable", unavailable)
	}
	// outcome is annotated on EVERY request, including the ones this
	// transform did nothing to. An audit has to be able to group and alert on
	// "a credential left the proxy" versus "it did not", and a state that
	// exists only as the absence of three other fields is neither greppable
	// nor alertable. passthrough is the value that was previously unsayable.
	tctx.Annotate("outcome", requestOutcome(len(injected) > 0, len(swapped) > 0 || len(signed) > 0))

	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

// Outcome values. A closed set, so a log pipeline can enumerate them.
const (
	// outcomeRejected: the request did not go upstream.
	outcomeRejected = "rejected"
	// outcomeInjected: the proxy attached a credential the client never sent.
	outcomeInjected = "injected"
	// outcomeSwapped: the proxy replaced a placeholder the client did send.
	outcomeSwapped = "swapped"
	// outcomeBoth: one request carried both, which is legal with several
	// entries matching one host. Kept as its own value rather than picking a
	// winner, because "which" would then be a lie.
	outcomeBoth = "injected+swapped"
	// outcomePassthrough: the request went upstream with nothing of ours in
	// it. The value that matters most for an audit, and the one that used to
	// be invisible.
	outcomePassthrough = "passthrough"
)

func requestOutcome(injected, swapped bool) string {
	switch {
	case injected && swapped:
		return outcomeBoth
	case injected:
		return outcomeInjected
	case swapped:
		return outcomeSwapped
	default:
		return outcomePassthrough
	}
}

func (s *Secrets) injectSecret(req *http.Request, sec *resolvedSecret, realValue string) ([]string, error) {
	formatted, err := s.formatValue(sec, realValue)
	if err != nil {
		return nil, err
	}

	var locations []string
	if sec.injectHeader != "" {
		headers.Set(req.Header, sec.injectHeader, formatted)
		locations = append(locations, "header:"+sec.injectHeader)
	}
	if sec.injectQueryParam != "" {
		q := req.URL.Query()
		q.Set(sec.injectQueryParam, formatted)
		req.URL.RawQuery = q.Encode()
		locations = append(locations, "query:"+sec.injectQueryParam)
	}
	return locations, nil
}

func (s *Secrets) formatValue(sec *resolvedSecret, realValue string) (string, error) {
	if sec.formatter == nil {
		return realValue, nil
	}
	var buf strings.Builder
	if err := sec.formatter.Execute(&buf, formatterData{Value: realValue}); err != nil {
		return "", fmt.Errorf("executing formatter: %w", err)
	}
	return buf.String(), nil
}

func (s *Secrets) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (s *Secrets) swapHeaders(req *http.Request, sec *resolvedSecret, realValue string) []string {
	var locations []string
	if len(sec.matchHeaders) == 0 {
		for name, vals := range req.Header {
			for i, v := range vals {
				if headerContains(name, v, sec.proxyValue) {
					req.Header[name][i] = replaceInHeader(name, v, sec.proxyValue, realValue)
					locations = append(locations, "header:"+name)
				}
			}
		}
		return locations
	}

	processed := make(map[string]struct{})
	// swap scans the header identified by its canonical name and, on a match,
	// rewrites it under wireName so the user's requested casing is sent over
	// the wire. For regex matches wireName is the header's existing casing.
	swap := func(canonical, wireName string) {
		if _, done := processed[canonical]; done {
			return
		}
		processed[canonical] = struct{}{}
		hit := false
		headers.Swap(req.Header, canonical, wireName, func(v string) string {
			if headerContains(canonical, v, sec.proxyValue) {
				hit = true
			}
			return replaceInHeader(canonical, v, sec.proxyValue, realValue)
		})
		if hit {
			locations = append(locations, "header:"+wireName)
		}
	}
	for _, m := range sec.matchHeaders {
		if m.re != nil {
			for name := range req.Header {
				if m.re.MatchString(name) {
					swap(name, name)
				}
			}
			continue
		}
		swap(m.name, m.wireName)
	}
	return locations
}

// replaceInHeader performs a secret replacement in a header value. For
// Authorization headers with HTTP Basic auth, the base64 payload is decoded
// before replacement and re-encoded after.
func replaceInHeader(headerName, value, proxyValue, realValue string) string {
	if strings.EqualFold(headerName, "Authorization") {
		if decoded, ok := decodeBasicAuth(value); ok {
			replaced := strings.ReplaceAll(decoded, proxyValue, realValue)
			return "Basic " + base64.StdEncoding.EncodeToString([]byte(replaced))
		}
	}
	return strings.ReplaceAll(value, proxyValue, realValue)
}

// headerContains checks whether a header value contains the proxy token.
// For Authorization headers with HTTP Basic auth, the base64 payload is
// decoded before checking.
func headerContains(headerName, value, proxyValue string) bool {
	if strings.EqualFold(headerName, "Authorization") {
		if decoded, ok := decodeBasicAuth(value); ok {
			return strings.Contains(decoded, proxyValue)
		}
	}
	return strings.Contains(value, proxyValue)
}

// decodeBasicAuth extracts and base64-decodes the payload from a "Basic ..."
// Authorization header value. Returns the decoded string and true on success.
func decodeBasicAuth(value string) (string, bool) {
	after, ok := strings.CutPrefix(value, "Basic ")
	if !ok {
		return "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(after)
	if err != nil {
		return "", false
	}
	return string(decoded), true
}

func (s *Secrets) swapQuery(req *http.Request, sec *resolvedSecret, realValue string) []string {
	raw := req.URL.RawQuery
	if raw == "" || !strings.Contains(raw, sec.proxyValue) {
		return nil
	}

	params, err := url.ParseQuery(raw)
	if err != nil {
		return nil
	}

	var locations []string
	for key, vals := range params {
		for i, v := range vals {
			if strings.Contains(v, sec.proxyValue) {
				params[key][i] = strings.ReplaceAll(v, sec.proxyValue, realValue)
				locations = append(locations, "query:"+key)
			}
		}
	}

	if len(locations) > 0 {
		req.URL.RawQuery = params.Encode()
	}
	return locations
}

func (s *Secrets) swapPath(req *http.Request, sec *resolvedSecret, realValue string) string {
	path := req.URL.Path
	if path == "" || !strings.Contains(path, sec.proxyValue) {
		return ""
	}
	req.URL.Path = strings.ReplaceAll(path, sec.proxyValue, realValue)
	// RawPath is an optional encoded form; clear it so net/http re-derives
	// the encoding from the new Path.
	req.URL.RawPath = ""
	return "path"
}

func (s *Secrets) swapBody(req *http.Request, sec *resolvedSecret, realValue string) string {
	if req.Body == nil {
		return ""
	}

	data, err := io.ReadAll(req.Body)
	if err != nil {
		return ""
	}

	if !bytes.Contains(data, []byte(sec.proxyValue)) {
		return ""
	}

	replaced := swapInBody(data, sec.proxyValue, realValue)
	req.Body = transform.NewBufferedBodyFromBytes(replaced)
	return "body"
}

// swapInBody replaces every occurrence of placeholder in data, escaping the
// substituted value where it lands inside a JSON string.
//
// WHY THIS IS NOT bytes.ReplaceAll. A JSON body carries the placeholder inside
// a quoted string — {"signature":"sign-paradex-…"} — and a substituted value
// containing a quote or a backslash ends the string early and leaves the venue
// with a parse error rather than a request. A signature encoded as a felt pair
// is exactly that value: ["<r>","<s>"], which is what a Cairo venue wants and
// what its own client sends ESCAPED, as "[\"<r>\",\"<s>\"]".
//
// The rule is deliberately narrow: escape only when the body looks like JSON
// AND the occurrence is delimited by a double quote on both sides, meaning the
// placeholder is the entire content of a string literal. That is the shape a
// placeholder actually takes in a JSON body, it needs no parser, and for a
// value with nothing to escape — every hex and base64 signature, and every API
// key in the fleet today — the output is byte-identical to the old behaviour.
//
// Not attempted: understanding the body. A placeholder spliced into the middle
// of a string, or a body that is JSON-ish but not JSON, gets the raw value.
// Guessing further would mean parsing every body of every content type, and
// being wrong there corrupts requests that work today.
func swapInBody(data []byte, placeholder, value string) []byte {
	ph := []byte(placeholder)
	if len(ph) == 0 {
		return data
	}
	raw := []byte(value)
	escaped := []byte(jsonStringEscape(value))
	jsonish := looksLikeJSON(data)

	// The scan keeps data whole and carries an absolute position, rather than
	// reslicing a shrinking remainder. The test is on the byte BEFORE an
	// occurrence, and a loop that reslices its input loses the ability to
	// address that byte for every match after the first.
	out := make([]byte, 0, len(data))
	pos := 0
	for {
		i := bytes.Index(data[pos:], ph)
		if i < 0 {
			return append(out, data[pos:]...)
		}
		start, end := pos+i, pos+i+len(ph)
		out = append(out, data[pos:start]...)
		if jsonish && start > 0 && data[start-1] == '"' && end < len(data) && data[end] == '"' {
			out = append(out, escaped...)
		} else {
			out = append(out, raw...)
		}
		pos = end
	}
}

// looksLikeJSON reports whether data opens as a JSON object or array.
//
// A cheap gate rather than a parse. It exists to keep the escaping away from
// bodies that are not JSON at all — a form-encoded or templated body can
// contain a quoted placeholder too, and escaping there would corrupt a request
// that works today. A body that opens with { or [ and is not JSON is not
// something this transform can serve correctly either way.
func looksLikeJSON(data []byte) bool {
	t := bytes.TrimLeft(data, " \t\r\n")
	return len(t) > 0 && (t[0] == '{' || t[0] == '[')
}

// jsonStringEscape renders v as it must appear INSIDE a JSON string literal —
// the encoding of the value, without the surrounding quotes, which the body
// already has.
//
// encoding/json rather than hand-rolled: the cases that matter beyond the
// quote and the backslash are control characters and invalid UTF-8, and those
// are where a hand-rolled escaper is wrong in a way nothing notices until a
// venue rejects a request.
func jsonStringEscape(v string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	// The default escapes <, > and & as \u003c and friends. Valid, and every
	// parser decodes it back the same — but it turns a readable signature into
	// something nobody can match against a packet capture, and this value is
	// read by whoever is debugging the venue's rejection.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		// Unreachable for a string, and falling back to the raw value keeps
		// the old behaviour rather than dropping the substitution.
		return v
	}
	out := bytes.TrimRight(buf.Bytes(), "\n")
	if len(out) < 2 {
		return v
	}
	return string(out[1 : len(out)-1])
}
