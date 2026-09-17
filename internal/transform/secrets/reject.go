package secrets

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/ironsh/iron-proxy/internal/transform"
)

// Explanatory refusals.
//
// WHY THIS FILE EXISTS. A refusal from this transform used to be a bare 403
// with an empty body: the transform returned ActionReject with no Response and
// the pipeline substituted its generic one. For a person debugging a curl that
// is merely unhelpful. For the actual caller here — an AI agent, which cannot
// read this config, cannot see the proxy's logs, and has not been told a proxy
// is in the path at all — it is a dead end. The request failed, nothing says
// what was expected, and the only moves left are guesses: retry the same call,
// then try a credential of its own. That second guess is precisely what
// `require` exists to prevent, so an opaque refusal makes the safe path
// undiscoverable and the unsafe one attractive.
//
// A refusal therefore says which credential, what was expected, and where. It
// is written to be acted on by a model reading tool output: prose rather than
// an error code, the placeholder quoted verbatim so it can be copied straight
// into a retry, and an explicit statement of whether retrying can help at all.
//
// WHAT IT MUST NEVER CONTAIN is the credential, or anything that helps obtain
// it. Everything named below is material the agent is already entitled to: the
// label and the placeholder both appear in the customer's own settings UI, and
// the placeholder is published into the agent's environment by design — it is
// the token the agent is supposed to write. The real value, the secret's
// storage identifier, and the reason a fetch failed stay out; the operator
// detail goes to the request log, which the agent cannot read.

const (
	// rejectionReasonHeader names the machine-readable reason, for tooling that
	// would rather branch than parse prose. The body is the part meant to be
	// read.
	rejectionReasonHeader = "X-Dime-Credential-Error"
	rejectionLabelHeader  = "X-Dime-Credential-Label"

	// rejectionWidth is where prose wraps. Fixed rather than terminal-derived:
	// this text is usually read out of a tool result or a log, neither of which
	// has a width.
	rejectionWidth = 76
)

// paragraphs assembles a body from logical paragraphs, wrapping each to
// rejectionWidth. A line beginning with a space or a "-" bullet is emitted
// verbatim, so a quoted placeholder is never broken across lines and a list
// stays a list.
//
// The alternative — hand-wrapped literals — is what the first version did, and
// it looked correct until a real hostname was interpolated into the first
// sentence and pushed it to 140 columns while every following line stayed at
// 76. Wrapping has to happen after substitution, so it cannot be done by hand.
func paragraphs(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, " ") || strings.HasPrefix(p, "-") {
			out = append(out, p)
			continue
		}
		out = append(out, wrap(p, rejectionWidth))
	}
	return strings.Join(out, "\n\n") + "\n"
}

// wrap breaks text on spaces at no more than width columns. A word longer than
// width gets its own line rather than being split, which keeps a placeholder or
// a URL intact and copyable.
func wrap(text string, width int) string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	lineLen := 0
	for i, w := range words {
		switch {
		case i == 0:
			b.WriteString(w)
			lineLen = len(w)
		case lineLen+1+len(w) > width:
			b.WriteString("\n")
			b.WriteString(w)
			lineLen = len(w)
		default:
			b.WriteString(" ")
			b.WriteString(w)
			lineLen += 1 + len(w)
		}
	}
	return b.String()
}

// bulletList renders items as an adjacent, hanging-indented list.
//
// One block rather than one part per item: paragraphs separates its parts with
// a blank line, which is right for prose and wrong for a list — the first
// version put a blank line between every bullet and let long ones run past the
// margin unwrapped.
func bulletList(items []string) string {
	var lines []string
	for _, item := range items {
		for i, line := range strings.Split(wrap(item, rejectionWidth-4), "\n") {
			if i == 0 {
				lines = append(lines, "  - "+line)
				continue
			}
			lines = append(lines, "    "+line)
		}
	}
	return strings.Join(lines, "\n")
}

// named renders a credential label for prose, or a neutral phrase when the
// source carries none (only the DIME sources have labels; an env or file source
// is nameless, and inventing a name for it would be worse than not having one).
func named(label string) string {
	if label == "" {
		return "a stored credential"
	}
	return fmt.Sprintf("a stored credential (%q)", label)
}

// placeholderAbsentBody explains a refusal caused by a request reaching a
// credentialed host without the placeholder the swap needs.
//
// The one refusal the caller can fix on its own, so it ends with the exact
// thing to do.
func placeholderAbsentBody(host, label string, sec *resolvedSecret) string {
	parts := []string{
		"403 Forbidden — refused by the DIME credential proxy.",
		fmt.Sprintf("This request was NOT sent to %s. That host has %s, which this agent is "+
			"meant to use by writing a placeholder where the credential belongs. The request "+
			"did not contain that placeholder, so the proxy refused it rather than forwarding "+
			"a call with the credential missing.", host, named(label)),
	}
	if sec.proxyValue != "" {
		parts = append(parts,
			"To fix this, put this exact string where the credential belongs, then retry:",
			"    "+sec.proxyValue,
			"The proxy substitutes the real credential on the way out. That value is "+
				"deliberately not available to this agent, and is not needed.")
	}
	parts = append(parts,
		"Where the proxy looks for it:",
		bulletList(placeholderLocations(sec)))
	parts = append(parts,
		"Do NOT substitute a credential of your own, and do not retry this request "+
			"unchanged — it will be refused again for the same reason.")
	return paragraphs(parts...)
}

// placeholderLocations describes, in reading order, every position this entry
// scans. It mirrors the swap order in TransformRequest: a position listed here
// that is not actually scanned would send an agent looking in the wrong place,
// which is worse than saying nothing.
func placeholderLocations(sec *resolvedSecret) []string {
	var out []string
	if len(sec.matchHeaders) == 0 {
		// The BROADEST case, not the empty one: swapHeaders with no matchers
		// walks every header. "Any request header" is both accurate and the
		// most useful thing an agent can hear, since it means the choice of
		// header is the agent's own.
		out = append(out, "any request header — choose whichever one this API expects "+
			"(commonly Authorization, or an API-key header)")
	} else {
		names := make([]string, 0, len(sec.matchHeaders))
		for _, m := range sec.matchHeaders {
			if m.re != nil {
				names = append(names, "any header matching /"+m.re.String()+"/")
				continue
			}
			name := m.wireName
			if name == "" {
				name = m.name
			}
			names = append(names, name)
		}
		out = append(out, "these request headers only: "+strings.Join(names, ", "))
	}
	if sec.matchQuery {
		out = append(out, "the URL query string")
	}
	if sec.matchPath {
		out = append(out, "the URL path")
	}
	if sec.matchBody {
		out = append(out, "the request body")
	}
	return out
}

// secretUnavailableBody explains a refusal the agent cannot do anything about.
//
// The last paragraph is the important content. Without it an agent reads a 403
// on a credentialed host as "my request was wrong" and burns turns varying it,
// or falls back to a credential of its own. Saying plainly that the request is
// not the problem is what stops both.
func secretUnavailableBody(host, label string) string {
	return paragraphs(
		"403 Forbidden — refused by the DIME credential proxy.",
		fmt.Sprintf("This request was NOT sent to %s. That host has %s, and the proxy could "+
			"not retrieve it. Rather than forward the request without the credential — where "+
			"it would fail at the venue as an authentication error with no explanation — it "+
			"was refused here.", host, named(label)),
		"NOTHING ABOUT THIS REQUEST CAUSED THIS, and changing the request cannot fix it: "+
			"the failure is between the proxy and the credential store, which this agent has "+
			"no part in.",
		"One retry is reasonable in case it was transient. Beyond that, stop and report it — "+
			"the credential needs attention in DIME Terminal settings, where re-saving it is "+
			"the usual fix. Do not work around this with a credential of your own.")
}

// rejection builds the response the pipeline returns to the caller.
func rejection(req *http.Request, reason, label, body string) *http.Response {
	payload := []byte(body)
	header := http.Header{
		"Content-Type":        {"text/plain; charset=utf-8"},
		rejectionReasonHeader: {reason},
		// Never cache a refusal. The placeholder-absent case is expected to be
		// fixed and retried immediately, and a cached 403 would fail the
		// corrected request too.
		"Cache-Control": {"no-store"},
	}
	if label != "" {
		header[rejectionLabelHeader] = []string{label}
	}
	return &http.Response{
		StatusCode:    http.StatusForbidden,
		Status:        strconv.Itoa(http.StatusForbidden) + " " + http.StatusText(http.StatusForbidden),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          transform.NewBufferedBodyFromBytes(payload),
		ContentLength: int64(len(payload)),
		Request:       req,
	}
}

// rejectionHost is the destination as the caller asked for it, port stripped.
// Prefers req.Host: after TLS termination that is the header the client sent,
// which is the name an agent will recognise.
func rejectionHost(req *http.Request) string {
	host := req.Host
	if host == "" && req.URL != nil {
		host = req.URL.Host
	}
	if h, _, found := strings.Cut(host, ":"); found {
		host = h
	}
	if host == "" {
		return "that host"
	}
	return host
}

// signPayloadAbsentBody explains a refusal caused by a request reaching a host
// with a signing credential without the bytes to sign.
//
// THE LONGEST BODY IN THIS FILE, on purpose. Sign mode asks more of the caller
// than the other two modes do — inject needs nothing at all, replace needs one
// placeholder, and this needs a placeholder AND a separate header carrying
// bytes in a form the scheme dictates. An agent has no way to discover any of
// that: it cannot read the config, the credential's settings page, or this
// code. So the refusal is the documentation, and it states the whole call
// rather than only the part that was missing.
func signPayloadAbsentBody(host, why string, sec *resolvedSecret) string {
	if sec.label == "" {
		// No label means no payload header, which means there is no correct
		// way to make this call. Saying how would be a lie.
		return paragraphs(
			"403 Forbidden — refused by the DIME credential proxy.",
			fmt.Sprintf("This request was NOT sent to %s. %s", host, why),
			"NOTHING ABOUT THIS REQUEST CAUSED THIS, and changing the request cannot fix it. "+
				"Stop and report it — the credential needs attention in DIME Terminal settings.")
	}

	header := signPayloadHeader(sec.label)
	parts := []string{
		"403 Forbidden — refused by the DIME credential proxy.",
		fmt.Sprintf("This request was NOT sent to %s. That host has %s, which is a SIGNING KEY: the "+
			"proxy signs bytes on this agent's behalf and writes the signature into the request. "+
			"%s", host, named(sec.label), why),
		"HOW TO MAKE THIS CALL. Both steps are required; either one alone is refused.",
		fmt.Sprintf("Step 1 — hand over the bytes to sign. %s Base64-encode them and send them in "+
			"this request header:", schemeExpectation(sec.scheme)),
		"    " + header + ": <base64 of the bytes to sign>",
		"The proxy REMOVES that header before forwarding, so the destination never sees what was " +
			"signed.",
	}
	if sec.proxyValue != "" {
		parts = append(parts,
			"Step 2 — mark where the signature goes. Put this exact string where the signature "+
				"belongs in the request:",
			"    "+sec.proxyValue,
			fmt.Sprintf("The proxy replaces it with the signature, rendered as %s.",
				encodingDescription(sec.encoding)))
	}
	parts = append(parts,
		"Where the proxy looks for that string:",
		bulletList(placeholderLocations(sec)))
	parts = append(parts,
		"The private key itself is never available to this agent and is not needed. Do NOT sign "+
			"with a key of your own, do NOT put the key's name or any value of your own where the "+
			"signature belongs, and do not retry this request unchanged — it will be refused again "+
			"for the same reason.")
	return paragraphs(parts...)
}

// signPlaceholderAbsentBody explains a refusal caused by a sign-mode request
// that handed over the bytes to sign but never said where the signature goes.
//
// Separate from placeholderAbsentBody because that one describes replace mode:
// it tells the caller the proxy will substitute "the real credential", which
// for a signing key is not what happens and not what the caller should be
// looking for. The agent is half-right at this point — step 1 worked — and the
// body says so, because "was my payload accepted?" is otherwise unanswerable
// and an agent that cannot tell will go back and change the part that was fine.
func signPlaceholderAbsentBody(host, label string, sec *resolvedSecret) string {
	parts := []string{
		"403 Forbidden — refused by the DIME credential proxy.",
		fmt.Sprintf("This request was NOT sent to %s. The bytes to sign WERE received and are "+
			"fine — %s is a signing key, and the proxy is ready to sign with it. What is missing "+
			"is where to put the result: the request contains no placeholder marking the spot, so "+
			"there is nowhere for the signature to go.", host, named(label)),
	}
	if sec.proxyValue != "" {
		parts = append(parts,
			"Put this exact string where the signature belongs, keep the sign header you already "+
				"sent, and retry:",
			"    "+sec.proxyValue,
			fmt.Sprintf("The proxy replaces it with the signature, rendered as %s.",
				encodingDescription(sec.encoding)))
	}
	parts = append(parts,
		"Where the proxy looks for that string:",
		bulletList(placeholderLocations(sec)))
	parts = append(parts,
		"Nothing else about this request needs to change. The private key is never available to "+
			"this agent and is not needed. Do NOT sign with a key of your own, and do NOT put a "+
			"value of your own where the signature belongs — only the placeholder above is "+
			"substituted.")
	return paragraphs(parts...)
}

// signLimitBody explains a refusal caused by one request asking for more
// signatures than a request is allowed to produce.
//
// Reachable only when many signing credentials match one host, so it is aimed
// at the operator as much as the agent: the agent is told plainly that
// retrying will not help, because nothing about the request's content is what
// tripped the limit.
func signLimitBody(host string) string {
	return paragraphs(
		"403 Forbidden — refused by the DIME credential proxy.",
		fmt.Sprintf("This request was NOT sent to %s. It matched more signing credentials than one "+
			"request may use — this proxy signs at most %d times per request — so it was refused "+
			"rather than turned into a bulk signing operation.", host, maxSignsPerRequest),
		"Splitting the work across several requests will not help: the limit counts the credentials "+
			"CONFIGURED for this host, not anything this request contains. Stop and report it — the "+
			"credentials for this host need attention in DIME Terminal settings.")
}

// signFailedBody explains a refusal caused by the signature itself failing to
// compute.
//
// The signing error is SAFE TO HAND BACK, unlike a fetch error. It names the
// scheme and the shape of input that scheme wanted, and nothing about the key:
// signPayload is written so that its failures describe the caller's bytes, not
// the secret. That matters, because the commonest failure here — a message
// where a digest was expected — is entirely the caller's to fix, and a refusal
// that hid the reason would leave it guessing.
func signFailedBody(host, scheme string, err error) string {
	return paragraphs(
		"403 Forbidden — refused by the DIME credential proxy.",
		fmt.Sprintf("This request was NOT sent to %s. The proxy held the signing key and the bytes "+
			"to sign, but could not produce a signature:", host),
		"    "+err.Error(),
		schemeExpectation(scheme),
		"Correct the bytes handed over in the sign header and retry. If they are already correct "+
			"for this scheme, stop and report it rather than retrying — the key may be stored in a "+
			"form this scheme cannot use, which is fixed in DIME Terminal settings. Do NOT sign "+
			"with a key of your own.")
}
