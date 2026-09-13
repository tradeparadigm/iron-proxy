# FORK.md — the DIME fork of iron-proxy

Fork of [`ironsh/iron-proxy`](https://github.com/ironsh/iron-proxy). Our
deployable branch is `main`, like any other repository we own — upstream is
reached through a remote, not through a branch of the same name. Upstream stays
the source of truth for everything not listed here.

`dime` is kept as an alias of `main` so older references still resolve; it is
not maintained separately, and the two will diverge only by mistake. The
`dime-<sha12>` image tag is unrelated to either name: it means "a build of this
fork", and it stays as it is because every proxy image already in ECR carries
it.

## Why a fork at all

DIME Terminal gives a customer's AI agent the use of that customer's API
credentials **without the agent, or us, ever holding them**. The agent writes a
placeholder where a credential belongs; a proxy running next to it swaps the
placeholder for the real value on the way out.

iron-proxy already does the hard parts of that: placeholder substitution across
URL, headers and streamed bodies; `require` mode; a default-deny host
allowlist; shadow mode; an outbound header allowlist; per-request audit;
WebSocket upgrades with handshake injection; and a dial guard in
`net.Dialer.Control` that checks the *resolved* address immediately before
connect. Writing those again would be worse, not different.

What it does not do is read a credential that we are unable to read ourselves.
That is the fork.

## The obligation this creates

**Every upstream bump: diff the security defaults.** Not the features — the
defaults. Upstream's threat model is a company proxying its own traffic; ours
is a hostile workload inside our own cluster. Those disagree, and the
disagreement is quiet.

The known instance: `DefaultDenyCIDRs` deliberately **excludes** RFC1918,
because upstream's typical user *wants* to reach private corporate networks.
For us those ranges are our own cluster — the Kubernetes API, the databases,
the other customers' pods. See "RFC1918" below.

## The deltas

### 1. `kms_sm` secret source — `internal/transform/secrets/kms_sm_resolver.go`

Reads a **sealed envelope** from AWS Secrets Manager and opens it locally,
instead of reading a plaintext secret.

The inversion is the design. dime-terminal's web-api stores a user's
credential holding `PutSecretValue` and **neither `GetSecretValue` nor
`kms:Decrypt`** — it writes what it cannot read. This proxy holds the other
half, per customer, so only a customer's own proxy pod can turn a stored blob
back into a credential.

The envelope is sealed in the user's **browser** to a published KMS public key:
a random AES-256-GCM key encrypts the credential, and that key is wrapped to
the public half with RSA-OAEP-SHA-256. (RSA-4096 OAEP tops out near 446 bytes,
so wrapping the credential directly would rule out PEM keys.)

```yaml
secrets:
  - source:
      type: kms_sm
      secret_id: terminal/prod/<account-id>/binance-1fbd3c58
      label: binance
    replace:
      proxy_value: dime-binance-<22 chars>
      match_headers: [X-MBX-APIKEY]
      require: true
```

Plus, **from the pod's own environment, never the config**:

| Variable | Why not config |
| --- | --- |
| `DIME_CREDENTIAL_NAMESPACE` | Half the AAD. Asymmetric `kms:Decrypt` takes no encryption context, so the AAD is the only thing stopping a stored blob being copied into another account's slot and opened there. A control plane that supplied it could name another account's namespace and undo that. |
| `DIME_CREDENTIAL_KMS_KEY_ID` | The opener's configuration selects the key. Taking it from the blob would let whoever wrote the blob choose the key it opens with. |

Both are read at `Build` time, so a pod missing either **refuses to build its
pipeline** rather than failing every request: without them no `kms_sm` secret
can ever open, and a config that cannot work should not load.

**The format is a contract across three implementations** — this file,
`api/terminal/pkg/secrets/envelope.go`, and
`ui/terminal/packages/core/src/credential-envelope.ts`. A disagreement does not
fail at enrollment; it fails at injection time, long afterwards, as a
credential that cannot be opened. `kms_sm_resolver_test.go` therefore carries
**fixed vectors byte-identical to the other two suites** — not a round-trip,
which would only prove this file is self-consistent. If those vectors fail, the
format changed, and a format change means a new envelope version and
re-enrollment for every user.

Refusals, all tested: an envelope version or alg that is not exactly ours; a
`kid` naming a different key (refused *before* any KMS call); a nonce of the
wrong length; a data key that is not 32 bytes; URL-safe base64 where standard
is required (a real interop trap — a browser using base64url would pass its own
round-trip and fail here); and an AAD that does not match, in either half.

No error path carries the credential, the data key or the wrapped key. There is
a test asserting it, because errors become log lines and a log line is forever.

### 2. Caller authentication — `internal/proxy/callerauth.go`

Upstream does not authenticate its callers: `Proxy-Authorization` appears in
its source only in the hop-by-hop strip list. Reasonable for a proxy a company
runs for its own traffic on a network it trusts; not for one holding a single
customer's live trading credentials next to other customers' agents.

Every caller must present `Proxy-Authorization: Bearer <token>`, compared in
constant time against `DIME_PROXY_AUTH_TOKEN` **from the pod's environment**.
Not from the config: in managed mode the config comes from the control plane,
and a token the control plane chose is one it can use.

**Why not a transform.** Upstream's intended extension point for this is a
transform — CONNECT headers are passed to the pipeline for exactly that, and
its own tests demonstrate a transform answering 407. We did not use it, for two
reasons. A transform is *configured*, so a control plane that omitted it would
silently produce an anonymous proxy; and transform ordering would decide
whether authentication ran before anything else did. In the core it cannot be
omitted or reordered.

Enforced at every front door — CONNECT, absolute-form HTTP on the tunnel
listener, and the direct http/https listeners — **before** any secret is
fetched, host matched, or upstream dialled. There is a test asserting the
upstream is never contacted by an unauthenticated caller.

Two deliberate asymmetries:

- **Requests inside an established tunnel are not challenged.** Their headers
  travel end-to-end to the venue, so requiring `Proxy-Authorization` there
  would mean asking every agent to hand our per-customer token to Binance. The
  CONNECT is authenticated; the tunnel it opens is trusted. This reads like an
  omission, so there is a test named after it.
- **SOCKS5 is refused** (method `0xFF`) while caller auth is on. Upstream
  negotiates no-auth only, so leaving it reachable would be an anonymous door
  into the same credentials. RFC 1929 username/password is more surface than
  this deployment needs — agents arrive by CONNECT.

`Proxy-Authorization` is hop-by-hop and already stripped upstream, so the token
never reaches a venue. A test pins that too.

**With the variable unset the proxy is unauthenticated** — upstream's
behaviour, which its suite and standalone users depend on. `New` logs a
warning at boot naming the risk. A DIME chart must set it; the honest
improvement is a boot-time refusal once the fork no longer needs to run
without it.

### 3. RFC1918 in the deny CIDRs — `internal/dnsguard/dnsguard.go`

Upstream's comment states the divergence outright: *"RFC1918 is intentionally
excluded — many legitimate iron-proxy deployments target private corporate
networks."* For a DIME proxy those ranges are our own cluster — the Kubernetes
API, the databases, the control plane, every other customer's agent pod.

Added to the defaults: RFC1918 (`10/8`, `172.16/12`, `192.168/16`), all of
link-local `169.254/16` (upstream pins only the metadata addresses), shared
address space `100.64/10`, and IPv6 `fc00::/7` + `fe80::/10`. The guard checks
the **resolved** address immediately before connect, so this also catches a
hostname that resolves inward.

This covers **proxied upstream connections only**. `internal/controlplane` and
the AWS SDK clients build their own transports and are not guarded, so config
sync and Secrets Manager / KMS still work over private addresses, including VPC
endpoints. It is also a *default*: an operator who sets `upstream_deny_cidrs`
replaces the list wholesale.

The test asserts `10.56.35.116` is denied, which is a real pod address in our
cluster — a regression there would let one customer's agent reach another's.

### 4. `label` and `outcome` on the request annotations

Upstream already annotates `swapped`, `injected`, `rejected` and
`reject_reason`. Two things were missing for an audit.

**`label`** — the existing `secret` field is `Source.Name()`, the AWS resource
id (`terminal/prod/<account>/binance-1fbd3c58`). An audit read by a person
needs the name the person chose. `kms_sm` sources carry it via a `Label()`
method the transform picks up through an anonymous interface assertion, so no
other source type grows a field it does not have, and the config does not
repeat the label in two places.

**`outcome`** — annotated on **every** request, with a closed set:
`rejected`, `injected`, `swapped`, `injected+swapped`, `passthrough`. The last
one is the point: "this request went upstream with nothing of ours in it"
previously existed only as the *absence* of three other fields, which is
neither greppable nor alertable.

**`signed_into`** — the sign-mode counterpart of `swapped`, added with delta 5
below. Same shape plus a `digest` field: a 12-hex-character prefix of SHA-256
over the bytes that were signed, which is enough to tie a signature in a
venue's logs to a request in ours and not enough to reconstruct what it
covered. A signed request's `outcome` is `swapped` — as far as an audit is
concerned, something of ours went into it.

The `require`-mode rejection with no placeholder present also gained
`reject_reason: placeholder_absent`. That refusal is what stops a workload
bypassing the swap with a credential of its own, so it deserves a name rather
than a bare `rejected`.

### 5. `sign` delivery mode — `internal/transform/secrets/sign.go`

A third thing a credential can be. Upstream has two: `inject` (the proxy
attaches the value, and the agent sends nothing) and `replace` (the agent
writes a placeholder, the proxy swaps it). Both assume the stored secret is
the thing that goes on the wire.

A signing key is not. The credential is a private key; what goes on the wire is
a signature over something the request itself determines — an auth challenge,
an order payload, a canonical string built from method, path, body and a
timestamp. Handing the agent the key would defeat the whole arrangement, and
there is nothing static to substitute.

**The calling convention.** The agent hands over the bytes; the proxy signs
them.

```
POST /v1/auth HTTP/1.1
Host: api.paradex.trade
X-Dime-Sign-paradex: <base64 of the bytes to sign>
PARADEX-STARKNET-SIGNATURE: sign-paradex-<22 chars>
```

The proxy reads the payload header, signs its contents under the credential's
configured scheme, renders the signature in the configured encoding, and
substitutes it wherever the placeholder appears — the same scan `replace` uses,
across headers, query, path and body, which is why the two config blocks share
field names. The payload header is **removed before forwarding, whatever
happens next**, including on a refusal: the destination has no business seeing
what we were asked to sign.

```yaml
secrets:
  - source:
      type: kms_sm
      secret_id: terminal/prod/<account-id>/paradex-1fbd3c58
      label: paradex
    sign:
      proxy_value: sign-paradex-<22 chars>
      scheme: ecdsa-p256
      encoding: hex
      match_headers: [PARADEX-STARKNET-SIGNATURE]
      require: true
```

**The scheme comes from the config, not from the key.** The sealed secret holds
key material and nothing else; what to do with it — which curve, which encoding
— is a column on the credential row in dime-terminal's database. So changing a
scheme is a control-plane edit rather than a re-enrollment, and a stored blob
carries no instruction about how it is to be used.

**Why the agent supplies the payload.** The alternative considered and rejected
was for the proxy to derive the signed bytes from the request, through a
declarative field-mapping. That works, and it is what a venue-specific
integration looks like — which is the objection: it is a per-endpoint recipe we
write and maintain for every venue and every signed route it has, and when a
signature comes out wrong there is no way to tell which mapping rule produced
it. Agent-supplied bytes are one mechanism that serves every venue, and the
bytes that produced a bad signature are right there in the request.

**The residual risk, and what bounds it.** A signature over bytes the caller
chose is portable: the agent decides what gets signed, so it can obtain a
signature over anything, including something it means to use elsewhere. That is
accepted for now, and bounded rather than removed:

- the payload header never reaches the destination;
- a payload is capped at 64 KiB, and one request may produce at most 8
  signatures;
- the audit records a 12-hex-character digest of what was signed, never the
  payload.

The exposure that remains — a venue echoing the request back, putting the
signature in a response body — is the one `replace` already has, and is
answered by response scrubbing, which is not yet built.

**Where the signature lands decides how it is rendered.** One credential
routinely serves several message types — on Paradex the same key signs the auth
challenge, whose signature rides in the `PARADEX-STARKNET-SIGNATURE` header,
and every order, whose signature is a field in a JSON body. The header takes
the felt pair as-is; the body needs it escaped, `"[\"<r>\",\"<s>\"]"`, which
is what the venue's own client sends. So `swapBody` escapes a substituted value
when the body opens as JSON and the placeholder is the whole content of a
string literal, and leaves it alone otherwise. The rule needs no parser, and
for a value with nothing to escape — every hex and base64 signature, and every
API key in the fleet — the bytes are identical to the `bytes.ReplaceAll` it
replaced. It fixes the same latent bug in `replace` mode, where a stored secret
containing a quote produced a body the venue could not parse.

**Schemes.** `hmac-sha256` covers the whole message; `ecdsa-p256` covers a
32-byte SHA-256 digest. **A mismatch is refused, not papered over**: a message
handed to an asymmetric scheme, or a digest handed to a MAC, yields a signature
the venue rejects with nothing saying why, and that is an afternoon rather than
a five-minute fix. `stark` covers one field element — the typed-data
message hash, 32 bytes big-endian — and its key is a bare hex scalar rather
than PEM, because that is the only form the Starknet ecosystem uses and the
form Paradex's own tooling emits.

**The stark signer uses the library the venue verifies with.** Paradex's
web-api calls `gnark-crypto/ecc/stark-curve/ecdsa`'s `PublicKey.Verify` with a
nil hash function, an `r||s` signature and the felt as the message; this signs
through the mirror of that call. That settles two things that would otherwise
be guesses: the wire shape, and low-s. gnark's `Sign` loops until
`s <= (order-1)/2` and its `Verify` refuses anything above — so the convention
lines up by construction rather than by luck, and a signer that emitted high-s
would be rejected by the venue with nothing saying why. The test does not sign
and verify with our own code, which would prove only self-consistency: it
rebuilds Paradex's verification path, public key recovered from the x
coordinate and all, and checks the signature against that.

**The refusal is the documentation.** An agent cannot read this file, the
config, or the credential's settings page, and sign mode asks more of it than
either other mode does: a placeholder *and* a separate header carrying bytes in
a form the scheme dictates. So a refusal states the whole calling convention —
the payload header by name, what the scheme expects, the placeholder verbatim,
the encoding the signature comes back in, and the positions scanned.
The `X-Dime-Credential-Error` reasons are
`sign_payload_absent`, `sign_payload_malformed`, `sign_payload_too_large`,
`sign_failed` and `sign_limit`, kept distinct so that a caller — prose or
tooling — can tell "you sent no bytes" from "re-encode them" from "send fewer"
from "you sent the wrong shape of bytes" from "this one is not yours to fix".
The rule every other refusal here follows holds: nothing in a body may help
obtain the key, and there are tests asserting no line of a PEM reaches either a
refusal body or the request annotations.

### 6. `Dockerfile` — a build from source

Upstream's `Dockerfile.release` is goreleaser's: it copies a binary
goreleaser has already cross-compiled into `linux/${TARGETARCH}/`, and the
pipeline producing it needs a goreleaser-pro licence and Docker Hub
credentials. Neither is available to the DIME build, and neither should be
required to ship a fork.

`Dockerfile` (new, additive — `Dockerfile.release` and `.goreleaser.yml` are
untouched, so a `v*` tag still publishes `ironsh/iron-proxy` exactly as
before) builds from the checkout with `go build`, stamps
`internal/version.Version` with the fork commit sha, and lands on
`gcr.io/distroless/static-debian12:nonroot`.

**Distroless rather than alpine**, which is what `Dockerfile.release` uses:
this process holds decrypted trading credentials in memory, and there is no
reason for a shell and a package manager to share its filesystem. It takes its
whole configuration from the control plane and its environment, so it needs
neither.

**Consequence for the deployment:** `:nonroot` is uid 65532 and cannot bind
ports below 1024. The DIME chart therefore puts every listener above 1024, and
upstream chart's `NET_BIND_SERVICE` capability is not needed. Do not "fix" a
bind failure by adding the capability back — move the port.

**Who builds it.** dime-terminal's `infra/jenkins/Jenkinsfile.terminal-openclaw`,
the same job that rolls the customer fleet: it resolves this repository's
`main` branch to a sha, builds `terminal/iron-proxy:dime-<sha12>` into ECR if
that tag is not already there, and deploys it in the same run. There is
deliberately no published image for this fork and no second pipeline —
a public iron-proxy image would be one without `kms_sm` or caller auth, which
is a silent removal of the two properties this fork exists for.

## Incidental: dependency versions

Adding the KMS client moved `aws-sdk-go-v2` 1.41.11 → 1.45.1 and `smithy-go`
1.27.0 → 1.28.1 (the KMS module requires the newer core). The whole
`internal/transform/...` and `internal/dnsguard/...` suites pass on the bumped
versions. Recorded here so an upstream merge conflict on `go.mod` has a reason
attached.
