# FORK.md — the DIME fork of iron-proxy

Fork of [`ironsh/iron-proxy`](https://github.com/ironsh/iron-proxy), branch
`dime`. Upstream stays the source of truth for everything not listed here.

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

The `require`-mode rejection with no placeholder present also gained
`reject_reason: placeholder_absent`. That refusal is what stops a workload
bypassing the swap with a credential of its own, so it deserves a name rather
than a bare `rejected`.

## Incidental: dependency versions

Adding the KMS client moved `aws-sdk-go-v2` 1.41.11 → 1.45.1 and `smithy-go`
1.27.0 → 1.28.1 (the KMS module requires the newer core). The whole
`internal/transform/...` and `internal/dnsguard/...` suites pass on the bumped
versions. Recorded here so an upstream merge conflict on `go.mod` has a reason
attached.
