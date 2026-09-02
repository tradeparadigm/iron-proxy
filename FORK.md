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

### 2. RFC1918 in the deny CIDRs

*Pending.* Upstream excludes RFC1918 from `DefaultDenyCIDRs` by design. For a
proxy running inside our cluster, those ranges are the cluster.

### 3. Caller authentication

*Pending.* `Proxy-Authorization` appears in upstream's source only in the
hop-by-hop strip list, so a per-customer iron-proxy is otherwise an
**unauthenticated** proxy holding one customer's credentials. Until this lands,
NetworkPolicy is the only thing keeping one customer's agent off another's
proxy — which makes it a prerequisite, not hardening.

### 4. `label` and `outcome` on every request log line

*Pending.* Needed to tell "injected", "refused, credential not sent" and
"passed through untouched" apart in an audit.

## Incidental: dependency versions

Adding the KMS client moved `aws-sdk-go-v2` 1.41.11 → 1.45.1 and `smithy-go`
1.27.0 → 1.28.1 (the KMS module requires the newer core). The whole
`internal/transform/...` and `internal/dnsguard/...` suites pass on the bumped
versions. Recorded here so an upstream merge conflict on `go.mod` has a reason
attached.
