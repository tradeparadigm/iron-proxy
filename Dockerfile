# Build the DIME fork of iron-proxy into a container image.
#
# WHY THIS FILE EXISTS, when the repository already has Dockerfile.release:
# that one is goreleaser's — it COPYs a binary goreleaser has already
# cross-compiled into `linux/${TARGETARCH}/`, and the release pipeline that
# produces it needs goreleaser-pro plus Docker Hub credentials. This builds
# from source with nothing but the checkout, so the DIME image is produced by
# the same Jenkins job that rolls out the customer fleet
# (dime-terminal: infra/jenkins/Jenkinsfile.terminal-openclaw) with no
# additional pipeline, no goreleaser licence, and no second registry.
#
# Upstream's own release path is left untouched: a `v*` tag still builds
# `ironsh/iron-proxy` through .goreleaser.yml exactly as before.
#
# There is deliberately NO published image for this fork. The fork exists for
# the kms_sm secret source and caller authentication, so anyone who reached for
# a public iron-proxy image would get a proxy that cannot decrypt a DIME
# credential and does not authenticate its callers — a silent downgrade of the
# two properties the fork was made for.

# Must stay >= the `go` directive in go.mod. Split into the same two ARGs
# dime-terminal's own Dockerfiles use, so "bump Go" is one edit shape
# everywhere and bumping the language version cannot silently unpin the OS.
ARG GO_VERSION=1.26.3
ARG OS_VERSION=bookworm

FROM golang:${GO_VERSION}-${OS_VERSION} AS build
WORKDIR /src

# Modules first: the dependency graph changes far less often than the code, so
# a code-only rebuild reuses this layer instead of re-downloading ~40 modules.
COPY go.mod go.sum ./
RUN --mount=type=cache,id=gomod-iron-proxy,target=/go/pkg/mod \
    go mod download

COPY . .

# VERSION is what `iron-proxy --version` and the version metric report. Jenkins
# passes the fork commit sha, which is the only honest answer for a build off a
# branch: there is no upstream release tag that describes it.
ARG VERSION=dime-dev
# CGO off so the binary runs on any libc — including the distroless base below,
# which has none. buildx pulls the golang base for the target platform, so this
# compiles natively for arm64 on an arm64 build and needs no cross toolchain.
RUN --mount=type=cache,id=gobuild-iron-proxy,target=/root/.cache/go-build \
    --mount=type=cache,id=gomod-iron-proxy,target=/go/pkg/mod \
    CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X github.com/ironsh/iron-proxy/internal/version.Version=${VERSION}" \
      -o /out/iron-proxy ./cmd/iron-proxy

# distroless rather than alpine (which Dockerfile.release uses): this process
# holds decrypted trading credentials in memory, and the fewer executables that
# share its filesystem the better. It needs no shell and no package manager —
# it takes its whole configuration from the control plane and its environment.
#
# `:nonroot` runs as uid 65532, matching the chart's runAsUser. It cannot bind
# ports below 1024, which is why the DIME deployment puts every listener above
# that; the chart's NET_BIND_SERVICE capability is for upstream's defaults, not
# for us.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/iron-proxy /usr/local/bin/iron-proxy
# ca-certificates come with the base: the proxy dials venues over TLS and
# fetches from Secrets Manager and KMS, all of which need a trust store.
ENTRYPOINT ["/usr/local/bin/iron-proxy"]
