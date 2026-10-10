GO      ?= go
BIN     := bin/sandwall
GOFLAGS ?=
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)
# Optional e2e locations; empty means the scripts' defaults.
FC_ASSETS   ?=
CHROOT_BASE ?=
E2E_TMP     ?=
E2E_ENV = SANDWALL=$(CURDIR)/$(BIN) $(if $(FC_ASSETS),FC_ASSETS=$(FC_ASSETS)) \
	$(if $(CHROOT_BASE),CHROOT_BASE=$(CHROOT_BASE)) $(if $(E2E_TMP),E2E_TMP=$(E2E_TMP)) \
	$(foreach v,CLONES CLONE_STAGGER FETCH_CONCURRENCY REAL_PROXY HTTP3_CURL,$(if $($(v)),$(v)=$($(v))))

.PHONY: psl-update build test vet fmt-check license-check release e2e e2e-m1 e2e-m2 e2e-m3 e2e-proxy e2e-s1 e2e-s1-real e2e-relay-cost e2e-synthetic e2e-dataplane e2e-quarantine e2e-alerts e2e-otel fc-assets clean

build:
	CGO_ENABLED=0 GOOS=linux $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/sandwall

# Unit tests; the few that need root skip without it.
test:
	$(GO) test ./...

vet:
	GOOS=linux $(GO) vet ./...

fmt-check:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }

# go-licenses runs on the build host and inspects the Linux build of sandwall.
GO_LICENSES_VERSION := v2.0.1
GO_LICENSES := bin/tools/$(shell $(GO) env GOHOSTOS)_$(shell $(GO) env GOHOSTARCH)/go-licenses-$(GO_LICENSES_VERSION)
GO_LICENSES_ARGS := ./cmd/sandwall --ignore github.com/anvanster/sandwall

$(GO_LICENSES):
	GOOS= GOARCH= GOBIN=$(CURDIR)/$(dir $@) $(GO) install github.com/google/go-licenses/v2@$(GO_LICENSES_VERSION)
	mv $(dir $@)go-licenses $@

# Fail on dependencies whose license is copyleft, forbidden or unrecognized.
license-check: $(GO_LICENSES)
	GOOS=linux $(GO_LICENSES) check $(GO_LICENSES_ARGS) --disallowed_types=forbidden,restricted,unknown

# Release archives in dist/: per architecture, a static binary with LICENSE,
# README.md and THIRD_PARTY_LICENSES (every compiled-in module's license and
# notice files, and Go's own), plus SHA256SUMS. Archives are reproducible:
# fixed owner, order and mtime (the commit time), and no gzip timestamp.
# Needs GNU tar and sha256sum; the release workflow runs it on Linux.
RELEASE_ARCHES := amd64 arm64
DIST := dist
release: license-check
	rm -rf $(DIST)
	set -e; mtime=$$(git log -1 --format=%ct); \
	for arch in $(RELEASE_ARCHES); do \
		name=sandwall-$(VERSION)-linux-$$arch; dir=$(DIST)/$$name; \
		mkdir -p $$dir/THIRD_PARTY_LICENSES/go.dev/go; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $$dir/sandwall ./cmd/sandwall; \
		GOOS=linux GOARCH=$$arch $(GO_LICENSES) save $(GO_LICENSES_ARGS) --force --save_path=$$dir/THIRD_PARTY_LICENSES/modules; \
		cp "$$($(GO) env GOROOT)/LICENSE" $$dir/THIRD_PARTY_LICENSES/go.dev/go/LICENSE; \
		cp LICENSE README.md $$dir/; \
		tar -C $(DIST) --sort=name --owner=0 --group=0 --numeric-owner --mtime=@$$mtime -cf - $$name | gzip -n > $(DIST)/$$name.tar.gz; \
	done
	cd $(DIST) && sha256sum *.tar.gz > SHA256SUMS

# Root-only end-to-end tests. Run inside a disposable Linux VM.
e2e: e2e-m1 e2e-m2 e2e-m3 e2e-proxy e2e-s1 e2e-quarantine e2e-alerts e2e-otel e2e-synthetic e2e-dataplane

e2e-m1: build
	sudo $(E2E_ENV) bash test/e2e/m1.sh

e2e-m2: build
	sudo $(E2E_ENV) bash test/e2e/m2.sh

# S1: SNI/Host check without an upstream proxy.
e2e-s1: build
	sudo $(E2E_ENV) bash test/e2e/s1.sh

# Quarantine: cut a sandbox off, keep it for forensics, release it.
e2e-quarantine: build
	sudo $(E2E_ENV) bash test/e2e/quarantine.sh

# S2: policy-violation webhooks.
e2e-alerts: build
	sudo $(E2E_ENV) bash test/e2e/alerts.sh

# S3: OpenTelemetry log export, against a local OTLP sink.
e2e-otel: build
	CGO_ENABLED=0 GOOS=linux $(GO) build $(GOFLAGS) -buildvcs=false -o bin/otlp-sink ./test/e2e/otlpsink
	sudo $(E2E_ENV) OTLPSINK=$(CURDIR)/bin/otlp-sink bash test/e2e/otel.sh

# S1 against real sites (pypi.org on a shared CDN, pip install); needs direct
# internet, so it is not part of e2e. HTTP3_CURL=/path enables the QUIC checks.
e2e-s1-real: build
	sudo $(E2E_ENV) bash test/e2e/s1-real.sh

# Relay cost benchmark: SNI check vs --sni-check=false, with and without a
# max_ingress_bw cap. Not part of e2e (takes minutes).
e2e-relay-cost: build
	sudo $(E2E_ENV) bash test/e2e/relay-cost.sh

# Data plane processes: relayed connections and DNS outlive daemon restarts.
e2e-dataplane: build
	sudo $(E2E_ENV) bash test/e2e/dataplane.sh

# Synthetic DNS behind an upstream proxy (--synthetic-dns).
e2e-synthetic: build
	sudo $(E2E_ENV) bash test/e2e/synthetic.sh

# Upstream proxy mode; REAL_PROXY=http://host:port also fetches real sites through it.
# On a host without direct internet, REAL_PROXY also makes e2e-m1/m2/m3 run their daemons behind it.
e2e-proxy: build
	sudo $(E2E_ENV) bash test/e2e/proxy.sh

# M3 needs /dev/kvm; fc-assets downloads Firecracker, a guest kernel and rootfs.
fc-assets:
	sudo --preserve-env=http_proxy,https_proxy,no_proxy bash test/e2e/fc-assets.sh $(FC_ASSETS)

e2e-m3: build fc-assets
	sudo $(E2E_ENV) bash test/e2e/m3.sh

# Refresh the embedded Public Suffix List used by the allowlist lint.
psl-update:
	curl -fsSL https://publicsuffix.org/list/public_suffix_list.dat -o internal/policy/psl/public_suffix_list.dat
	$(GO) test ./...icy/...

clean:
	rm -rf bin $(DIST)
