GO      ?= go
BIN     := bin/egressd
GOFLAGS ?=
# Optional e2e locations; empty means the scripts' defaults.
FC_ASSETS   ?=
CHROOT_BASE ?=
E2E_TMP     ?=
E2E_ENV = EGRESSD=$(CURDIR)/$(BIN) $(if $(FC_ASSETS),FC_ASSETS=$(FC_ASSETS)) \
	$(if $(CHROOT_BASE),CHROOT_BASE=$(CHROOT_BASE)) $(if $(E2E_TMP),E2E_TMP=$(E2E_TMP)) \
	$(foreach v,CLONES CLONE_STAGGER FETCH_CONCURRENCY REAL_PROXY,$(if $($(v)),$(v)=$($(v))))

.PHONY: build test vet fmt-check e2e e2e-m1 e2e-m2 e2e-m3 e2e-proxy fc-assets clean

build:
	CGO_ENABLED=0 GOOS=linux $(GO) build $(GOFLAGS) -o $(BIN) ./cmd/egressd

# Unit tests: policy parsing, allowlist matching, DNS proxy logic, golden rulesets.
test:
	$(GO) test ./internal/...

vet:
	GOOS=linux $(GO) vet ./...

fmt-check:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }

# Root-only milestone acceptance tests. Run inside a disposable Linux VM.
e2e: e2e-m1 e2e-m2 e2e-m3 e2e-proxy

e2e-m1: build
	sudo $(E2E_ENV) bash test/e2e/m1.sh

e2e-m2: build
	sudo $(E2E_ENV) bash test/e2e/m2.sh

# Upstream proxy mode; REAL_PROXY=http://host:port also fetches real sites through it.
# On a host without direct internet, REAL_PROXY also makes e2e-m1/m2/m3 run their daemons behind it.
e2e-proxy: build
	sudo $(E2E_ENV) bash test/e2e/proxy.sh

# M3 needs /dev/kvm; fc-assets downloads Firecracker, a guest kernel and rootfs.
fc-assets:
	sudo --preserve-env=http_proxy,https_proxy,no_proxy bash test/e2e/fc-assets.sh $(FC_ASSETS)

e2e-m3: build fc-assets
	sudo $(E2E_ENV) bash test/e2e/m3.sh

clean:
	rm -rf bin
