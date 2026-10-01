GO      ?= go
BIN     := bin/egressd
GOFLAGS ?=

.PHONY: build test vet fmt-check e2e e2e-m1 e2e-m2 e2e-m3 fc-assets clean

build:
	CGO_ENABLED=0 GOOS=linux $(GO) build $(GOFLAGS) -o $(BIN) ./cmd/egressd

# Unit tests: policy parsing, allowlist matching, DNS proxy logic, golden rulesets.
test:
	$(GO) test ./internal/...

vet:
	GOOS=linux $(GO) vet ./...

fmt-check:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }

# Root-only scenario tests from PRD §10. Run inside a disposable Linux VM.
e2e: e2e-m1 e2e-m2 e2e-m3

e2e-m1: build
	sudo EGRESSD=$(CURDIR)/$(BIN) bash test/e2e/m1.sh

e2e-m2: build
	sudo EGRESSD=$(CURDIR)/$(BIN) bash test/e2e/m2.sh

# M3 needs /dev/kvm; fc-assets downloads Firecracker, a guest kernel and rootfs.
fc-assets:
	sudo bash test/e2e/fc-assets.sh

e2e-m3: build fc-assets
	sudo EGRESSD=$(CURDIR)/$(BIN) bash test/e2e/m3.sh

clean:
	rm -rf bin
