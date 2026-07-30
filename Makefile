# Airlock — dev entrypoints.
#
# Everything here assumes you are inside WSL Ubuntu, not Windows.
#   wsl -d Ubuntu
#   cd /mnt/c/Users/bhavy/OneDrive/ドキュメント/GitHub/software_github
#
# Build caches are redirected to the WSL-native filesystem on purpose: the
# source tree lives under OneDrive, and letting Cargo write a multi-GB
# target/ into a synced folder would be miserable for both OneDrive and you.

SHELL := /bin/bash
.DEFAULT_GOAL := help

export CARGO_TARGET_DIR ?= $(HOME)/.cache/airlock/cargo-target
export GOCACHE          ?= $(HOME)/.cache/airlock/go-build
export GOMODCACHE       ?= $(HOME)/.cache/airlock/go-mod

COMPOSE := docker compose
BENCH_DIR := bench/results

# ---------------------------------------------------------------- help
.PHONY: help
help: ## Show this help
	@echo "Airlock — targets:"
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Memory budget (see docker-compose.yml): core 384M, +obs 648M, +storage 192M, +events 640M"

# ---------------------------------------------------------------- dev stack
.PHONY: dev
dev: ## Start core stack only (postgres + redis, ~384M)
	$(COMPOSE) up -d
	@$(MAKE) --no-print-directory mem

.PHONY: dev-obs
dev-obs: ## Start core + observability (prometheus, grafana, jaeger)
	$(COMPOSE) --profile obs up -d
	@$(MAKE) --no-print-directory mem

.PHONY: dev-storage
dev-storage: ## Start core + MinIO (object storage for snapshots/recordings)
	$(COMPOSE) --profile storage up -d
	@$(MAKE) --no-print-directory mem

.PHONY: dev-events
dev-events: ## Start core + Redpanda (Kafka-compatible event spine)
	$(COMPOSE) --profile events up -d
	@$(MAKE) --no-print-directory mem

.PHONY: dev-full
dev-full: ## Start EVERYTHING (~1.9G — will be tight; close your browser first)
	@echo "WARNING: full stack is ~1.9G inside a $$(free -m | awk '/Mem:/{print $$2}')M WSL guest."
	@echo "         Rust link jobs can spike >1G. Ctrl-C now if a build is running."
	@sleep 3
	$(COMPOSE) --profile full up -d
	@$(MAKE) --no-print-directory mem

.PHONY: down
down: ## Stop all containers (keeps volumes)
	$(COMPOSE) --profile full down

.PHONY: clean
clean: ## Stop everything and DELETE volumes (destroys local db)
	$(COMPOSE) --profile full down -v

.PHONY: ps
ps: ## Show container status
	$(COMPOSE) ps

.PHONY: logs
logs: ## Tail logs from all running containers
	$(COMPOSE) logs -f --tail=100

.PHONY: mem
mem: ## Show live memory use per container + WSL total
	@echo ""
	@docker stats --no-stream --format \
		"table {{.Name}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.CPUPerc}}" 2>/dev/null \
		|| echo "  (no containers running)"
	@echo ""
	@free -m | awk '/Mem:/{printf "  WSL guest: %sM used / %sM total (%sM available)\n", $$3, $$2, $$7}'
	@echo ""

# ---------------------------------------------------------------- build & test
.PHONY: build
build: build-go build-rust ## Build all Go and Rust binaries

.PHONY: build-go
build-go: ## Build Go services
	go build ./...

.PHONY: build-rust
build-rust: ## Build Rust crates (tool-broker, policy-sidecar)
	cargo build --workspace

.PHONY: test
test: test-go test-rust ## Run all tests

.PHONY: test-go
test-go: ## Go tests with the race detector
	go test -race -count=1 ./...

.PHONY: test-rust
test-rust: ## Rust tests
	cargo test --workspace

.PHONY: test-prop
test-prop: ## Property suites only (capability attenuation monotonicity)
	go test -race -count=1 -run 'TestProp' ./internal/capability/...
	cargo test --workspace prop_

.PHONY: lint
lint: ## golangci-lint + clippy
	golangci-lint run ./...
	cargo clippy --workspace --all-targets -- -D warnings

.PHONY: fmt
fmt: ## Format Go and Rust
	go fmt ./...
	cargo fmt --all

# ---------------------------------------------------------------- evidence
# These targets produce the numbers in docs/BENCHMARK.md. Raw output lands in
# bench/results/ and is committed — see docs/BENCHMARK.md "Provenance".
# --- implemented ---
.PHONY: bench-micro
bench-micro: ## B2a decision-function microbenchmark, 5 independent reps
	./bench/micro.sh

.PHONY: analyze
analyze: ## Re-run the pre-registered analysis over committed results
	python3 bench/analyze.py $(BENCH_DIR)/*.samples.json

.PHONY: anchor-evidence
anchor-evidence: ## Hash new results into the tamper-evident ledger
	go run ./cmd/airlock anchor-evidence --dir $(BENCH_DIR)

.PHONY: verify-evidence
verify-evidence: ## Re-verify committed results against the ledger
	go run ./cmd/airlock verify-evidence --dir $(BENCH_DIR)

# --- not implemented yet: these fail loudly rather than passing vacuously ---
.PHONY: bench-policy
bench-policy: ## [Phase 1] End-to-end broker decision latency under load
	@echo "B2 needs the tool-broker (Phase 1). Use 'make bench-micro' for B2a." && exit 1

.PHONY: bench-coldstart
bench-coldstart: ## [Phase 2] Sandbox cold start across docker/gvisor/firecracker
	@echo "B3 needs the isolator backends (Phase 2)." && exit 1

.PHONY: bench-injection
bench-injection: ## [Phase 4] AgentDojo prompt-injection resistance, 4 arms
	@echo "B1 needs the broker and recorder (Phase 4)." && exit 1

.PHONY: escape-test
escape-test: ## [Phase 2] Adversarial suite: every egress attempt MUST fail
	@echo "B5 needs the sandbox (Phase 2)." && exit 1

.PHONY: bench
bench: bench-micro anchor-evidence ## Everything runnable today, then anchor it

.PHONY: verify-phase0
verify-phase0: ## Check every Phase 0 exit criterion (0=done, 2=needs root setup)
	@bash scripts/verify-phase0.sh

.PHONY: setup
setup: ## One-time privileged setup: docker, gvisor, firecracker, kvm group
	@bash scripts/setup-wsl.sh

.PHONY: sysinfo
sysinfo: ## Capture the exact hardware/software the numbers were measured on
	@mkdir -p $(BENCH_DIR)
	./bench/sysinfo.sh | tee $(BENCH_DIR)/sysinfo.txt
