LIMA_VM ?= lima-ko
LIMA := limactl shell $(LIMA_VM) --
REPO := /Users/anjmao/castai/ko
DEVBOX_BIN ?= /nix/var/nix/profiles/default/bin/devbox
DEVBOX_ENV = eval "$$($(DEVBOX_BIN) shellenv)"

.PHONY: lima-install lima-vmlinux lima-generate lima-test lima-run

# Installs devbox.json packages (go, llvm_22, clang_22) inside the VM.
lima-install:
	$(LIMA) sh -c 'cd $(REPO) && devbox install'

# Regenerates c/headers/vmlinux.h from the kernel the VM is running.
lima-vmlinux:
	$(LIMA) sh -c 'cd $(REPO) && $(DEVBOX_ENV) >/dev/null && $$(ls /usr/lib/linux-tools/*/bpftool | tail -1) btf dump file /sys/kernel/btf/vmlinux format c > $(REPO)/pkg/tracer/c/headers/vmlinux.h'

# Compiles the eBPF C code and generates Go bindings via bpf2go.
lima-generate:
	$(LIMA) sh -c 'cd $(REPO) && $(DEVBOX_ENV) >/dev/null && go generate ./pkg/tracer'

lima-test:
	$(LIMA) sudo sh -c 'export GOMODCACHE=/home/anjmao.guest/go/pkg/mod; cd $(REPO) && $(DEVBOX_ENV) >/dev/null && go test ./pkg/tracer/ ./pkg/kontext/ ./cmd/ko/node-agent/ -skip "^TestTracer$$" -v -count=1'

lima-run:
	$(LIMA) sudo sh -c 'cd $(REPO) && $(DEVBOX_ENV) >/dev/null && go run ./cmd/ko node-agent'
