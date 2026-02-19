# =============================================================================
# Makefile — generate vmlinux.h from running kernel BTF
# =============================================================================

# --- paths -------------------------------------------------------------------
EBPF_DIR    := $(shell pwd)
HEADERS_DIR := $(EBPF_DIR)/headers
VMLINUX_H   := $(HEADERS_DIR)/vmlinux.h

# --- tools -------------------------------------------------------------------
BPFTOOL     := $(shell which bpftool 2>/dev/null)
LLVM_STRIP  := $(shell which llvm-strip 2>/dev/null)

# --- kernel BTF sources (tried in order) -------------------------------------
BTF_SOURCES := \
    /sys/kernel/btf/vmlinux \
    /boot/vmlinux-$(shell uname -r) \
    /usr/lib/debug/boot/vmlinux-$(shell uname -r) \
    /usr/lib/debug/lib/modules/$(shell uname -r)/vmlinux \
    /proc/kcore

# =============================================================================
.PHONY: all vmlinux clean check-tools check-btf help

all: vmlinux

# =============================================================================
# check bpftool is installed
# =============================================================================
check-tools:
	@echo "--- Checking required tools ---"

	@if [ -z "$(BPFTOOL)" ]; then \
		echo "[ERROR] bpftool not found."; \
		echo "        Install it:"; \
		echo "          Ubuntu/Debian : sudo apt install linux-tools-common linux-tools-$(shell uname -r)"; \
		echo "          Fedora/RHEL   : sudo dnf install bpftool"; \
		echo "          Arch          : sudo pacman -S bpf"; \
		echo "          From source   : https://github.com/libbpf/bpftool"; \
		exit 1; \
	fi

	@echo "[OK] bpftool found at : $(BPFTOOL)"
	@echo "[OK] bpftool version  : $(shell $(BPFTOOL) version 2>&1 | head -1)"

# =============================================================================
# find a valid BTF source on this machine
# =============================================================================
check-btf:
	@echo ""
	@echo "--- Checking BTF sources ---"

	@BTF_FOUND=""; \
	for src in $(BTF_SOURCES); do \
		if [ -r "$$src" ]; then \
			echo "[OK] Found BTF at: $$src"; \
			BTF_FOUND=$$src; \
			break; \
		else \
			echo "[ ] Not found   : $$src"; \
		fi; \
	done; \
	if [ -z "$$BTF_FOUND" ]; then \
		echo ""; \
		echo "[ERROR] No BTF source found on this system."; \
		echo "        Your kernel may not have BTF enabled."; \
		echo ""; \
		echo "        Check:  cat /boot/config-$(shell uname -r) | grep CONFIG_DEBUG_INFO_BTF"; \
		echo "        Should show: CONFIG_DEBUG_INFO_BTF=y"; \
		echo ""; \
		echo "        If missing, you need to either:"; \
		echo "          1. Recompile kernel with CONFIG_DEBUG_INFO_BTF=y"; \
		echo "          2. Install kernel debug symbols"; \
		echo "          3. Use a prebuilt vmlinux.h from BTFHub (see help)"; \
		exit 1; \
	fi

# =============================================================================
# main target — generate vmlinux.h
# =============================================================================
vmlinux: check-tools check-btf $(VMLINUX_H)

$(VMLINUX_H):
	@echo ""
	@echo "--- Generating vmlinux.h ---"

	@mkdir -p $(HEADERS_DIR)

	@# find the first readable BTF source
	@BTF_SRC=""; \
	for src in $(BTF_SOURCES); do \
		if [ -r "$$src" ]; then \
			BTF_SRC=$$src; \
			break; \
		fi; \
	done; \
	\
	echo "[..] Using BTF source : $$BTF_SRC"; \
	echo "[..] Output           : $(VMLINUX_H)"; \
	echo ""; \
	\
	$(BPFTOOL) btf dump file $$BTF_SRC format c > $(VMLINUX_H); \
	\
	if [ $$? -ne 0 ]; then \
		echo "[ERROR] bpftool failed to generate vmlinux.h"; \
		rm -f $(VMLINUX_H); \
		exit 1; \
	fi

	@echo "[OK] vmlinux.h generated successfully"
	@echo "[OK] Size      : $(shell wc -l < $(VMLINUX_H)) lines"
	@echo "[OK] Location  : $(VMLINUX_H)"

	@# stamp kernel version into top of file for reference
	@KERNEL=$(shell uname -r); \
	TMPFILE=$$(mktemp); \
	echo "/* Generated from kernel $${KERNEL} on $(shell date -u) */" > $$TMPFILE; \
	echo "/* BTF source: $(firstword $(wildcard $(BTF_SOURCES)))              */" >> $$TMPFILE; \
	echo "" >> $$TMPFILE; \
	cat $(VMLINUX_H) >> $$TMPFILE; \
	mv $$TMPFILE $(VMLINUX_H)

	@echo "[OK] Done"

# =============================================================================
# clean
# =============================================================================
clean:
	@echo "--- Cleaning ---"
	@rm -f  $(VMLINUX_H)
	@echo "[OK] Removed $(VMLINUX_H)"

# =============================================================================
# help
# =============================================================================
help:
	@echo ""
	@echo "Usage:"
	@echo "  make vmlinux        generate headers/vmlinux.h from running kernel"
	@echo "  make clean          remove generated vmlinux.h"
	@echo "  make check-tools    verify bpftool is installed"
	@echo "  make check-btf      verify kernel BTF is available"
	@echo "  make help           show this message"
	@echo ""
	@echo "BTF sources checked (in order):"
	@for src in $(BTF_SOURCES); do echo "  $$src"; done
	@echo ""
	@echo "If no BTF source is found, get a prebuilt vmlinux.h from BTFHub:"
	@echo "  https://github.com/aquasecurity/btfhub-archive"
	@echo ""
	@echo "Or install bpftool from source:"
	@echo "  https://github.com/libbpf/bpftool"
	@echo ""