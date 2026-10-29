# Shared GhostLock source tree — Samsung Galaxy A15 target via `make a15`.
API ?= 35

NDK_ROOT ?= $(or $(ANDROID_NDK_HOME),$(ANDROID_NDK_ROOT),$(HOME)/Library/Android/sdk/ndk/30.0.15729638)
HOST_TAG := $(shell uname -m | sed 's/x86_64/darwin-x86_64/;s/arm64/darwin-x86_64/')
NDK_CC := $(NDK_ROOT)/toolchains/llvm/prebuilt/$(HOST_TAG)/bin/aarch64-linux-android$(API)-clang

SRCS := \
  src/core/main.c \
  src/core/util.c \
  src/core/slide.c \
  src/core/fops.c \
  src/core/pipe_physrw.c \
  src/core/pipe_reclaim.c \
  src/core/rwforge_a17.c \
  src/core/root.c \
  src/core/miniadb.c \
  src/core/umh_root.c

TARGET ?= target.h
CFLAGS := -O2 -Wall -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function \
  -Isrc/core -Isrc/devices -DTARGET_CONFIG_H=\"$(TARGET)\"
LDFLAGS := -fPIE -pie -pthread

.PHONY: all clean czg1 a15 g4d g4d-su g4su g4mount

all: ghostlock g4d g4sh g4exec g4d-su g4su g4mount

ghostlock: $(SRCS) src/core/$(TARGET)
	$(NDK_CC) $(CFLAGS) $(LDFLAGS) $(SRCS) -o $@

# CZG1 build: same tree, target_czg1.h offsets (identical to CZF1)
czg1:
	rm -f ghostlock
	$(MAKE) TARGET=target_czg1.h
	mv ghostlock ghostlock-czg1

# A15 build: Samsung Galaxy A15 (SM-A156U), kernel 5.15.189-android13-8.
# Uses target_a15.h (5.15 BTF-verified offsets). KDP present: wq-umh endgame.
a15:
	rm -f ghostlock-a15
	$(MAKE) TARGET=target_a15.h
	mv ghostlock ghostlock-a15

# root daemon + client (static, standalone — no exploit internals)
# Static linking: NDK toolchains ship a static libc, Termux clang does not.
# When NDK_CC is overridden on the command line (e.g. Termux: NDK_CC=clang),
# default to dynamic linking; otherwise keep -static. Override with STATIC=.
ifeq ($(origin NDK_CC),command line)
STATIC ?=
else
STATIC ?= -static
endif
g4d: src/daemon/g4d.c src/daemon/g4d_protocol.h
	$(NDK_CC) -O2 -Wall $(STATIC) src/daemon/g4d.c -o $@

# Companion service for the app-facing manager. Its private socket keeps it
# separate from @ghostlocksu, so it can start without replacing the shell daemon.
g4d-su: src/daemon/g4d.c src/daemon/g4d_protocol.h
	$(NDK_CC) -O2 -Wall $(STATIC) -DG4D_SU_ONLY_DEFAULT=1 \
	  -DG4D_SU_NAME='"ghostlocksu_mgr2"' \
	  -DG4D_PIDF='"/dev/ghostlock-g4d-su.pid"' src/daemon/g4d.c -o $@

g4sh: src/daemon/g4sh.c src/daemon/g4d_protocol.h
	$(NDK_CC) -O2 -Wall $(STATIC) src/daemon/g4sh.c -o $@

g4su: src/daemon/g4su.c src/daemon/g4d_protocol.h
	$(NDK_CC) -O2 -Wall $(STATIC) -DG4D_SU_NAME='"ghostlocksu_mgr2"' \
	  src/daemon/g4su.c -o $@

g4mount: src/daemon/g4mount.c
	$(NDK_CC) -O2 -Wall $(STATIC) src/daemon/g4mount.c -o $@

g4exec: src/daemon/g4exec.c
	$(NDK_CC) -O2 -Wall $(STATIC) src/daemon/g4exec.c -o $@

clean:
	rm -f ghostlock g4d g4sh g4exec g4d-su g4su g4mount
